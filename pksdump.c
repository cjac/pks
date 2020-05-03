#include <fcntl.h>
#include <db.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "database.h"
#include "globals.h"
#include "kd_internal.h"

void usage(char *argv0)
{
   fprintf(stderr,
	   "%s /db/path\n",
	   argv0);
   exit(1);
}

void dump_worddb()
{
   DBC *cursor;
   DBT key, data;
   int ret, count, bufsize;
   char buf[1024];
   unsigned char *tmp;

   if ((ret = (*(worddb->cursor))(worddb, NULL, &cursor, 0))) {
      sprintf(buf, "error creating worddb cursor: error = %d", ret);
      log_error("main", buf);
      return;
   }

   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   bufsize = 0;
   buf[0] = '\0';
   count = 0;

   for (ret = (*(cursor->c_get))(cursor, &key, &data, DB_FIRST);
	ret == 0;
	ret = (*(cursor->c_get))(cursor, &key, &data, DB_NEXT)) {
      if (data.size != 12) {
	 printf("worddb corrupt in entry = \"%.*s\", size = %d\n",
		(int) key.size, (char *) key.data, (int) data.size);
	 return;
      }

      if ((bufsize != key.size) ||
	  (memcmp(buf, key.data, key.size) != 0)) {
	 count = 1;
	 bufsize = key.size;
	 memcpy(buf, key.data, key.size);
      } else {
	 count++;
      }

      printf("word = \"%.*s\", count = %d\n",
	     (int) key.size, (char *) key.data, count);

      tmp = (unsigned char *) data.data;
      printf("  %12ld   %02X%02X%02X%02X %02X%02X%02X%02X\n",
	     (long) (tmp[0]<<24)|(tmp[1]<<16)|(tmp[2]<<8)|(tmp[3]),
	     tmp[4], tmp[5], tmp[6], tmp[7],
	     tmp[8], tmp[9], tmp[10], tmp[11]);
   }

   (*(cursor->c_close))(cursor);
}

void dump_timedb()
{
   DBC *cursor;
   char buf[1024];
   DBT key, data;
   int ret, i;
   unsigned char *tmp;

   if ((ret = (*(timedb->cursor))(timedb, NULL, &cursor, 0))) {
      sprintf(buf, "error creating timedb cursor: error = %d", ret);
      log_error("main", buf);
      return;
   }

   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   for (ret = (*(cursor->c_get))(cursor, &key, &data, DB_FIRST);
	ret == 0;
	ret = (*(cursor->c_get))(cursor, &key, &data, DB_NEXT)) {
      tmp = (unsigned char *) key.data;

      if (data.size%12) {
	 printf("timedb corrupt in entry add time = %ld, size = %d\n",
		(long) (tmp[0]<<24)|(tmp[1]<<16)|(tmp[2]<<8)|(tmp[3]),
		(int) data.size/12);
	 return;
      }

      printf("add time = %ld, count = %d\n",
	     (long) (tmp[0]<<24)|(tmp[1]<<16)|(tmp[2]<<8)|(tmp[3]),
	     (int) (data.size/12));

      for (i=0; i<data.size; i+=12) {
	 tmp = ((unsigned char *) data.data)+i;
	 printf("  %12ld   %02X%02X%02X%02X %02X%02X%02X%02X\n",
		(long) (tmp[0]<<24)|(tmp[1]<<16)|(tmp[2]<<8)|(tmp[3]),
		tmp[4], tmp[5], tmp[6], tmp[7],
		tmp[8], tmp[9], tmp[10], tmp[11]);
      }
   }

   (*(cursor->c_close))(cursor);
}

int main(int argc, char *argv[])
{
   char *dir, *str;

   if (argc < 2)
      usage(argv[0]);

   dir = argv[1];
   log_terminal = 1;

   if (!kd_open(dir, KD_OPEN_READONLY, &str)) {
      fprintf(stderr, "database open failed: %s\n", str);
      free(str);
      exit(1);
   }

   dump_worddb();

   printf("\n");

   dump_timedb();

   kd_close();

   exit(0);
}
