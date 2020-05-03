const char rcsid_dbcheck_c[] = "$Id: pkscheck.c,v 1.3 2003/02/07 01:01:21 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <db.h>
#include <stdio.h>
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

int main(int argc, char *argv[])
{
   char *dir, *str;
   DBC *cursor;
   DBT ikey, idata, kkey, kdata;
   int ret, i;
   char buf[1024];

   if (argc < 2)
      usage(argv[0]);

   dir = argv[1];
   log_terminal = 1;

   if (!kd_open(dir, KD_OPEN_READONLY, &str)) {
      fprintf(stderr, "database open failed: %s\n", str);
      free(str);
      exit(1);
   }

   if ((ret = (*(worddb->cursor))(worddb, NULL, &cursor, 0))) {
      sprintf(buf, "error creating worddb cursor: error = %d", ret);
      log_error("main", buf);
   }

   memset(&ikey, 0, sizeof(ikey));
   memset(&idata, 0, sizeof(idata));

   memset(&kkey, 0, sizeof(kkey));
   memset(&kdata, 0, sizeof(kdata));
   for (ret = (*(cursor->c_get))(cursor, &ikey, &idata, DB_FIRST);
	ret == 0;
	ret = (*(cursor->c_get))(cursor, &ikey, &idata, DB_NEXT)) {
      if (idata.size != 12) {
	 sprintf(buf, "worddb corrupt in entry = \"%.*s\", size = %d\n",
		 (int) ikey.size, (char *) ikey.data, (int) idata.size);

	 log_error("main", buf);
      }

      kkey.size = 4;
      kkey.data = ((unsigned char *) idata.data)+8;

      if ((*(keydb(&kkey)->get))(keydb(&kkey), NULL, &kkey, &kdata, 0)) {
	  sprintf(buf, "keyid %02X%02X%02X%02X in worddb but not keydb\n",
		  ((unsigned char *) kkey.data)[0],
		  ((unsigned char *) kkey.data)[1],
		  ((unsigned char *) kkey.data)[2],
		  ((unsigned char *) kkey.data)[3]);
	  log_error("main", buf);
      }
   }

   (*(cursor->c_close))(cursor);

   if ((ret = (*(timedb->cursor))(timedb, NULL, &cursor, 0))) {
      sprintf(buf, "error creating timedb cursor: error = %d", ret);
      log_error("main", buf);
   }

   for (ret = (*(cursor->c_get))(cursor, &ikey, &idata, DB_FIRST);
	ret == 0;
	ret = (*(cursor->c_get))(cursor, &ikey, &idata, DB_NEXT)) {
      if (idata.size%12) {
	 sprintf(buf, "timedb corrupt in entry = \"%.*s\", size = %d\n",
		 (int) ikey.size, (char *) ikey.data, (int) idata.size);

	 log_error("main", buf);
      }

      for (KD_FIRST_ENTRY(i); KD_LAST_ENTRY(i, idata); KD_NEXT_ENTRY(i)) {
	 kkey.size = 4;
	 kkey.data = ((unsigned char *) idata.data)+i+8;

	 if ((*(keydb(&kkey)->get))(keydb(&kkey), NULL, &kkey, &kdata, 0)) {
	    sprintf(buf, "keyid %02X%02X%02X%02X in timedb but not keydb\n",
		    ((unsigned char *) kkey.data)[0],
		    ((unsigned char *) kkey.data)[1],
		    ((unsigned char *) kkey.data)[2],
		    ((unsigned char *) kkey.data)[3]);
	    log_error("main", buf);
	 }
      }
   }

   (*(cursor->c_close))(cursor);

   kd_close();

   exit(0);
}
