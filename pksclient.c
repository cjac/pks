const char rcsid_pksclient_c[] = "$Id: pksclient.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "database.h"
#include "globals.h"
#include "util.h"

void usage(char *argv0)
{
   fprintf(stderr,
	   "%s /db/path create [num_files]\n"
	   "%s /db/path recover\n"
	   "%s /db/path add filename [flags]\n"
	   "%s /db/path get userid [flags]\n"
	   "%s /db/path index userid [flags]\n"
	   "%s /db/path since time [flags]\n"
	   "%s /db/path delete userid [flags]\n"
	   "%s /db/path disable userid [flags]\n",
	   argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
   exit(1);
}

int main(int argc, char *argv[])
{
   char *dir, *op;
   unsigned char *ret;
   long retlen;

   if (argc < 3)
      usage(argv[0]);

   dir = argv[1];
   op = argv[2];

   ret = NULL;

   log_terminal = 1;

   if (strcmp(op, "create") == 0) {
      int num_files;

      num_files = argv[3]?atoi(argv[3]):3;

      if (!kd_create(dir, num_files, (char **) &ret)) {
	 fprintf(stderr, "database create failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      printf("Database files created in %s\n", dir);
   } else if (strcmp(op, "recover") == 0) {
      if (!kd_open(dir, KD_OPEN_RECOVER, (char **) &ret)) {
	 fprintf(stderr, "database recovery failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      printf("Database files recovered in %s\n", dir);
   } else if (strcmp(op, "add") == 0) {
      unsigned char *ret, *newkeys;
      long retlen, newkeyslen;
      char *fn, *opts;
      int donew = 0, flags = 0, oflags = 0;
      FILE *f;
      xfilecontents infile;

      if ((fn = argv[3]) == NULL)
	 usage(argv[0]);

      if ((opts = argv[4])) {
	 if (strchr(opts, 'n'))
	    donew = 1;
	 if (strchr(opts, 'd'))
	    flags |= KD_ADD_NO_STRIP_DISABLED;
	 if (strchr(opts, 't'))
	    oflags |= KD_OPEN_NOTXN;
      }

      if ((f = fopen(fn, "r")) == NULL) {
	 perror("opening file");
	 exit(1);
      }

      if (!xfilecontents_get(&infile, f)) {
	 fprintf(stderr, "%s: error getting input file %s contents\n",
		 argv[0], fn);
	 exit(1);
      }

      fclose(f);

      if (!kd_open(dir, oflags, (char **) &ret)) {
	 fprintf(stderr, "database open failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      if (!kd_add(infile.buf, infile.len, KD_ADD_VERBOSE | flags,
		  &ret, &retlen,
		  donew?&newkeys:NULL, donew?&newkeyslen:NULL)) {
	 fprintf(stderr, "database add failed: %.*s\n", (int) retlen, ret);
	 free(ret);
	 xfilecontents_free(&infile);
	 kd_close();
	 exit(1);
      }

      xfilecontents_free(&infile);

      fwrite((void *) ret, (size_t) retlen, 1, stderr);
      if (donew)
	 fwrite((void *) newkeys, (size_t) newkeyslen, 1, stdout);
   } else if (strcmp(op, "get") == 0) {
      char *userid, *opts;
      int flags = 0, oflags = KD_OPEN_READONLY;

      if ((userid = argv[3]) == NULL)
	 usage(argv[0]);

      if ((opts = argv[4])) {
	 if (strchr(opts, 'e'))
	    flags |= KD_GET_EXACT;
	 if (strchr(opts, 'a'))
	    flags |= KD_GET_ALL;
	 if (strchr(opts, 'b'))
	    flags |= KD_GET_BINARY;
	 if (strchr(opts, 'i'))
	    flags |= KD_GET_IGNORE_ERRORS;
	 if (strchr(opts, 'd'))
	    flags |= KD_GET_RETURN_DISABLED;
	 if (strchr(opts, 's'))
	    flags |= KD_GET_STDOUT;
	 if (strchr(opts, 't'))
	    oflags |= KD_OPEN_NOTXN;
      }

      if (!kd_open(dir, oflags, (char **) &ret)) {
	 fprintf(stderr, "database open failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      if (!kd_get((unsigned char *) userid, (long) strlen(userid),
		  flags, -1, &ret, &retlen)) {
	 fprintf(stderr, "database get failed: %.*s\n", (int) retlen, ret);
	 free(ret);
	 kd_close();
	 exit(1);
      }

      fwrite((void *) ret, (size_t) retlen, 1, stdout);
   } else if (strcmp(op, "index") == 0) {
      char *userid, *opts;
      int flags = 0, oflags = KD_OPEN_READONLY;

      if ((userid = argv[3]) == NULL)
	 usage(argv[0]);

      if ((opts = argv[4])) {
	 if (strchr(opts, 'v'))
	    flags |= KD_INDEX_VERBOSE;
	 if (strchr(opts, 'f'))
	    flags |= KD_INDEX_FINGERPRINT;
	 if (strchr(opts, 'e'))
	    flags |= KD_INDEX_EXACT;
	 if (strchr(opts, 'a'))
	    flags |= KD_INDEX_ALL;
	 if (strchr(opts, 'i'))
	    flags |= KD_INDEX_IGNORE_ERRORS;
	 if (strchr(opts, 's'))
	    flags |= KD_INDEX_STDOUT;
	 if (strchr(opts, 't'))
	    oflags |= KD_OPEN_NOTXN;
      }

      if (!kd_open(dir, oflags, (char **) &ret)) {
	 fprintf(stderr, "database open failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      if (!kd_index((unsigned char *) userid, (long) strlen(userid),
		    flags, -1, &ret, &retlen)) {
	 fprintf(stderr, "database index failed: %.*s\n", (int) retlen, ret);
	 free(ret);
	 kd_close();
	 exit(1);
      }

      fwrite((void *) ret, (size_t) retlen, 1, stdout);
   } else if (strcmp(op, "since") == 0) {
      time_t since, last;
      char *opts;
      int flags = 0, oflags = KD_OPEN_READONLY;

      if (argv[3] == NULL)
	 usage(argv[0]);

      since = atoi(argv[3]);

      if ((opts = argv[4])) {
	 if (strchr(opts, 'b'))
	    flags |= KD_SINCE_BINARY;
	 if (strchr(opts, 'r')) {
	    time_t now;
	    now = time(NULL);
	    since = now - since;
         }
	 if (strchr(opts, 't'))
	    oflags |= KD_OPEN_NOTXN;
      }

      if (!kd_open(dir, oflags, (char **) &ret)) {
	 fprintf(stderr, "database open failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      if (!kd_since(since, flags, -1, &last, &ret, &retlen)) {
	 fprintf(stderr, "database since failed: %.*s\n", (int) retlen, ret);
	 free(ret);
	 kd_close();
	 exit(1);
      }

      fprintf(stderr, "Last key added at %ld\n\n", (long) last);

      fwrite((void *) ret, (size_t) retlen, 1, stdout);
   } else if (strcmp(op, "delete") == 0) {
      char *userid, *opts;
      int oflags = 0;

      if ((userid = argv[3]) == NULL)
	 usage(argv[0]);

      if ((opts = argv[4])) {
	 if (strchr(opts, 't'))
	    oflags |= KD_OPEN_NOTXN;
      }

      if (!kd_open(dir, oflags, (char **) &ret)) {
	 fprintf(stderr, "database open failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      if (!kd_delete((unsigned char *) userid, (long) strlen(userid),
		     0, &ret, &retlen)) {
	 fprintf(stderr, "database delete failed: %.*s\n", (int) retlen, ret);
	 free(ret);
	 kd_close();
	 exit(1);
      }

      fwrite((void *) ret, (size_t) retlen, 1, stdout);
   } else if (strcmp(op, "disable") == 0) {
      char *userid, *opts;
      int flags = 0, oflags = 0;

      if ((userid = argv[3]) == NULL)
	 usage(argv[0]);

      if ((opts = argv[4])) {
	 if (strchr(opts, 'c'))
	    flags |= KD_DISABLE_CLEAR;
	 if (strchr(opts, 't'))
	    oflags |= KD_OPEN_NOTXN;
      }

      if (!kd_open(dir, oflags, (char **) &ret)) {
	 fprintf(stderr, "database open failed: %s\n", ret);
	 free(ret);
	 exit(1);
      }

      if (!kd_disable((unsigned char *) userid, (long) strlen(userid),
		      flags, &ret, &retlen)) {
	 fprintf(stderr, "database disable failed: %.*s\n", (int) retlen, ret);
	 free(ret);
	 kd_close();
	 exit(1);
      }

      fwrite((void *) ret, (size_t) retlen, 1, stdout);
   } else {
      usage(argv[0]);
   }

   if (ret)
      free(ret);

   kd_close();

   exit(0);
}
