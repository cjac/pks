const char rcsid_pgpfile_c[] = "$Id: pgpfile.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "pgputil.h"
#include "pgpfile.h"

void one_file(FILE *f, char *fn)
{
   ddesc data;
   xfilecontents xfc;

   if (!xfilecontents_get(&xfc, f)) {
      perror("reading file");
   } else {
      data.data = xfc.buf;
      data.size = xfc.len;
      data.offset = 0;

      if (!do_file(&data)) {
	 fprintf(stderr, "Error decoding %s\n", fn);
      }
   }

   xfilecontents_free(&xfc);
}


int main(int argc, char *argv[])
{
   int i;
   FILE *f;

   if (argc == 1) {
      one_file(stdin, "<STDIN>");
   } else {
      for (i=1; i<argc; i++) {
	 if (strcmp(argv[i], "-") == 0) {
	    one_file(stdin, "<STDIN>");
	 } else {
	    if ((f = fopen(argv[i], "r")) == NULL) {
	       perror("opening file");

	       continue;
	    }

	    one_file(f, argv[i]);

	    fclose(f);
	 }
      }
   }

   exit(0);
}
