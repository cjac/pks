const char rcsid_pgpsplit_c[] = "$Id: pgpsplit.c,v 1.4 2002/09/08 19:55:45 rlaager Exp $";

/* 
 * Copyright (c) 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/param.h>

#include "util.h"
#include "pgputil.h"
#include "pgpfile.h"

struct state {
   int maxbytes;
   char *filenamebase;

   int filenum;
   char filename[MAXPATHLEN];
   FILE *f;

   int bytes;
};

int split(ddesc *packet, void *c)
{
   long ptype, plen;
   struct state *s = (struct state *) c;

   if (!decode_psf(packet, &ptype, &plen))
      return(0);

   if ((ptype == 6) && (s->f) && ((s->bytes+packet->size) >= s->maxbytes)) {
      fclose(s->f);
      s->f = NULL;
   }

   if (!s->f) {
      sprintf(s->filename, "%s%04d.pgp", s->filenamebase, s->filenum++);
      if ((s->f = fopen(s->filename, "w")) == NULL) {
	 fprintf(stderr, "Error opening %s for writing\n", s->filename);
	 return(0);
      }
      s->bytes = 0;
   }

   if (fwrite(packet->data, packet->size, 1, s->f) != 1) {
      fprintf(stderr, "Error writing to %s\n", s->filename);
      return(0);
   }

   s->bytes += packet->size;

   return(1);
}

void usage(char *argv0)
{
   fprintf(stderr, "Usage: %s [-b bytes] [-o outfile] infile\n", argv0);
   exit(1);
}

int main(int argc, char *argv[])
{
   int i;
   FILE *f;
   char *infile, *outfile;
   struct state s;
   xfilecontents xfc;
   ddesc data;

   infile = NULL;
   outfile = NULL;

   s.maxbytes = 0;
   s.filenamebase = NULL;
   s.f = NULL;
   s.filenum = 0;

   for (i=1; i<argc; i++) {
      if (argv[i][0] == '-') {
	 if (argv[i][1] == 'b') {
	    if (s.maxbytes || !argv[i+1])
	       usage(argv[0]);

	    if ((s.maxbytes = atoi(argv[i+1])) <= 0)
	       usage(argv[0]);

	    i++;
	 } else if (argv[i][1] == 'o') {
	    if (outfile || !argv[i+1])
	       usage(argv[0]);

	    outfile = argv[i+1];

	    i++;
	 } else {
	    usage(argv[0]);
	 }
      } else {
	 if (infile)
	    usage(argv[0]);

	 infile = argv[i];
      }
   }

   if (!infile && !outfile)
      usage(argv[0]);

   if (!s.maxbytes)
      s.maxbytes = 10*1024*1024;

   if (outfile)
      s.filenamebase = outfile;
   else
      s.filenamebase = infile;

   if (!infile) {
      infile = "<STDIN>";
      f = stdin;
   } else {
      if ((f = fopen(infile, "r")) == NULL) {
	 perror("opening file");
	 exit(1);
      }
   }

   if (!xfilecontents_get(&xfc, f)) {
      perror("reading file");
      exit(1);
   }

   data.data = xfc.buf;
   data.size = xfc.len;
   data.offset = 0;
   
   if (!decode_file(&data, split, (void *) &s)) {
      perror("reading file");
      xfilecontents_free(&xfc);
      exit(1);
   }

   xfilecontents_free(&xfc);
   exit(0);
}
