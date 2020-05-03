const char rcsid_kxa_c[] = "$Id: kxa.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "pgputil.h"
#include "pgpfile.h"
#include "util.h"
#include "armor.h"

struct state {
   xbuffer xb;
};

int kxa(ddesc *packet, void *c)
{
   long ptype, plen;
   struct state *s = (struct state *) c;

   if (!decode_psf(packet, &ptype, &plen))
      return(0);

   if ((ptype == 6) || (ptype == 13) || (ptype == 2) || (ptype == 14))
      return(xbuffer_append(&(s->xb), packet->data, packet->size));
   else
      return(1);
}

int do_file(ddesc *data)
{
   struct state s;
   ddesc binary, ascii;

   xbuffer_alloc(&(s.xb));

   if (!decode_file(data, kxa, (void *) &s)) {
      xbuffer_free(&(s.xb));
      return(0);
   }

   binary.data = s.xb.buf;
   binary.size = s.xb.len;
   binary.offset = 0;

   ascii.size = encode_ascii_size(&binary, "PUBLIC KEY BLOCK");
   if ((ascii.data = (unsigned char *) malloc(ascii.size)) == NULL) {
      xbuffer_free(&(s.xb));
      return(0);
   }
   ascii.offset = 0;

   if (!encode_ascii(&binary, "PUBLIC KEY BLOCK", &ascii)) {
      free(ascii.data);
      xbuffer_free(&(s.xb));
      return(0);
   }

   printf("%.*s", (int) ascii.size, ascii.data);

   free(ascii.data);
   xbuffer_free(&(s.xb));

   return(1);
}
