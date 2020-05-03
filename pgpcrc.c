const char rcsid_pgpcrc_c[] = "$Id: pgpcrc.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include "pgpcrc.h"
#include "pgputil.h"

#define CRC_GENERATOR 0x864CFB
#define CRC_INIT 0xB704CE
#define CRC_BITS 24

int crc_byte_initted;
unsigned long crc_byte[256];

static void init_crc_byte()
{
   int i;

   crc_byte[0] = 0;

   for (i=1; i<256; i++)
      crc_byte[i] = (
		     ((crc_byte[i>>1])<<1)
		     ^
		     (((crc_byte[i>>1]>>(CRC_BITS-1))^(i&0x1)) ?
		      CRC_GENERATOR : 0)
		      ) & ((1<<CRC_BITS)-1);
}

void crc_compute(ddesc *data, long *crc)
{
   int i;
   long tmp;

   if (!crc_byte_initted) {
      init_crc_byte();
      crc_byte_initted = 1;
   }

   tmp = CRC_INIT;

   for (i=0; i<data->size; i++)
      tmp = (tmp<<8)^crc_byte[(data->data[i]^(tmp>>(CRC_BITS-8)))&0xff];

   *crc = tmp&((1<<CRC_BITS)-1);
}

