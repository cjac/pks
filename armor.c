const char rcsid_armor_c[] = "$Id: armor.c,v 1.2 2002/09/05 13:12:16 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "globals.h"
#include "pgputil.h"
#include "pgpcrc.h"
#include "armor.h"
#include "util.h"

/* - 0177 indicates a character which should never appear in a base64
   encoding.  This is an error.
   - 0200 indicates the pad character '='
   - 0377 indicates whitespace which should be skipped and ignored
   - any other value is the converted value of the character
   */

static unsigned char base64_decoder[] = {
   /* 0x */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0377, 0377, 0177, 0177, 0377, 0177, 0177,
   /* 1x */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* 2x */
   0377, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0076, 0177, 0177, 0177, 0077,
   /* 3x */
   0064, 0065, 0066, 0067, 0070, 0071, 0072, 0073,
   0074, 0075, 0177, 0177, 0177, 0200, 0177, 0177,
   /* 4x */
   0177, 0000, 0001, 0002, 0003, 0004, 0005, 0006,
   0007, 0010, 0011, 0012, 0013, 0014, 0015, 0016,
   /* 5x */
   0017, 0020, 0021, 0022, 0023, 0024, 0025, 0026,
   0027, 0030, 0031, 0177, 0177, 0177, 0177, 0177,
   /* 6x */
   0177, 0032, 0033, 0034, 0035, 0036, 0037, 0040,
   0041, 0042, 0043, 0044, 0045, 0046, 0047, 0050,
   /* 7x */
   0051, 0052, 0053, 0054, 0055, 0056, 0057, 0060,
   0061, 0062, 0063, 0177, 0177, 0177, 0177, 0177,
   /* 8x */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* 9x */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* Ax */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* Bx */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* Cx */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* Dx */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* Ex */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   /* Fx */
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
   0177, 0177, 0177, 0177, 0177, 0177, 0177, 0177,
};

#define base64_decode_size(asciilen) (((asciilen+3)/4)*3)

int decode_base64(ddesc *asciidata, ddesc *binarydata)
{
   int count;
   long block;
   unsigned char ch;

   count = 0;
   block = 0;

   while (DECODE_READABLE(asciidata, 1)) {
      ch = base64_decoder[asciidata->data[asciidata->offset++]];

      switch (ch) {
       case 0177:
	 return(0);
       case 0200:
	 if (count < 2) {
	    return(0);
	 } else if (count == 2) {
	    if (!DECODE_READABLE(binarydata, 1))
	       return(0);

	    binarydata->data[binarydata->offset++] = (block>>4)&0xff;
	 } else if (count == 3) {
	    if (!DECODE_READABLE(binarydata, 2))
	       return(0);

	    binarydata->data[binarydata->offset++] = (block>>10)&0xff;
	    binarydata->data[binarydata->offset++] = (block>>2)&0xff;
	 }

	 count = 0;
	 asciidata->offset = asciidata->size;
	 break;
       case 0377:
	 break;
       default:
	 block = (block<<6)+ch;
	 if (++count == 4) {
	    if (!DECODE_READABLE(binarydata, 3))
	       return(0);

	    binarydata->data[binarydata->offset++] = (block>>16)&0xff;
	    binarydata->data[binarydata->offset++] = (block>>8)&0xff;
	    binarydata->data[binarydata->offset++] = block&0xff;

	    count = 0;
	    block = 0;
	 }
      }
   }

   if (count)
      return(0);

   binarydata->size = binarydata->offset;
   binarydata->offset = 0;

   return(1);
}

static unsigned char base64_encoder[] = {
   'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
   'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
   'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
   'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
   'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
   'w', 'x', 'y', 'z', '0', '1', '2', '3',
   '4', '5', '6', '7', '8', '9', '+', '/',
};

#define base64_encode_size(asciilen) (((asciilen+47)/48)*65)

int encode_base64(ddesc *binarydata, ddesc *asciidata)
{
   long block;
   ddesc tmp;

   tmp.data = asciidata->data + asciidata->offset;
   tmp.size = asciidata->size - asciidata->offset;
   tmp.offset = 0;

   while (DECODE_READABLE(binarydata, 3)) {
      if (!DECODE_READABLE(asciidata, 4))
	 return(0);

      block = binarydata->data[binarydata->offset++]<<16;
      block |= binarydata->data[binarydata->offset++]<<8;
      block |= binarydata->data[binarydata->offset++];

      tmp.data[tmp.offset++] = base64_encoder[(block>>18)&0x3f];
      tmp.data[tmp.offset++] = base64_encoder[(block>>12)&0x3f];
      tmp.data[tmp.offset++] = base64_encoder[(block>>6)&0x3f];
      tmp.data[tmp.offset++] = base64_encoder[block&0x3f];

      if (tmp.offset%65 == 64)
	 tmp.data[tmp.offset++] = '\n';
   }

   if (DECODE_READABLE(binarydata, 2)) {
      if (!DECODE_READABLE(asciidata, 4))
	 return(0);

      block = binarydata->data[binarydata->offset++]<<16;
      block |= binarydata->data[binarydata->offset++]<<8;

      tmp.data[tmp.offset++] = base64_encoder[(block>>18)&0x3f];
      tmp.data[tmp.offset++] = base64_encoder[(block>>12)&0x3f];
      tmp.data[tmp.offset++] = base64_encoder[(block>>6)&0x3f];
      tmp.data[tmp.offset++] = '=';
   } else if (DECODE_READABLE(binarydata, 1)) {
      if (!DECODE_READABLE(asciidata, 4))
	 return(0);

      block = binarydata->data[binarydata->offset++]<<16;

      tmp.data[tmp.offset++] = base64_encoder[(block>>18)&0x3f];
      tmp.data[tmp.offset++] = base64_encoder[(block>>12)&0x3f];
      tmp.data[tmp.offset++] = '=';
      tmp.data[tmp.offset++] = '=';
   }

   if (tmp.offset%65 != 0)
      tmp.data[tmp.offset++] = '\n';

   asciidata->offset += tmp.offset;

   return(1);
}

unsigned char *skip_blank_line(unsigned char *ptr, long len)
{
   long offset;
   int blank = 0;

   for (offset = 0; offset < len; offset++) {
      if (ptr[offset] == '\012') {
	 if (blank == 1)
	    return(ptr+offset+1);
	 else
	    blank = 1;
      } else if (!isspace(ptr[offset])) {
	 blank = 0;
      }
   }

   return(NULL);
}

int decode_ascii(ddesc *data, packet_handler h, void *c)
{
   unsigned char *ptr;
   unsigned char *contents, *base64crc;
   unsigned char crcbits[3];
   ddesc asciidata, binarydata, binarycrc;
   long read_crc, computed_crc;
   int ret;

   /* look for Armor headerline */

   if ((ptr = (unsigned char *)
	my_memstr((void *) data->data, "-----BEGIN PGP", data->size)) ==
       NULL)
      return(0);

   /* find blank line after armor headers */

   if ((contents = skip_blank_line(ptr, ((data->data + data->size) -
					 ((unsigned char *) ptr))))
       == NULL)
      return(0);

   while ((contents < (data->data + data->size)) && isspace(*contents))
      contents++;

   if (contents == data->data + data->size)
      return(0);

   if ((ptr = my_memstr((void *) contents, "\n=",
			data->size - (contents - data->data))) == NULL)
      return(0);

   base64crc = ptr+2;

   ptr = base64crc+4;

   while ((ptr < (data->data + data->size)) &&
	  ((*ptr == '\012') || (*ptr == '\015')))
      ptr++;

   if ((ptr+12) > (data->data + data->size))
      return(0);

   if (strncmp(((char *) ptr), "-----END PGP", 12) != 0)
      return(0);

   /* at this point, the ascii armor seems intact, and contents and crc
      point to the relevant places.  decode the base64 blocks. */

   asciidata.size = base64crc-1-contents;
   asciidata.data = contents;
   asciidata.offset = 0;

   binarydata.size = (base64crc-1-contents)*3/4;
   if ((binarydata.data = (unsigned char *) malloc(binarydata.size)) == NULL)
      return(0);
   binarydata.offset = 0;

   if (!decode_base64(&asciidata, &binarydata)) {
      free(binarydata.data);
      return(0);
   }

   asciidata.data = base64crc;
   asciidata.size = 4;
   asciidata.offset = 0;

   binarycrc.data = crcbits;
   binarycrc.size = sizeof(crcbits);
   binarycrc.offset = 0;

   if (!decode_base64(&asciidata, &binarycrc)) {
      free(binarydata.data);
      return(0);
   }

   if (!decode_num(&binarycrc, 3, &read_crc)) {
      free(binarydata.data);
      return(0);
   }

   crc_compute(&binarydata, &computed_crc);

   if (computed_crc != read_crc) {
      free(binarydata.data);
      return(0);
   }

   ret = decode_binary(&binarydata, h, c);

   free(binarydata.data);

   return(ret);
}

const unsigned char headerline_head[] = "-----BEGIN PGP ";
const unsigned char headerline_tail[] = ("-----\n"
					 "Version: PGP Key Server "
					 PKS_VERSION "\n\n");
const unsigned char tailline_head[] = "-----END PGP ";
const unsigned char tailline_tail[] = "-----\n";

int encode_ascii_size(ddesc *binarydata, const char *desc)
{
   return(sizeof(headerline_head)-1+
	  sizeof(headerline_tail)-1+
	  sizeof(tailline_head)-1+
	  sizeof(tailline_tail)-1+
	  6+ /* sizeof crc line */
	  strlen(desc)*2+
	  base64_encode_size(binarydata->size));
}

int encode_ascii(ddesc *binarydata, const char *headerline, ddesc *asciidata)
{
   long crc;
   unsigned char crcbits[3];
   ddesc crcdata;

   crc_compute(binarydata, &crc);

   crcbits[0] = crc>>16;
   crcbits[1] = crc>>8;
   crcbits[2] = crc;

   crcdata.data = crcbits;
   crcdata.size = 3;
   crcdata.offset = 0;

#define ddesc_append(dd, str) \
   memcpy((void *) ((dd)->data+(dd)->offset), (const void *) (str), \
	  strlen((char *) (str))); \
   (dd)->offset += strlen((char *) (str));

   ddesc_append(asciidata, headerline_head);
   ddesc_append(asciidata, headerline);
   ddesc_append(asciidata, headerline_tail);

   if (!encode_base64(binarydata, asciidata))
      return(0);

   asciidata->data[asciidata->offset++] = '=';

   if (!encode_base64(&crcdata, asciidata))
      return(0);

   ddesc_append(asciidata, tailline_head);
   ddesc_append(asciidata, headerline);
   ddesc_append(asciidata, tailline_tail);

   return(1);
}
