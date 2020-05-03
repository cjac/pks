#ifndef _PGPUTIL_H_
#define _PGPUTIL_H_

/*
 * $Id: pgputil.h,v 1.2 2003/01/26 16:08:58 dmshaw Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include <time.h>

typedef struct _ddesc {
   unsigned char *data;
   long size;
   long offset;
} ddesc;

typedef struct _mpidesc {
   long nbits;
   ddesc number;
} mpidesc;

#define DECODE_READABLE(data, length) \
	((data)->size >= ((data)->offset + (length)))

typedef int (*packet_handler)(ddesc *packet, void *closure);

int decode_num(ddesc *data, long size, long *num);
int decode_psf(ddesc *data, long *ptype, long *plen);
int decode_pubkey(ddesc *data, long len, mpidesc *modulus, mpidesc *exponent,
		  unsigned char *keyid, unsigned char *keytype,
		  time_t *create_time, int *keyversion);
int decode_userid(ddesc *data, long len, ddesc *userid);
int decode_sig(ddesc *data, long len, ddesc *keyid, long *sigclass,
	       time_t *sigtime);
int decode_file(ddesc *data, packet_handler h, void *c);
int decode_binary(ddesc *data, packet_handler h, void *c);

#endif
