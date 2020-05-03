#ifndef _KD_TYPES_H_
#define _KD_TYPES_H_

#include <time.h>

#include "util.h"
#include "llist.h"

/*
 * $Id: kd_types.h,v 1.3 2003/01/26 19:54:46 dmshaw Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

typedef struct _words_elem {
   unsigned char *ptr; /* ptr into userid xbuffer */
   long len;
} words_elem;

typedef struct _sigs_elem {
   xbuffer keyid;
   xbuffer sig;
   time_t sig_time;
} sigs_elem;

typedef struct _userids_elem {
   xbuffer uid;
   unsigned char *uidprint;
   long uidplen;
   llist sigs;
} userids_elem;

typedef struct _keys_elem {
   xbuffer pubkey;
   xbuffer subkey;
   xbuffer subkeysig;
   int modsigbits;
   xbuffer modbits, expbits;	/* used only for RSA fingerprint computation */
   xbuffer keyidbits;
   int keytype;
   int keyversion;
   time_t create_time;
   int disabled;
   userids_elem *primary;
   xbuffer revocation;
   llist userids;
   llist words;
} keys_elem;

void sigs_elem_alloc(sigs_elem *se);
void userids_elem_alloc(userids_elem *ue);
void keys_elem_alloc(keys_elem *ke);
int malloc_elem_free(void *e, void *c);
int sigs_elem_free(void *e, void *c);
int userids_elem_free(void *e, void *c);
int keys_elem_free(void *e, void *c);
int bytestr_order(const unsigned char *s1, long s1len,
		  const unsigned char *s2, long s2len);
int words_elem_order(const void *e1, const void *e2);
int sigs_elem_order(const void *e1, const void *e2);
int userids_elem_order(const void *e1, const void *e2);
int keys_elem_order(const void *e1, const void *e2);

#endif
