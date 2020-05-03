const char rcsid_kvcv_c[] = "$Id: kvcv.c,v 1.5 2003/02/07 01:01:18 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "globals.h"
#include "pgputil.h"
#include "md5.h"
#include "pgpfile.h"
#include "shs.h"

/* when you see a type 6 (pubkey), forget all state
   when you see the first type 13, print the pk header
   */

struct state {
   int got_pk, got_userid, got_revoke;
   ddesc pubkey;
   long pubkeylen;
};

int kvcv(ddesc *packet, void *c)
{
   long ptype, plen;
   struct state *s = (struct state *) c;

   if (!decode_psf(packet, &ptype, &plen)) {
       log_error("decode_psf", "");
       return(0);
   }
   

   switch (ptype) {
    case 6:
      /* public key packet */
      {
	 s->got_pk = 1;
	 s->got_userid = 0;
	 s->got_revoke = 0;
	 s->pubkey = *packet;
	 s->pubkeylen = plen;
      }
      break;
    case 14:
       /* subkey packet */
       {
	  mpidesc m, e;
	  unsigned char keytype;
	  time_t create_time;
	  int keyversion = 4; /* Assume v4 keys. */

	  if (!decode_pubkey(packet, plen, &m, &e, NULL, &keytype,
			     &create_time, &keyversion)) {
	       log_error("decode_pubkey", "");
	     return(0);
	  }

	  switch (keytype) {
	  case 1:
	     printf("subkey (RSA)\n");
	     break;
	  case 16:
	     printf("subkey (DSA)\n");
	     break;
	  case 17:
	     printf("subkey (ElGamal)\n");
	     break;
	  default:
	     printf("subkey (type %d)\n", keytype);
	     break;
	  }
	  break;
       }
    case 13:
      /* user id packet */
      {
	 int i;
	 ddesc userid;

	 if (!decode_userid(packet, plen, &userid)) {
	    log_error("decode_userid", "");
	    return(0);
	 }

	 if (s->got_userid) {
	    printf("                              %.*s\n",
		   (int) userid.size, userid.data);
	 } else if (s->got_pk) {
	    mpidesc modulus, exponent;
	    unsigned char keytype;
	    time_t create_time;
	    int keyversion = 4; /* Assume v4 keys. */
	    MD5_CTX md5ctx;
	    SHS_CTX sha;
	    unsigned char hash[20];
	    struct tm *c_tm;

	    if (!decode_pubkey(&(s->pubkey), s->pubkeylen, &modulus,
			       &exponent, NULL, &keytype, &create_time,
			       &keyversion)) {
	 	 log_error("decode_pubkey 2", "");
	       return(0);
	    }

            if (keytype == 16 || keytype == 17) {
               shsInit(&sha);
               shsUpdate(&sha, s->pubkey.data, s->pubkey.size);
               shsFinal(&sha, hash);
            } else {
	       MD5Init(&md5ctx);
	       MD5Update(&md5ctx, modulus.number.data, modulus.number.size);
	       MD5Update(&md5ctx, exponent.number.data, exponent.number.size);
	       MD5Final(hash, &md5ctx);
	    }

	    /* pgp does gmtime, so we do, too */
	    c_tm = gmtime(&create_time);

	    printf("pub%6d/%02X%02X%02X%02X %04d/%02d/%02d %s%.*s\n"
		   "          Key fingerprint =  ",
		   (int) modulus.nbits,
		   modulus.number.data[modulus.number.size-4],
		   modulus.number.data[modulus.number.size-3],
		   modulus.number.data[modulus.number.size-2],
		   modulus.number.data[modulus.number.size-1],
		   c_tm->tm_year+1900, c_tm->tm_mon+1, c_tm->tm_mday,
		   (s->got_revoke?
		    "*** KEY REVOKED ***\n                              ":""),
		   (int) userid.size, userid.data);

	    for (i=0; i<8; i++)
	       printf("%02X ", hash[i]);
	    printf(" ");
	    for (i=8; i<16; i++)
	       printf("%02X ", hash[i]);
            if (keytype == 16 || keytype == 17) {
	       printf(" ");
	       for (i=16; i<20; i++)
	          printf("%02X ", hash[i]);
	    }

	    printf("\n");

	    switch (keytype) {
	    case 1:
	       printf("          key type RSA\n");
	       break;
	    case 16:
	       printf("          key type DSA\n");
	       break;
	    case 17:
	       printf("          key type ElGamal\n");
	       break;
	    default:
	       printf("          key type %d\n", keytype);
	       break;
	    }

	    s->got_userid = 1;
	 }
      }
      break;
    case 2:
      /* signature packet */
      {
	 ddesc keyid;
	/* Point to "null" by default */
	 long sigclass;
	 time_t sigtime;
	 int i;

	 keyid.data = NULL;
	 if (!decode_sig(packet, plen, &keyid, &sigclass, &sigtime)) {
	      log_error("decode_sig", "");
	    return(0);
	 }

	 if (keyid.data == NULL) {
	     printf("sig       ????????         [X.509 Signature]\n");
	 } else if (sigclass == 0x20) {
	    /* key revoked */
	    s->got_revoke = 1;
	 } else if (sigclass == 0x10) {
	    printf("sig       ");
	    for (i=4; i<8; i++)
	       printf("%02X", keyid.data[i]);
	    printf("             (can't do keyid->name conversion yet)\n");
	 } else if (sigclass == 0x18) {
	    printf("             (subkey signature)\n");
	 } else {
	    printf("             (funny signature packet (class %02lX))\n",
		   sigclass);
	 }
      }
      break;
   }

   return(1);
}

int do_file(ddesc *data)
{
   struct state s;

   s.got_pk = 0;
   s.got_userid = 0;
   s.got_revoke = 0;

   return(decode_file(data, kvcv, (void *) &s));
}

/* These are just dummy, for the linker */
void kd_close(void)
{
}

int debug;
