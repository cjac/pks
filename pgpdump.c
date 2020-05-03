const char rcsid_pgpdump_c[] = "$Id: pgpdump.c,v 1.2 2003/02/07 01:01:21 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

/*
 * XXX this file isn't completely 5.0 compatible yet
 */

#include <stdio.h>
#include <time.h>

#include "pgputil.h"
#include "md5.h"
#include "util.h"
#include "pgpfile.h"

int unparse_packet(ddesc *packet, void *c)
{
   long ptype, plen;

   if (!decode_psf(packet, &ptype, &plen))
      return(0);

   printf("type=%ld, len=%ld\n", ptype, plen);

   switch (ptype) {
    case 6:
      /* public key packet */
      {
	 mpidesc modulus, exponent;
	 unsigned char keyid[8];
	 unsigned char keytype;
	 time_t dummy;
	 int keyversion = 4; /* Assume v4 keys. */
	 MD5_CTX md5ctx;
	 unsigned char hash[16];
	 int i;

	 if (!decode_pubkey(packet, plen, &modulus, &exponent, keyid,
			    &keytype, &dummy, &keyversion))
	    return(0);

         if (keytype == 1) { /* RSA */
             MD5Init(&md5ctx);
             MD5Update(&md5ctx, modulus.number.data, modulus.number.size);
             MD5Update(&md5ctx, exponent.number.data, exponent.number.size);
             MD5Final(hash, &md5ctx);

             printf("  Public key packet alg %d\n  Key ID = ", keytype);
             for (i=modulus.number.size-4; i<modulus.number.size; i++)
                 printf("%02X", modulus.number.data[i]);

             printf("\n  Key fingerprint = ");
             for (i=0; i<8; i++)
                 printf("%02X ", hash[i]);
             printf(" ");
             for (i=8; i<16; i++)
                 printf("%02X ", hash[i]);
             printf("\n");
         } else {
             printf("  Public key packet alg %d\n  Key ID = ", keytype);
             for (i=4; i<8; i++)
                 printf("%02X", keyid[i]);
             printf("\n");
         }
      }
      break;
    case 12:
      /* trust packet */
      {
	 long trust;

	 if (!decode_num(packet, 1, &trust))
	    return(0);

	 printf("  Trust packet\n  trust value = %ld\n", trust);
      }
      break;
    case 13:
      /* user id packet */
      {
	 ddesc userid;

	 if (!decode_userid(packet, plen, &userid))
	    return(0);

	 printf("  User id packet\n  User id: \"%.*s\"\n",
		(int) userid.size, userid.data);
      }
      break;
    case 2:
      /* signature packet */
      {
	 ddesc keyid;
	 long sigclass;
	 time_t sigtime;
	 int i;

	 if (!decode_sig(packet, plen, &keyid, &sigclass, &sigtime))
	    return(0);

	 printf("  Signature packet\n  Signing key ID = ");
	 for (i=4; i<8; i++)
	    printf("%02X", keyid.data[i]);

	 printf("\n  Signature class = 0x%02lX\n", sigclass);
	 printf("  Signature time = %ld\n", (long) sigtime);
      }
      break;
   }

   return(1);
}

int do_file(ddesc *data)
{
   return(decode_file(data, unparse_packet, NULL));
}
