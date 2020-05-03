const char rcsid_pgputil_c[] = "$Id: pgputil.c,v 1.5 2003/01/26 16:08:58 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "globals.h"
#include "pgputil.h"
#include "armor.h"
#include "shs.h"

#ifdef HANDLE_X509
#include <openssl/x509.h>
#endif

int generate_v4_keyid(ddesc *data, unsigned char *keyid)
{
   unsigned char hash[20];
   SHS_CTX sha;

   shsInit(&sha);
   shsUpdate(&sha, data->data, data->size);
   shsFinal(&sha, hash);

   /* We only need the low order 64 bits */
   memcpy(keyid, hash+12, 8);

   return 1;
}

int decode_num(ddesc *data, long size, long *num)
{
   long i;
   long tmp = 0;

   if (!DECODE_READABLE(data, size))
      return(0);

   for (i=0; i<size; i++)
      tmp = (tmp<<8) + data->data[data->offset++];

   *num = tmp;
   return(1);
}
   
int decode_bytestr(ddesc *data, long len, ddesc *bytestr)
{
   if (!DECODE_READABLE(data, len))
      return(0);

   bytestr->data = data->data+data->offset;
   bytestr->size = len;
   bytestr->offset = 0;

   data->offset += len;

   return(1);
}

int decode_psf(ddesc *data, long *ptype, long *plen)
{
   unsigned char ch;
   long tmp;

   if (!DECODE_READABLE(data, 1))
      return(0);

   ch = data->data[data->offset++];

   if ((ch & 0xc0) != 0x80)
      return(0);

   tmp = ((ch & 0x3c) >> 2);

   switch (tmp) {
    case 0:
    case 3:
    case 4:
    case 7:
    case 8:
    case 10:
    case 15:
      return(0);
    default:
      *ptype = tmp;
      break;
   }

   tmp = (ch & 0x03);

   switch (tmp) {
    case 0:
      if (!decode_num(data, 1, plen))
	 return(0);
      break;
    case 1:
      if (!decode_num(data, 2, plen))
	 return(0);
      break;
    case 2:
      if (!decode_num(data, 4, plen))
	 return(0);
      break;
    case 3:
      return(0);
      break;
   }

   return(1);
}

int decode_mpi(ddesc *data, mpidesc *mpi)
{
   if (!decode_num(data, 2, &(mpi->nbits)))
      return(0);

   return(decode_bytestr(data, (mpi->nbits+7)/8, &(mpi->number)));
}

int decode_string(ddesc *data, ddesc *str)
{
   long tmp;

   if (!decode_num(data, 1, &tmp))
      return(0);

   return(decode_bytestr(data, tmp, str));
}

int decode_time(ddesc *data, time_t *t)
{
   long tmp;

   if (!decode_num(data, 4, &tmp))
      return(0);

   *t = (time_t) tmp;

   return(1);
}

#ifdef HANDLE_X509
int decode_x509(ddesc *data, long len, ddesc *keyid)
{
   X509 *cert = NULL;
   EVP_PKEY *pkey;
   int ret = 0;
   char *keyid_hex;
   BIGNUM *b;
   unsigned char *data_start = data->data+data->offset;

   if (d2i_X509(&cert, &data_start, len) != NULL) {
      /* X.509 certificate has been parsed,
         now get keyid = last 4 bytes of modulus */
      pkey = X509_get_pubkey(cert);
      if (pkey != NULL && pkey->type == EVP_PKEY_RSA) {
         /* pkey->pkey.rsa->n is the modulus */
	 b = BN_dup(pkey->pkey.rsa->n);
	 BN_mask_bits(b,32);
         keyid_hex = BN_bn2hex(b);
         if (keyid_hex != NULL) {
            /* left pad with zeroes if necessary */
	    if ((keyid->data = malloc(8)) != NULL) {
	       memset(keyid->data,'0',8);
               memcpy(keyid->data+8-strlen(keyid_hex),keyid_hex,strlen(keyid_hex));
	       free(keyid_hex);
	       keyid->size = 8;
	       ret = 1;
	    }
	 }
      }
   }
   data->offset += len;
   return(ret);
}

int decode_nai(ddesc *data, long len, ddesc *keyid)
{
   len -= 3;			/* skip header */
   if (len < 0 || data->data[data->offset++] != 1 ||
       data->data[data->offset++] != 1 ||
       data->data[data->offset++] != 4) {
      /* don't know how to handle this case */
      data->offset += len;
      return(0);
   }

   /* here follows an asn.1 coded X.509 certificate */
   return(decode_x509(data, len, keyid));
}
#endif

int decode_subpacket(ddesc *data, time_t *sig_time, ddesc *keyid)
{
   long OverallSPlen;
   long SPlen;
   long SPtype;

   OverallSPlen = (data->data[data->offset++]) << 8;
   OverallSPlen += data->data[data->offset++];

   while (OverallSPlen > 0) {
      SPlen = data->data[data->offset++];
      if (SPlen >= 192) {
         SPlen = ((SPlen & 0x3F) << 8) + data->data[data->offset++] + 192;
	 OverallSPlen--;
      }
      OverallSPlen--;
      
      SPtype = data->data[data->offset++] & 0x7F;

      if (SPtype == 2)			/* Sig creation time */
         decode_time(data, sig_time);
      else if (SPtype == 16)		/* keyid of signer */
	 decode_bytestr(data, SPlen - 1, keyid);
#ifdef HANDLE_X509
      else if (SPtype == 100)           /* NAI private */
	 decode_nai(data, SPlen - 1, keyid);
#endif
      else
         data->offset += SPlen - 1;

      OverallSPlen -= SPlen;
   }

   if (OverallSPlen != 0)
      return(0);

   return(1);
}


int decode_pubkey(ddesc *data, long len, mpidesc *modulus, mpidesc *exponent,
		  unsigned char *keyid, unsigned char *keytype,
		  time_t *create_time, int *keyversion)
{
   long version, valid_days, pkctype;
   unsigned char *pktend = data->data+data->offset+len;
   mpidesc publicbits, grouporder, groupgenerator;

   if (!decode_num(data, 1, &version))
      return(0);

   if(keyversion)
     *keyversion=version;

   if ((version != 2) && (version != 3) && (version !=4))
      return(0);

   if (!decode_time(data, create_time))
      return(0);

   if (version < 4)
      if (!decode_num(data, 2, &valid_days))
         return(0);

   if (!decode_num(data, 1, &pkctype))
      return(0);

   /* This is pretty sloppy.  It will set the type to DSA first time
      through then to ElGamal the last time through (for each packet).
      Either DSA or ElGamal should be considered the same. */
   *keytype = pkctype;

   switch (pkctype) {
   case 1: /*RSA*/
   case 2:
   case 3:
      if (!decode_mpi(data, modulus))
         return(0);

      if (!decode_mpi(data, exponent))
         return(0);
      break;
   case 17: /*DSA*/
      if (!decode_mpi(data, modulus))
         return(0);

      if (!decode_mpi(data, &grouporder))
         return(0);

      if (!decode_mpi(data, &groupgenerator))
         return(0);

      if (!decode_mpi(data, &publicbits))
         return(0);
      break;
   case 16: /*ElGamal*/
   case 20:
      if (!decode_mpi(data, modulus))
         return(0);

      if (!decode_mpi(data, &groupgenerator))
         return(0);

      if (!decode_mpi(data, &publicbits))
         return(0);
      break;
   default:
      return(0);
   }

   if (keyid)
     {
       if(version>3)
	 generate_v4_keyid(data,keyid);
       else
	 memcpy(keyid, &modulus->number.data[modulus->number.size - 8], 8);
     }

   return(pktend == (data->data + data->offset));
}

/* the spec seems to lie, since the userid strings I actually see
 * don't seem to have a one-byte length */

int decode_userid(ddesc *data, long len, ddesc *userid)
{
   return(decode_bytestr(data, len, userid));
}

int decode_sig(ddesc *data, long len, ddesc *keyid, long *sigclass,
	       time_t *sig_time)
{
   long version, five, pkctype, mdtype;
   ddesc cksum;
   mpidesc sig;
   unsigned char *pktend = data->data+data->offset+len;
#if 0
   char msg[100];
#endif

   keyid->size = 0;

   if (!decode_num(data, 1, &version))
      return(0);

   if (version < 4) {
      if ((version != 2) && (version != 3))
         return(0);

      if (!decode_num(data, 1, &five))
         return(0);

      if (five != 5)
         return(0);

      if (!decode_num(data, 1, sigclass))
         return(0);

      if (!decode_time(data, sig_time))
         return(0);
  
      if (!decode_bytestr(data, 8, keyid))
         return(0);

      if (!decode_num(data, 1, &pkctype))
         return(0);

      if (!decode_num(data, 1, &mdtype))
         return(0);

      if (!decode_bytestr(data, 2, &cksum))
         return(0);

      switch (pkctype) {
      case 1: /*RSA: 1*MPI*/
      case 2:
      case 3:
         if (!decode_mpi(data, &sig))
	    return(0);
         break;
      case 17: /*DSA: 2*MPI*/
         if (!decode_mpi(data, &sig) || !decode_mpi(data, &sig))
	    return(0);
         break;
      default:
         /* this is kind of ugly.  There can be any number of MPI's here
            (although 1 is most likely, and no documented pkctype uses
            more than 2). */
         while (DECODE_READABLE(data, 1)) {
            if (!decode_mpi(data, &sig))
               return(0);
         }
         break;
      }
      if (pktend != data->data+data->offset) {
#if 0
         sprintf(msg, "%d sig bytes ignored (pkctype=%ld)",
                 pktend-(data->data+data->offset), pkctype);

	 /* at some point, this should become a soft_err() */
         log_info("decode_sig", msg);
#endif
	 if (!decode_bytestr(data, pktend-(data->data+data->offset),
			     &sig.number))
	    return(0);
      }
   } else {
      if (version != 4)
         return(0);

      if (!decode_num(data, 1, sigclass))
         return(0);

      if (!decode_num(data, 1, &pkctype))
         return(0);

      if (!decode_num(data, 1, &mdtype))
         return(0);

      keyid->size = 0;

      if (!decode_subpacket(data, sig_time, keyid))
         return(0);

      if (!decode_subpacket(data, sig_time, keyid))
         return(0);

      if (!decode_bytestr(data, 2, &cksum))
         return(0);

      /* This is probably an x.509 signature.  Fill in a bogus keyid
	 until I have a better way of dealing with this.  keyid is
	 normally a pointer into another dynamically allocated bit of
	 data, so making it a pointer to static data will work
	 fine. */
      if (keyid->size == 0) {
	 static unsigned char boguskeyid[8] = "????????";
	 keyid->data = boguskeyid;
	 keyid->size = sizeof(boguskeyid);
	 keyid->offset = 0;
      }

      switch (pkctype) {
      case 1: /*RSA: 1*MPI*/
      case 2:
      case 3:
         if (!decode_mpi(data, &sig))
	    return(0);
         break;
      case 17: /*DSA: 2*MPI*/
         if (!decode_mpi(data, &sig) || !decode_mpi(data, &sig))
	    return(0);
         break;
#if 0
      case 100: /* X.509 */
	 if (!decode_x509(data, &sig)
	    return(0);
         break;
#endif
      default:
         /* this is kind of ugly.  There can be any number of MPI's here
            (although 2 is the largest and most likely number. */
         while (DECODE_READABLE(data, 1)) {
            if (!decode_mpi(data, &sig))
               return(0);
         }
         break;
      }
      if (pktend != data->data+data->offset) {
#if 0
         sprintf(msg, "%d sig bytes ignored (pkctype=%ld)",
                 pktend-(data->data+data->offset), pkctype);

	 /* at some point, this should become a soft_err() */
         log_info("decode_sig", msg);
#endif
	 if (!decode_bytestr(data, pktend-(data->data+data->offset),
			     &sig.number))
	    return(0);
      }
   }

   return(keyid->size > 0);
}

int decode_packet(ddesc *data, packet_handler h, void *c)
{
   long ptype, plen;
   ddesc packet;

   packet.data = data->data+data->offset;

   if (!decode_psf(data, &ptype, &plen))
      return(0);

   packet.size = ((data->data+data->offset) - packet.data) + plen;
   packet.offset = 0;

   if (!DECODE_READABLE(data, plen))
      return(0);

   data->offset += plen;

   if (!(*h)(&packet, c))
      return(0);

   return(1);
}

int decode_binary(ddesc *data, packet_handler h, void *c)
{
   while (DECODE_READABLE(data, 1)) {
      if (!decode_packet(data, h, c))
	 return(0);
   }

   return(1);
}

int decode_file(ddesc *data, packet_handler h, void *c)
{
   ddesc tmp;
   long n1;
   long n2;

   tmp = *data;

   if (decode_psf(&tmp, &n1, &n2))
      return(decode_binary(data, h, c));
   else
      return(decode_ascii(data, h, c));
}

