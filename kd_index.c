const char rcsid_kd_index_c[] = "$Id: kd_index.c,v 1.12 2003/01/26 19:54:45 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "database.h"
#include "globals.h"
#include "llist.h"
#include "md5.h"
#include "kd_types.h"
#include "kd_internal.h"
#include "kd_search.h"

#include "shs.h"

typedef struct _gfu_state {
   unsigned char *ptr;
   long len;
} gfu_state;

int get_first_userid(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   gfu_state *s = (gfu_state *) c;

   /* if there was likely to be more than one key in one of these
      lists, I'd deal with a truncation return, but it's not
      worth it */

   if (!s->ptr) {
      s->ptr = ke->primary->uidprint;
      s->len = ke->primary->uidplen;
   }

   return(1);
}

typedef struct _gi_state {
   kd_txn tid;
   int verbose;
   xbuffer *xb;
} gi_state;

int sigs_elem_genindex(void *e, void *c)
{
   sigs_elem *se = (sigs_elem *) e;
   gi_state *s = (gi_state *) c;
   llist keys;
   error err;
   gfu_state gfus;
   char buf[512];

   if (se->keyid.buf == NULL) {
       return xbuffer_append_str(s->xb, "sig       ????????              [X.509 Signature]\n");
   }
   
   llist_alloc(&keys);
   err.str = err.buf;

   if (!kd_get_keys_by_keyid(s->tid, se->keyid.buf, &keys, &err)) {
      if (err.fatal) {
	 llist_free(&keys);
	 return(0);
      }
   }

   if (llist_count(&keys)) {
      gfus.ptr = NULL;

      if (!llist_iterate(&keys, get_first_userid, (void *) &gfus))
	 return(0);

      sprintf(buf, "sig        %02X%02X%02X%02X             %.*s\n",
	      se->keyid.buf[se->keyid.len-4],
	      se->keyid.buf[se->keyid.len-3],
	      se->keyid.buf[se->keyid.len-2],
	      se->keyid.buf[se->keyid.len-1],
	      (int) gfus.len, gfus.ptr);
   } else {
      sprintf(buf, "sig        %02X%02X%02X%02X             (Unknown signator, can't be checked)\n",
	      se->keyid.buf[se->keyid.len-4],
	      se->keyid.buf[se->keyid.len-3],
	      se->keyid.buf[se->keyid.len-2],
	      se->keyid.buf[se->keyid.len-1]);
   }

   llist_iterate(&keys, keys_elem_free, NULL);
   llist_free(&keys);

   if (!xbuffer_append_str(s->xb, buf))
      return(0);

   return(1);
}

int userids_elem_genindex(void *e, void *c)
{
   userids_elem *ue = (userids_elem *) e;
   gi_state *s = (gi_state *) c;
   char buf[512];

   sprintf(buf, "                               %.*s\n",
	   (int) ue->uidplen, ue->uidprint);

   if (!xbuffer_append_str(s->xb, buf))
      return(0);

   if (s->verbose) {
      if (!llist_iterate(&(ue->sigs), sigs_elem_genindex, c))
	 return(0);
   }

   return(1);
}

int userids_elem_genmrindex(void *e, void *c)
{
   userids_elem *ue = (userids_elem *) e;
   gi_state *s = (gi_state *) c;
   int i=0;
   char buf[512+5],tmp[512];

   while(ue->uidplen && *(ue->uidprint))
     {
       if(*(ue->uidprint)==':')
	 {
	   tmp[i++]='%';
	   tmp[i++]='3';
	   tmp[i++]='A';
	 }
       else if(*(ue->uidprint)=='%')
	 {
	   tmp[i++]='%';
	   tmp[i++]='2';
	   tmp[i++]='5';
	 }
       else
	 tmp[i++]=*(ue->uidprint);

       ue->uidprint++;
       ue->uidplen--;

       if(i>509)
	 return(1);
     }

   /* For the sake of sanity, please do not change this format without
      talking to David Shaw <dshaw@jabberwocky.com> first. */

   sprintf(buf,"uid:%.*s\n",i,tmp);

   if (!xbuffer_append_str(s->xb, buf))
      return(0);

   return(1);
}

typedef struct _keg_state {
   kd_txn tid;
   int flags;
   xbuffer *xb;
} keg_state;

int keys_elem_genindex(void *e, void *c)
{

   keys_elem *ke = (keys_elem *) e;
   keg_state *s = (keg_state *) c;
   gi_state gis;
   char buf[512];
   struct tm *c_tm;
   MD5_CTX md5ctx;
   SHS_CTX sha;
   unsigned char hash[20];
   int i;
   unsigned int pos = 0;


   /* pgp does gmtime, so we do, too */
   c_tm = gmtime(&(ke->create_time));

   sprintf(buf, "pub%c%5d%c/%02X%02X%02X%02X %04d/%02d/%02d %s%.*s\n",
	   (ke->disabled?'-':' '),
	   (int) ke->modsigbits,
	   ((ke->keytype == 1)?'R':'D'),
	   ke->keyidbits.buf[4],
	   ke->keyidbits.buf[5],
	   ke->keyidbits.buf[6],
	   ke->keyidbits.buf[7],
	   c_tm->tm_year+1900, c_tm->tm_mon+1, c_tm->tm_mday,
	   (ke->revocation.len?
	    "*** KEY REVOKED ***\n                              ":""),
	   (int) ke->primary->uidplen,
	   ke->primary->uidprint);

   if (!xbuffer_append_str(s->xb, buf))
      return(0);

   if (s->flags & KD_INDEX_FINGERPRINT) {
      if (ke->keyversion>3) {
         shsInit(&sha);
         shsUpdate(&sha, ke->pubkey.buf, ke->pubkey.len);
         shsFinal(&sha, hash);
      } else {
         MD5Init(&md5ctx);
         MD5Update(&md5ctx, ke->modbits.buf, ke->modbits.len);
         MD5Update(&md5ctx, ke->expbits.buf, ke->expbits.len);
         MD5Final(hash, &md5ctx);
      }

      pos = 0;
      /* print longer SHA-1 hashes differently */
      if (ke->keyversion>3) {
	for (i = 0; i < 20; i += 2) {
	  sprintf (&buf[pos], "%02X%02X ", hash[i], hash[i+1]);
	  pos += 5; /* just added n chars... */
	  /* add another space halfway through... */
	  if (i == 8) {
	    buf[pos] = ' ';
	    pos++;
	  }
	} /* for i */
	pos--; /* remove last space */
	buf[pos] = '\n';
      } else { /* version<=3 */
	for (i=0; i<8; i++)
	  sprintf(buf+i*3, "%02X ", hash[i]);
	buf[24] = ' ';
	for (i=8; i<16; i++)
	  sprintf(buf+1+i*3, "%02X ", hash[i]);
	buf[48] = '\n';
      } /* if else on keytype */

      if (!xbuffer_append_str(s->xb, "     Key fingerprint = "))
	 return(0);
      if (ke->keyversion>3) {
         if (!xbuffer_append(s->xb, (unsigned char *) buf, 51))
	    return(0);
      } else {
         if (!xbuffer_append(s->xb, (unsigned char *) buf, 49))
	    return(0);
      }
   }

   gis.tid = s->tid;
   gis.verbose = (s->flags & KD_INDEX_VERBOSE);
   gis.xb = s->xb;

   if (s->flags & KD_INDEX_VERBOSE) {
      if (!llist_iterate(&(ke->primary->sigs), sigs_elem_genindex, &gis))
	 return(0);
   }

   if (!llist_iterate(&(ke->userids), userids_elem_genindex, &gis))
      return(0);

   return(1);
}

int keys_elem_genmrindex(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   keg_state *s = (keg_state *) c;
   gi_state gis;
   char buf[512];

   /* For the sake of sanity, please do not change this format without
      talking to David Shaw <dshaw@jabberwocky.com> first. */

   /* It is possible to put the 16-digit keyid or fingerprint here,
      but until the server can actually make use of all of the
      available precision, it is misleading to include it in the
      response. */
   sprintf(buf,"pub:%02X%02X%02X%02X:%u:%u:%lu::%s%s\n",
	   ke->keyidbits.buf[4],
	   ke->keyidbits.buf[5],
	   ke->keyidbits.buf[6],
	   ke->keyidbits.buf[7],
	   ke->keytype,ke->modsigbits,ke->create_time,
	   ke->revocation.len?"r":"",
	   ke->disabled?"d":""
	   );

   if (!xbuffer_append_str(s->xb, buf))
      return(0);

   gis.tid = s->tid;
   gis.verbose = (s->flags & KD_INDEX_VERBOSE);
   gis.xb = s->xb;

   if(!userids_elem_genmrindex(ke->primary,&gis))
     return 0;

   if (!llist_iterate(&(ke->userids), userids_elem_genmrindex, &gis))
      return(0);

   return(1);
}

typedef struct _kegc_state {
   FILE *out;
   keg_state keg;
} kegc_state;

int keys_elem_genindex_cout(void *e, void *c)
{
   kegc_state *s = (kegc_state *) c;

   if (!keys_elem_genindex(e, &s->keg))
      fail();

   fwrite(s->keg.xb->buf, s->keg.xb->len, 1, s->out);

   /* "remove" the data from the buffer, but don't free it.
      this will save a lot of malloc/free calls */
   s->keg.xb->len = 0;

   return(1);
}

int kd_index_1(kd_txn tid, unsigned char *userid, long len, int flags,
	       int maxkeys, xbuffer *index, error *err)
{
   keg_state kegs;
   int ret;

   /* This is called violating abstractions in the interest of
      efficiency.  Whee. */

   if (flags & KD_INDEX_STDOUT) {
      kegc_state kegcs;
      xbuffer buf;

      xbuffer_alloc(&buf);

      kegcs.out = stdout;
      kegcs.keg.tid = tid;
      kegcs.keg.flags = flags;
      kegcs.keg.xb = &buf;

      ret = kd_search_1(tid, userid, len, flags & KD_SEARCH_FLAGS, maxkeys,
			keys_elem_genindex_cout, NULL, &kegcs, err);

      xbuffer_free(&buf);

      return(ret);
   }

   kegs.tid = tid;
   kegs.flags = flags;
   kegs.xb = index;

   if (!kd_search_1(tid, userid, len, flags & KD_SEARCH_FLAGS, maxkeys,
		    flags&KD_INDEX_MR?keys_elem_genmrindex:keys_elem_genindex,
		    NULL, &kegs, err))
      return(0);

   if (index->len == 0) {
      /* no matching keys in database */

      err->fatal = 0;
      err->str = "No matching keys in database";
      return(0);
   }

   return(1);
}

int kd_index(unsigned char *userid, long len, int flags, int maxkeys,
	     unsigned char **ret, long *retlen)
{
   error err;
   xbuffer index;
   kd_txn tid;

   err.str = err.buf;
   xbuffer_alloc(&index);

   kd_log_start("kd_index", userid, len, flags);

   if (kd_txn_begin(&tid, &err) &&
       kd_index_1(tid, userid, len, flags, maxkeys, &index, &err) &&
       kd_txn_commit(tid, &err)) {
      *ret = index.buf;
      *retlen = index.len;

      kd_log_finish("kd_index", 1);

      return(1);
   }

   kd_txn_abort(tid, NULL);

   if (!err.fatal) {
      if (!(*ret = (unsigned char *) my_strdup(err.str))) {
	 err.fatal = 1;
	 err.str = "Failed allocating space for error string";
	 dabort();

	 /* fall through to fatal error handler */
      } else {
	 *retlen = strlen((char *) *ret);

	 kd_log_finish("kd_index", 0);

	 return(0);
      }
   }

   /* fatal errors */

   if (err.fatal) {
      log_fatal("kd_index", err.str);
      /* never returns */
   }

   /* keep the compiler quiet */

   return(0);
}
