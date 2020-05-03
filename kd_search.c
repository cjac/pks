const char rcsid_kd_search_c[] = "$Id: kd_search.c,v 1.11 2003/02/02 17:22:27 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <db.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "pgputil.h"
#include "database.h"
#include "globals.h"
#include "llist.h"
#include "kd_types.h"
#include "kd_internal.h"
#include "kd_search.h"
#include "util.h"

typedef struct _mke_state {
   /* what do do with the key when done */
   llist_iter iter;
   void *c;
   /* this is set when a secret key packet is seen. */
   int ignoring;
   /* temp vars */
   keys_elem *ke;
   userids_elem *ue;
   /* error returns */
   error *err;
   ki_softerr *softerr;
   /* used to not show errors in certain cases, so that
      already-mangled keys in the database don't cause errors when
      searched for */
   int errorhack;
} mke_state;

int finish_userid(mke_state *s)
{
   int ret;

   /* this is called when a userid's signature list ends.  This happens
      when a userid or public key is seen, or at the end of the keyblock.
      s->ue contains the current userid entry, including the uid,
      and possibly signatures */

   /* this just means this is the first userid in a pubkey,
      so there's no other userid to finish */
   if (!s->ue)
      return(1);

   /* if there's a userid but no pubkey, that's an error */
   if (!s->ke) {
      s->err->fatal = 0;
      s->err->str = "Key block corrupt: userid before public key";
      return(0);
   }

   if (!s->ke->primary) {
      /* if the primary userid isn't set, this is it */
      s->ke->primary = s->ue;
   } else if (userids_elem_order(s->ke->primary, s->ue) == 0) {
      /* if this userid is the same as the primary, merge the sig lists */

      llist merged_sigs;

      llist_alloc(&merged_sigs);

      if (!llist_merge(&merged_sigs, &(s->ke->primary->sigs),
		       &(s->ue->sigs),
		       kd_sigs_elem_merge, NULL,
		       userids_elem_free, NULL)) {
	 s->err->fatal = 1;
	 s->err->str = "Failed merging duplicate into sigs list";
	 fail();
      }

      s->ke->primary->sigs = merged_sigs;

      userids_elem_free(s->ue, NULL);

      s->ue = NULL;
   } else {
      /* otherwise, insert this userid to the list of userids */
      if (!(ret = llist_add_sorted(&(s->ke->userids), s->ue,
				   userids_elem_order))) {
	 s->err->fatal = 1;
	 s->err->str = "Appending userids_elem to userids failed";
	 fail();
      }
      if (ret == -1) {
	 llist tmp, merged_userids;

	 llist_alloc(&tmp);
	 llist_alloc(&merged_userids);

	 if (!llist_add(&tmp, s->ue)) {
	    s->err->fatal = 1;
	    s->err->str = "Failed creating duplicate userid list";
	    fail();
	 }

	 /* the order of args 2 and 3 are significant.  For the element
	    which matches, the userid string in tmp is thrown away,
	    only the sigs are kept */

	 if (!llist_merge(&merged_userids, &tmp, &(s->ke->userids),
			  kd_userids_elem_merge, NULL,
			  userids_elem_free, NULL)) {
	    s->err->fatal = 1;
	    s->err->str = "Failed merging duplicate into userid list";
	    fail();
	 }

	 s->ke->userids = merged_userids;

	 s->ue = NULL;
      }
   }

   /* this is non-NULL if the userid was added into the keys_elem, and
      not ignored (already in the keys_elem).  take the words from the
      userid string and stash them in the keys_elem, too. */

   if (s->ue) {
      if (!kd_add_userid_to_wordlist(&(s->ke->words),
				     s->ue->uidprint, s->ue->uidplen)) {
	 s->err->fatal = 1;
	 s->err->str = "Extending wordlist failed";
	 fail();
      }

      s->ue = NULL;
   }

   return(1);
}

static void soft_err(mke_state *s, char *message)
{
    char logbuf[1024];

    /* if s->softerr is non-NULL, then the keyblock came from the
       user, and the relevant state needs to be stashed in the softerr
       handle so it can be sent back to the user.  Otherwise, it came
       from the database, and should be logged */

    if (s->softerr) {
       s->softerr->count++;
       strncpy(s->softerr->buf, message, sizeof(s->softerr->buf));
       s->softerr->buf[sizeof(s->softerr->buf)-1] = '\0';
    }

    if (s->ke != NULL && s->ke->keyidbits.len >= 4) {
	unsigned char *ptr;

	ptr = s->ke->keyidbits.buf + (s->ke->keyidbits.len - 4);

	if (s->softerr) {
	    memcpy(&s->softerr->keyid, ptr, 4);
	    s->softerr->keyid_set = 1;
	}

	if (! s->softerr) {
	    sprintf(logbuf,
		    "internal db error: keyid 0x%02x%02x%02x%02x; reason %800s\n",
		    ptr[0], ptr[1], ptr[2], ptr[3], message);
	}
    } else {
	if (! s->softerr) {
	    sprintf(logbuf,
		    "internal db error: keyid unknown; reason %800s\n",
		    message);
	}
    }

    if (!s->softerr)
	log_info("soft_err", logbuf);
}

int finish_pubkey(mke_state *s)
{
   /* this is called when a pubkey's userid list ends.  This happens
      when a public key is seen, or at the end of the keyblock.  s->ke
      contains the current key entry, including the pubkey.  If the
      primary userid does not exist, that's an error */

   /* first, finish up the current userid */
   if (!finish_userid(s)) {
      /* error set already */
      if (s->ke != NULL)
          keys_elem_free((void *)s->ke, NULL);
      s->ke = NULL;
      return(1);
   }

   /* no prior pubkey, means this is the first.  that's ok. */
   if (!s->ke)
      return(1);

   /* if there's no primary userid, that's an error */
   if (!s->ke->primary) {
      soft_err(s,"Key block corrupt: pubkey with no userid");
      if (s->ke != NULL)
          keys_elem_free((void *)s->ke, NULL);
      s->ke = NULL;
      return(1);
   }

   if (!s->ke->keyidbits.len) {
      soft_err(s,"Key block corrupt: userid outside of pubkey");
      if (s->ke != NULL)
          keys_elem_free((void *)s->ke, NULL);
      s->ke = NULL;
      return(1);
   }
   
   /* do something useful with the key */

   if (!(*(s->iter))(s->ke, s->c))
      return(0);

   s->ke = NULL;

   return(1);
}

int make_keys_elem(ddesc *packet, void *c)
{
   long ptype, plen;
   mke_state *s = (mke_state *) c;
   
   if (!decode_psf(packet, &ptype, &plen)) {
      s->err->fatal = 0;
      s->err->str = "psf failed in make_keys_elem packet handler";
      fail();
   }

   switch (ptype) {
   case 6:
   case 14:			/* subkey packet */
      /* public key packet */
      {
	 mpidesc m, e;
	 unsigned char keyid[8];
	 unsigned char keytype;
	 time_t create_time;

	 s->ignoring = 0;

	 /* finish the prior pubkey, if any */

	 if (ptype == 6 && !finish_pubkey(s))
	    /* error message already set */
	    return(0);

	 /* allocate space for a new key_elem, fill it in */

	 if (s->ke == NULL) {
	    if ((s->ke = (keys_elem *) malloc(sizeof(keys_elem))) == NULL) {
	       s->err->fatal = 1;
	       s->err->str = "Out of memory allocating keys_elem";
	       fail();
	    }

	    keys_elem_alloc(s->ke);
	 }

	 /* extract the creation time and modulus bits from the pubkey */

	 if (!decode_pubkey(packet, plen, &m, &e, keyid,
			    &keytype, &create_time,
			    &(s->ke->keyversion))) {
            soft_err(s, "Key block corrupt: pubkey decode failed");
            s->ignoring = 1; /* Ignore until next pubkey */
	    return(1);
	 }

	 if (!xbuffer_append(&(s->ke->keyidbits), keyid, sizeof(keyid))) {
	       s->err->fatal = 1;
	       s->err->str = "Appending keyid to key failed";
	       fail();
	 }

#ifdef DBKEY_BUG
	 s->ke->create_time=create_time;
#endif

	 /* store the modulus bits, exponent bits, and pubkey packet */

	 if (ptype == 6) {			/* public key packet */
#ifndef DBKEY_BUG
	    s->ke->create_time=create_time;
#endif
	    s->ke->keytype=keytype;
	    s->ke->modsigbits = m.nbits;

	    if (!xbuffer_append(&(s->ke->pubkey), packet->data,
				packet->size)) {
	       s->err->fatal = 1;
	       s->err->str = "Appending pubkey to key failed";
	       fail();
	    }

	    /* for RSA keys, stash the data needed to compute the
	       fingerprint */
	    if (keytype == 1) {		/* RSA */
	       if (!xbuffer_append(&(s->ke->modbits),
				   m.number.data, m.number.size)) {
		  s->err->fatal = 1;
		  s->err->str = "Appending modulus bits to key failed";
		  fail();
	       }

	       if (!xbuffer_append(&(s->ke->expbits),
			           e.number.data, e.number.size)) {
	          s->err->fatal = 1;
	          s->err->str = "Appending exponent bits to key failed";
	          fail();
	       }
	    }
	 } else {				/* subkey packet */
	    if (s->ke->subkey.len) {
	      if(s->errorhack)
                soft_err(s,"Key block corrupt: more than one subkey");
	      return(1);
	    }

	    if (!xbuffer_append(&(s->ke->subkey), packet->data, packet->size)) {
	       s->err->fatal = 1;
	       s->err->str = "Appending subkey to key failed";
	       fail();
	    }
	 }

	 s->ke->disabled = 0;
      }
   break;
   case 13:
      /* userid packet */
      {
	 ddesc kpacket, userid;

	 if (s->ignoring)
	    break;

	 /* finish the prior userid, if any */
	 if (!finish_userid(s)) {
            /* error message already set */
            s->ignoring = 1;
            return(0);
         }

	 /* allocate userids_elem and fill it in */

	 if ((s->ue = (userids_elem *) malloc(sizeof(userids_elem)))
	     == NULL) {
	    s->err->fatal = 1;
	    s->err->str = "Out of memory allocating userids_elem";
	    fail();
	 }

	 userids_elem_alloc(s->ue);

	 /* store the userid packet */
	 if (!xbuffer_append(&(s->ue->uid), packet->data, packet->size)) {
	    s->err->fatal = 1;
	    s->err->str = "Appending userid to key failed";
	    fail();
	 }

	 /* extract the actual userid string */

	 kpacket.data = s->ue->uid.buf;
	 kpacket.size = s->ue->uid.len;
	 kpacket.offset = packet->offset;

	 if (!decode_userid(&kpacket, plen, &userid)) {
            soft_err(s, "Key block corrupt: userid decode failed");
            s->ignoring = 1; /* Do not put the sigs onto the wrong UID */
	    return(1);
	 }

	 s->ue->uidprint = userid.data;
	 s->ue->uidplen = userid.size;
      }
   break;
   case 2:
      /* signature packet */
      {
	 ddesc keyid;
	 long sigclass;
	 long sig_time;
	 sigs_elem *se;
	 int ret;
         static unsigned char maxid[8] = {0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff};
	 if (s->ignoring)
	    break;

	 /* extract the keyid and sigclass from the signature */

         /* if no keyid is found, take maxid */
         keyid.data = maxid;
         keyid.size = 8;
         keyid.offset = 0;

	 if (!decode_sig(packet, plen, &keyid, &sigclass, &sig_time)) {
             soft_err(s,
                      "Key block corrupt: signature decode failed");
	    return(1);
	 }

         if (s->ke == NULL) {
             /* signature on nothing */
             soft_err(s,
                      "Key block corrupt: signature without key");
             return(1);
         }

         if (sigclass == 0x20) {
	    /* key revocation signature */
	    if (s->ke->revocation.len) {
                soft_err(s,
		  "Key block corrupt: multiple revocations on single key");
	       return(1);
	    }

	    if (!xbuffer_append(&(s->ke->revocation),
				packet->data, packet->size)) {
	       s->err->fatal = 1;
	       s->err->str = "Storing revocation sig failed";
	       fail();
	    }
	 } else if (sigclass == 0x18) {
	    /* subkey signature */
	    if (s->ke->subkeysig.len) {
                soft_err(s,
		  "Key block corrupt: more than one signature on subkey");
	       return(1);
	    }

	    if (!xbuffer_append(&(s->ke->subkeysig),
				packet->data, packet->size)) {
	       s->err->fatal = 1;
	       s->err->str = "Storing subkey sig failed";
	       fail();
	    }
	 } else if (sigclass == 0x28) {
	   if(s->errorhack)
	     soft_err(s,"Key block corrupt: subkey revocation not supported");
	   return(1);
	 } else {
	    if (!s->ue) {
                soft_err(s, "Key block corrupt: signature before userid");
	       return(1);
	    }

	    /* allocate space for the signature and fill it in */
	    if ((se = (sigs_elem *) malloc(sizeof(sigs_elem))) == NULL) {
	       s->err->fatal = 1;
	       s->err->str = "Out of memory allocating sigs_elem";
	       fail();
	    }

	    sigs_elem_alloc(se);

	    if (!xbuffer_append(&(se->keyid), keyid.data, keyid.size)) {
	       s->err->fatal = 1;
	       s->err->str = "Storing keyid into sigs_elem failed";
	       free(se);
	       fail();
	    }

	    if (!xbuffer_append(&(se->sig), packet->data, packet->size)) {
	       s->err->fatal = 1;
	       s->err->str = "Storing signature into sigs_elem failed";
	       xbuffer_free(&(se->keyid));
	       free(se);
	       fail();
	    }

	    se->sig_time = sig_time;

	    /* append to the signature list */
	    if (!(ret = llist_add_sorted(&(s->ue->sigs), se,
					 sigs_elem_order))) {
	       s->err->fatal = 1;
	       s->err->str = "Adding to signature list failed";
	       sigs_elem_free(se, NULL);
	       fail();
	    }
	    if (ret == -1) {
	       llist tmp, merged_sigs;

	       llist_alloc(&tmp);
	       llist_alloc(&merged_sigs);

	       if (!llist_add(&tmp, se)) {
		  s->err->fatal = 1;
		  s->err->str = "Failed creating duplicate sigs list";
		  sigs_elem_free(se, NULL);
		  fail();
	       }

	       if (!llist_merge(&merged_sigs, &(s->ue->sigs), &tmp,
				kd_sigs_elem_merge, NULL,
				sigs_elem_free, NULL)) {
		  s->err->fatal = 1;
		  s->err->str = "Failed merging duplicate into sigs list";
		  sigs_elem_free(se, NULL);
		  fail();
	       }

	       s->ue->sigs = merged_sigs;
	    }
	 }
      }
   break;
   case 5:
      /* secret key packet -- there are actually people confused
	 enough to submit these */
      {
	 /* finish the prior pubkey, if any */

	 if (!finish_pubkey(s))
	    /* error message already set */
	    return(0);

	 s->ignoring = 1;
      }
   break;
   case 12:
      {
	 long trust;

	 /* ignore trust packets on secret keys, too. (from marcd@pgp.com) */
	 if (s->ignoring)
	    break;

	 /* only pay attention to trust packets right after the keyid,
	    and then only if the trust value is 0x20 (disabled) */
	 if (! s->ue) {
	    if (! s->ke) {
               soft_err(s,
		  "Key block corrupt: trust packet before pubkey packet");
	       return(1);
	    }

	    if (!decode_num(packet, 1, &trust)) {
	       s->err->fatal = 0;
	       s->err->str = "Key block corrupt: bad trust packet";
	       return(0);
	    }

	    s->ke->disabled = (trust & 0x20)?1:0;
	 }
      }
   break;
   case 1:
   case 8:
   case 9:
   case 11:
      /* if any of these occur, it's an error */
      {
	 char errbuf[100];

	 sprintf(errbuf,
		 "Key block corrupt: unexpected packet type %d encountered",
		 (int) ptype);
         soft_err(s, errbuf);
	 return(1);
      }
   break;
#if 0
   case 14:
      /* these should just be ignored */
      break;
#endif
   }

   return(1);
}
   
int kd_keyblock_iterate(unsigned char *block, long blocklen,
			llist_iter iter, void *c, error *err,
			ki_softerr *softerr, int errorhack)
{
   ddesc keyblock;
   mke_state mkes;

   mkes.iter = iter;
   mkes.c = c;
   mkes.ignoring = 0;
   mkes.ke = NULL;
   mkes.ue = NULL;
   mkes.err = err;
   mkes.softerr = softerr;
   mkes.errorhack = errorhack;

   keyblock.data = block;
   keyblock.size = blocklen;
   keyblock.offset = 0;

   /* initialize error condition in case decode_file fails
      internally, not in the iterator */

   err->fatal = 0;
   strcpy(err->buf, "Error decoding keyblock");

   if ((!decode_file(&keyblock, make_keys_elem, (void *) &mkes)) ||
       (!finish_pubkey(&mkes))) {
      if (mkes.ke)
	 keys_elem_free((void *) mkes.ke, NULL);
      if (mkes.ue)
	 userids_elem_free((void *) mkes.ue, NULL);

      return(0);
   }

   return(1);
}

typedef struct _aktk_state {
   llist *keys;
   error *err;
} aktk_state;   

int add_key_to_keylist(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   aktk_state *s = (aktk_state *) c;
   int ret;

   /* add the current key to key list */
   if (!(ret = llist_add_sorted(s->keys, ke, keys_elem_order))) {
      s->err->fatal = 1;
      s->err->str = "Appending keys_elem to keys failed";
      fail();
   }
   if (ret == -1) {
      llist tmp, merged_keys;

      llist_alloc(&tmp);
      llist_alloc(&merged_keys);

      if (!llist_add(&tmp, ke)) {
	 s->err->fatal = 1;
	 s->err->str = "Failed creating duplicate keys list";
	 fail();
      }

      if (!llist_merge(&merged_keys, s->keys, &tmp,
		       kd_keys_elem_merge, NULL, keys_elem_free, NULL)) {
	 s->err->fatal = 1;
	 s->err->str = "Failed merging duplicate into keys list";
	 fail();
      }

      *(s->keys) = merged_keys;
   }

   return(1);
}

int kd_get_keys_by_keyid(kd_txn tid, unsigned char *keyid,
			 llist *keys, error *err)
{
   DBT key, data;
   int ret;
   aktk_state aktks;

   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   key.data = keyid+(8-KEYDB_KEYID_BYTES);
   key.size = KEYDB_KEYID_BYTES;

   ret = (*(keydb(&key)->get))(keydb(&key), tid, &key, &data, 0);

   if ((ret == DB_NOTFOUND) ||
       ((ret == 0) && (data.size == 0))) {
      return(1);
   } else if (ret) {
      err->fatal = 1;
      sprintf(err->buf, "keydb->get returned %d", ret);
      fail();
   }

   /* key not in database */
   if (ret == 1 || (data.size == 0))
      return(1);

   /* got a keyblock from the file */

   aktks.keys = keys;
   aktks.err = err;

   if (!kd_keyblock_iterate((unsigned char *) data.data,
			    (long) data.size,
			    add_key_to_keylist, &aktks, err, NULL, 0)) {
      llist_iterate(keys, keys_elem_free, NULL);

      /* a "non-fatal" error here indicates a user err, which
	 indicates db corruption, which is fatal */
      err->fatal = 1;
      fail();
   }

   return(1);
}

typedef struct _ow1_state {
   time_t create_time;
   int is_exact;
   llist new_keys_elem;
   ow_state *ows;
} ow1_state;

void kd_make_worddb_entry(keys_elem *ke, unsigned char entry[])
{
   /* create the new entry */

   entry[0] = ke->create_time>>24;
   entry[1] = ke->create_time>>16;
   entry[2] = ke->create_time>>8;
   entry[3] = ke->create_time;
   memcpy((void *) (entry+4),
	  (void *) ke->keyidbits.buf, 8);
}

int match_userids_elem_exact(void *e, void *c)
{
   userids_elem *ue = (userids_elem *) e;
   ow1_state *s = (ow1_state *) c;

   if (my_memcasemem((void *) ue->uidprint, (void *) s->ows->userid,
		     (size_t) ue->uidplen, (size_t) s->ows->userid_len))
      s->is_exact++;

   return(1);
}

int match_keys_elem_exact(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   ow1_state *s = (ow1_state *) c;

   match_userids_elem_exact(ke->primary, c);

   if (!s->is_exact)
      llist_iterate(&(ke->userids), match_userids_elem_exact, c);

   return(1);
}

#ifdef KEYID_TRANSFORM
int v4_v3_keyid_transform(void *e, void *c)
{
  keys_elem *ke=(keys_elem *)e;
  unsigned char *wde = (unsigned char *) c;

  /* This does some magic to work around a bug in previous version of
     pksd.  The problem is that they calculated v4 RSA keyids as if
     they were v3, and stored them in the database as that.  So, in
     order to fix this, we catch cases where the actual keyid does not
     match the keyid that the database thinks we have and substitute
     what the database thinks.  Thus, key deletions work without
     leaving the database in an inconsistent state.  Eventually this
     function should be removed. - dshaw */

  if(ke->keytype==1 && ke->keyversion>3
     && (ke->keyidbits.buf[0]!=wde[0]
	 || ke->keyidbits.buf[1]!=wde[1]
	 || ke->keyidbits.buf[2]!=wde[2]
	 || ke->keyidbits.buf[3]!=wde[3]
	 || ke->keyidbits.buf[4]!=wde[4]
	 || ke->keyidbits.buf[5]!=wde[5]
	 || ke->keyidbits.buf[6]!=wde[6]
	 || ke->keyidbits.buf[7]!=wde[7]))
    {
      /* We have a mismatch between what the keyid is and what it was
	 looked up as. */

      memcpy(ke->keyidbits.buf,wde,8);
    }

  return (1);
}
#endif

int match_keys_elem(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   ow1_state *s = (ow1_state *) c;

   if (s->ows->return_disabled && (ke->disabled > 0))
      ke->disabled = -1;

   if (s->ows->userid) {
      s->is_exact = 0;
      match_keys_elem_exact(e, c);
   }

   /* for the matches, call the append function, then the filter
      function.  for the non-matches, just append to the new list.
      this function must do *something* with e, the obvious
      possibilities being chaining it onto the new list, or freeing
      it. */
   
   /* if ((!(an exact match was requested) || (an exact match was requested
					       and this is an exact match)) &&
          (any create_time is ok) || (this matches the specified create_time))
	  
	  */

   if ((!s->ows->userid || s->is_exact) &&
       ((s->create_time == 0) || (ke->create_time == s->create_time))) {
      if (s->ows->append && (!(*(s->ows->append))(e, s->ows->c)))
	 return(0);

      if (s->ows->filter) {
	 if (!(*(s->ows->filter))(e, &(s->new_keys_elem),
				  s->ows->c, s->ows->err))
	    return(0);
      } else {
	 keys_elem_free(e, NULL);
      }
   } else if (s->ows->filter) {
      if (!llist_add(&(s->new_keys_elem), e)) {
	 s->ows->err->fatal = 1;
	 s->ows->err->str =
	    "appending unprocessed key to new_keys_elem list failed";
	 fail();
      }
   } else {
      keys_elem_free(e, NULL);
   }

   return(1);
}

/* intersect by checking the heads of the two lists.  Since they are
   sorted later (larger) first, delete the head which is greater than
   the other.  If the heads are the same, keep one and delete the
   other. */

int wdes_intersect(llist *lout, void *e1, void *e2, void *c)
{
   unsigned char *wde1 = (unsigned char *) e1;
   unsigned char *wde2 = (unsigned char *) e2;
   int order;

   if (!e1) {
      malloc_elem_free(e2, NULL);
      return(LLIST_MERGE_DEL_2);
   }

   if (!e2) {
      malloc_elem_free(e1, NULL);
      return(LLIST_MERGE_DEL_1);
   }

   order = memcmp((void *) wde1, (void *) wde2, 12);

   if (order > 0) {
      malloc_elem_free(e1, NULL);
      return(LLIST_MERGE_DEL_1);
   }

   if (order < 0) {
      malloc_elem_free(e2, NULL);
      return(LLIST_MERGE_DEL_2);
   }

   /* they're the same.  keep one */

   if (!llist_add(lout, e1))
      return(LLIST_MERGE_FAIL);
   malloc_elem_free(e2, NULL);

   return(LLIST_MERGE_DEL_1 | LLIST_MERGE_DEL_2);
}

typedef struct _wki_state {
   kd_txn tid;
   int first;
   llist wdes;
   error *err;
} wki_state;

static int sort_twelvebytes(const void *a, const void *b)
{
   /* the result should be most recent first, so reverse args to memcmp */
   return(memcmp(b, a, 12));
}

int word_key_intersect(void *e, void *c)
{
   words_elem *we = (words_elem *) e;
   wki_state *s = (wki_state *) c;
   /* since no userid can be > 255, it follows that no
      word can be, either */
   int ret;
   unsigned char word[256];
   DBT key, data;
   DBC *cursor;
   llist db_wdes, merged_wdes;
   int i;
   unsigned char *wde;

   /* we've got an empty list after one word.  give up before doing
      any more work */

   if (!s->first && (llist_count(&(s->wdes)) == 0))
      return(1);

   /* a word is greater than the maximum userid size.  fail.  This shouldn't
      ever happen, since the total userid length is checked, but it makes
      analyzing the code for buffer overruns easier */

   if (we->len > sizeof(word)) {
       s->err->fatal = 0;
       sprintf(s->err->buf, "search word is greater than %d characters",
	       sizeof(word));
       return(0);
   }

   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   for (i=0; i<we->len && i < sizeof(word); i++)
      word[i] = tolower((we->ptr)[i]);

   key.data = (void *) word;
   key.size = (size_t) we->len;

   ret = (*(worddb->cursor))(worddb, s->tid, &cursor, 0);

   if (ret && ret != DB_NOTFOUND) {
      s->err->fatal = 1;
      s->err->str = "database read error creating worddb cursor";
      fail();
   }

   llist_alloc(&db_wdes);

   if (ret == 0) {
      /* create a llist of these wdes */

      for (ret = (*(cursor->c_get))(cursor, &key, &data, DB_SET);
	   ret == 0;
	   ret = (*(cursor->c_get))(cursor, &key, &data, DB_NEXT_DUP)) {
	 if ((wde = (unsigned char *) malloc(12)) == NULL) {
	    llist_iterate(&(db_wdes), malloc_elem_free, NULL);
	    llist_free(&(db_wdes));
	    (*(cursor->c_close))(cursor);
	    s->err->fatal = 1;
	    s->err->str = "allocating memory for wde failed";
	    fail();
	 }

	 memcpy(wde, (unsigned char *)data.data, 12);

	 /* they should already be sorted coming in */

	 if (!llist_add(&db_wdes, (void *) wde)) {
	    llist_iterate(&(db_wdes), malloc_elem_free, NULL);
	    llist_free(&(db_wdes));
	    (*(cursor->c_close))(cursor);
	    s->err->fatal = 1;
	    s->err->str = "failed adding keyid to db_wdes list";
	    fail();
	 }
      }

      if (ret && ret != DB_NOTFOUND) {
	 (*(cursor->c_close))(cursor);
	 s->err->fatal = 1;
	 sprintf(s->err->buf, "error reading from worddb cursor: error = %d",
		 ret);
	 fail();
      }
   } else {
      /* the word wasn't in the database, db_wdes will be empty, which
	 is correct. */
      llist_iterate(&(s->wdes), malloc_elem_free, NULL);
      llist_free(&(s->wdes));
   }

   (*(cursor->c_close))(cursor);

   /* the first time, just take the list as-is */

   if (s->first) {
      s->wdes = db_wdes;
      s->first = 0;
      return(1);
   }

   /* intersect the two lists */

   llist_alloc(&merged_wdes);

   if (!llist_merge(&merged_wdes, &db_wdes, &(s->wdes),
		    wdes_intersect, NULL,
		    malloc_elem_free, NULL)) {
      s->err->fatal = 1;
      s->err->str = "merging wdes lists failed";
      fail();
   }
	
   s->wdes = merged_wdes;

   return(1);
}

int kd_output_wde(void *e, void *c)
{
   unsigned char *wde = (unsigned char *) e;
   ow_state *s = (ow_state *) c;
   llist db_keys;
   ow1_state ow1s;
   time_t create_time;

   llist_alloc(&db_keys);

   if (!kd_get_keys_by_keyid(s->tid, wde+4, &db_keys, s->err))
      return(0);

#ifdef KEYID_TRANSFORM
   /* If the keyid we got doesn't match the keyid we looked up, check
      if the key is v4 rsa.  if it is, change the keyid internally to
      the old bogus one */
   if (!llist_iterate(&db_keys, v4_v3_keyid_transform, wde+4))
      return(0);
#endif

   create_time = ((wde[0]<<24)+(wde[1]<<16)+(wde[2]<<8)+(wde[3]));

   if (!llist_count(&db_keys)) {
      if (create_time) {
	 char buf[1024];

	 sprintf(buf,
		 "consistency error: key id %02X%02X%02X%02X not found "
		 "in database", 
		 wde[8], wde[9], wde[10], wde[11]);
	 log_error("kd_output_wde", buf);
	 return(1);
      } else {
	 s->err->fatal = 0;
	 s->err->str = "No matching keys in database";
	 return(0);
      }
   }

   ow1s.create_time = create_time;
   ow1s.ows = s;

   if (s->filter)
       llist_alloc(&(ow1s.new_keys_elem));

   if (!llist_iterate(&db_keys, match_keys_elem, &ow1s))
      return(0);

   llist_free(&db_keys);

   if (s->filter) {
      if (llist_count(&(ow1s.new_keys_elem))) {
	 if (!kd_db_store_keyblock(s->tid, &(ow1s.new_keys_elem), s->err))
	    return(0);

	 llist_iterate(&(ow1s.new_keys_elem), keys_elem_free, NULL);
	 llist_free(&(ow1s.new_keys_elem));
      } else {
	 DBT key;

	 memset(&key, 0, sizeof(key));

	 key.data = wde+4 + (8-KEYDB_KEYID_BYTES);
	 key.size = KEYDB_KEYID_BYTES;

	 if ((*(keydb(&key)->del))(keydb(&key), s->tid, &key, 0)) {
	    s->err->fatal = 1;
	    s->err->str = "failed deleting keydb entry from database";
	    fail();
	 }
      }
   }

   return(1);
}

typedef struct _akte_state {
   xbuffer entries;
   error *err;
} akte_state;

int add_key_to_entrylist(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   akte_state *s = (akte_state *) c;
   unsigned char entry[12];

   kd_make_worddb_entry(ke, entry);

   if (!xbuffer_append(&(s->entries), entry, sizeof(entry))) {
      s->err->fatal = 1;
      s->err->str = "failed allocating memory for global entry list";
      fail();
   }

   keys_elem_free(ke, NULL);

   return(1);
}

typedef struct _ftf_state {
   llist_iter func;
   void *state;
} ftf_state;

int func_then_free(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   ftf_state *s = (ftf_state *) c;

   if (!((*(s->func))(e, s->state)))
      return(0);

   keys_elem_free(ke, NULL);

   return(1);
}

int do_all_keys(kd_txn tid, int flags, llist_iter func, void *c, error *err)
{
   akte_state aktes;
   int ret, i;
   DBC *cursor;
   DBT key, data;
   ow_state ows;
   ftf_state ftfs;
   
   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   xbuffer_alloc(&(aktes.entries));
   aktes.err = err;

   ftfs.func = func;
   ftfs.state = c;

   for (i=0; i<num_keydb; i++) {
      if ((ret = (*(keydb_files[i]->cursor))(keydb_files[i], tid, &cursor,
					     0))) {
	 err->fatal = 1;
	 sprintf(err->buf, "error creating keydb[%d] cursor: error = %d",
		 i, ret);
	 fail();
      }

      for (ret = (*(cursor->c_get))(cursor, &key, &data, DB_FIRST);
	   ret == 0;
	   ret = (*(cursor->c_get))(cursor, &key, &data, DB_NEXT)) {
	 if (flags & KD_SEARCH_STDOUT) {
	    /* just iterate the database calling the iterator function.
	       don't bother collecting id's or sorting */
	    if (kd_keyblock_iterate((unsigned char *) data.data,
				    (long) data.size,
				    func_then_free, &ftfs, err, NULL, 0))
	       continue;
	 } else {
	    if (kd_keyblock_iterate((unsigned char *) data.data,
				    (long) data.size,
				    add_key_to_entrylist, &aktes, err, NULL,0))
	       continue;
	 }

	 /* if the loop gets here, there was an error in the iteration. */

	 if ((flags & KD_SEARCH_IGNORE_ERRORS) && (err->fatal == 0)) {
	    char buf[1024];

	    sprintf(buf, "ignoring error in kd_keyblock_iterate, "
		    "keyid %02X%02X%02X%02X: %s",
		    ((unsigned char *) key.data)[0],
		    ((unsigned char *) key.data)[1],
		    ((unsigned char *) key.data)[2],
		    ((unsigned char *) key.data)[3],
		    err->str);

	    log_error("do_all_keys", buf);
	 } else {
	    xbuffer_free(&(aktes.entries));
	    (*(cursor->c_close))(cursor);

	    /* a "non-fatal" error here indicates a user err, which
	       indicates db corruption, which is fatal */
	    err->fatal = 1;
	    fail();
	 }
      }

      (*(cursor->c_close))(cursor);

      if (ret != DB_NOTFOUND) {
	 err->fatal = 1;
	 sprintf(err->buf, "error iterating keydb[%d]: error = %d", i, ret);
	 fail();
      }
   }

   if (!(flags & KD_SEARCH_STDOUT)) {
      if (aktes.entries.len == 0) {
	 /* the database is empty */

	 err->fatal = 0;
	 err->str = "The database is empty";
	 return(0);
      }

      qsort(aktes.entries.buf, (size_t) (aktes.entries.len/12), 12, 
	    sort_twelvebytes);

      ows.tid = tid;
      ows.userid = NULL;
      ows.userid_len = 0;
      ows.filter = NULL;
      ows.return_disabled = (flags & KD_SEARCH_RETURN_DISABLED)?1:0;
      ows.c = c;
      ows.err = err;
      ows.append = func;

      for (i=0; i<aktes.entries.len; i+=12)
	 if (!kd_output_wde((void *) (aktes.entries.buf+i), (void *) &ows))
	    return(0);
   }

   xbuffer_free(&(aktes.entries));

   return(1);
}

/* 
   1) generate a list of words from the userid 
   2) for each word, look up the keyid's associated with it
   3)    intersect-merge the keyid lists
   4) for each keyid in the resulting list
   5)    look up the matching keys
   6)    process each key into the output xbuffer

   */

int do_by_userid(kd_txn tid, unsigned char *userid, long len, int flags,
		 int maxkeys, llist_iter func, search_llist_filter filt,
		 void *c, error *err)
{
   llist words;
   wki_state wkis;
   ow_state ows;
   int key_count;

   llist_alloc(&words);

   /* if the search userid is longer than any valid userid, fail. */
   if (len > 255) {
       err->fatal = 0;
       err->str = "search userid may not be longer than 255 characters";
       return(0);
   }

   /* generate the word list */

   if (!kd_add_userid_to_wordlist(&words, userid, len)) {
      err->fatal = 1;
      err->str = "adding userid search words to word list failed";
      fail();
   }

   /* if there aren't any words, fail */

   if (llist_count(&words) == 0) {
      err->fatal = 0;
      err->str = "search userid did not contain any words";
      return(0);
   }

   wkis.tid = tid;
   wkis.first = 1;
   llist_alloc(&(wkis.wdes));
   wkis.err = err;

   /* this is a default error */

   err->fatal = 1;
   strcpy(err->buf, "internal error intersecting word lists");

   /* from that, generate the keyid list */

   if (!llist_iterate(&words, word_key_intersect, &wkis))
      return(0);

   /* if there aren't any keyids, fail */

   key_count = llist_count(&(wkis.wdes));

   if (key_count == 0) {
      /* this can happen a lot */

      llist_iterate(&(wkis.wdes), malloc_elem_free, NULL);
      llist_free(&(wkis.wdes));
      llist_iterate(&words, malloc_elem_free, NULL);
      llist_free(&words);

      err->fatal = 0;
      err->str = "No matching keys in database";
      return(0);
   } else if ((maxkeys >= 0) &&
	      (key_count > maxkeys)) {
      llist_iterate(&(wkis.wdes), malloc_elem_free, NULL);
      llist_free(&(wkis.wdes));
      llist_iterate(&words, malloc_elem_free, NULL);
      llist_free(&words);

      err->fatal = 0;
      sprintf(err->buf,"Number of keys in reply (%d) exceeded maximum "
	      "allowed (%d)\nTry a more specific query.\n",
	      key_count, maxkeys);
      return(0);
   }

   /* lastly, generate a key list */

   /* this is a default error */

   err->fatal = 1;
   strcpy(err->buf, "internal error generating key list");

   ows.tid = tid;
   if (flags & KD_SEARCH_EXACT) {
      ows.userid = userid;
      ows.userid_len = len;
   } else {
      ows.userid = NULL;
      ows.userid_len = 0;
   }
   ows.filter = filt;
   ows.return_disabled = (flags & KD_SEARCH_RETURN_DISABLED)?1:0;
   ows.c = c;
   ows.err = err;
   ows.append = func;

   if (!llist_iterate(&(wkis.wdes), kd_output_wde, &ows)) {
      llist_iterate(&(wkis.wdes), malloc_elem_free, NULL);
      llist_free(&(wkis.wdes));
      llist_iterate(&words, malloc_elem_free, NULL);
      llist_free(&words);
      
      return(0);
   }

   llist_iterate(&(wkis.wdes), malloc_elem_free, NULL);
   llist_free(&(wkis.wdes));
   llist_iterate(&words, malloc_elem_free, NULL);
   llist_free(&words);

   return(1);
}

int parse_keyidstr(unsigned char *keyidstr, long len,
		   unsigned char keyid[8], error *err)
{
   int i, digit;

   /* Note the 32-character v3 fingerprint is not included here as it
      is not possible to calculate a long or short keyid from it. -ds */

   if (len != KEYDB_KEYID_BYTES*2 &&
       len != KEYDB_KEYID_BYTES*4 &&
       len != 40) {
      err->fatal = 0;
      sprintf(err->buf,"Key ID string should be %d, %d, or 40 characters long",
	      KEYDB_KEYID_BYTES*2,KEYDB_KEYID_BYTES*4);
      return(0);
   }

   /* If it is too big, shrink to the short 8-digit keyid.  This will
      give a graceful transition to a future version that can handle
      16-digit or full fingerprint keyids. -ds */

   while(len>KEYDB_KEYID_BYTES*2)
     {
       keyidstr++;
       len--;
     }

   for (i=0; i<8; i++)
      keyid[i] = 0;

   for (i=0; i<len; i++) {
      if (!isxdigit(keyidstr[i])) {
	 err->fatal = 0;
	 err->str = "Key ID must contain only hexadecimal digits";
	 return(0);
      }

      if (isdigit(keyidstr[i]))
	 digit = keyidstr[i]-'0';
      else if (isupper(keyidstr[i]))
	 digit = keyidstr[i]-'A'+10;
      else /* if (islower(keyidstr[i])) */
	 digit = keyidstr[i]-'a'+10;

      if (i%2 == 0)
	 keyid[8-len/2+(i/2)] |= digit<<4;
      else
	 keyid[8-len/2+(i/2)] |= digit;
   }

   return(1);
}

int kd_search_1(kd_txn tid, unsigned char *userid, long len, int flags,
		int maxkeys, llist_iter func, search_llist_filter filt,
		void *c, error *err)
{
   if (flags & KD_SEARCH_ALL)
      return(do_all_keys(tid, flags, func, c, err));

   /* skip over initial whitespace */

   while(len && isspace(*userid)) {
      len--;
      userid++;
   }

   if (len < 2) {
      err->fatal = 0;
      err->str = "Userid must be at least two characters long";
      return(0);
   }

   /* get a keyblock, by keyid or word list as appropriate */

   if ((userid[0] == '0') && (userid[1] == 'x')) {
      unsigned char wde[12];
      ow_state ows;

      if (!parse_keyidstr(userid+2, len-2, wde+4, err))
	 return(0);

      wde[0] = 0;
      wde[1] = 0;
      wde[2] = 0;
      wde[3] = 0;

      err->fatal = 1;
      strcpy(err->buf, "internal error generating key list");

      ows.tid = tid;
      ows.userid = NULL;
      ows.userid_len = 0;
      ows.filter = filt;
      ows.return_disabled = (flags & KD_SEARCH_RETURN_DISABLED)?1:0;
      ows.c = c;
      ows.err = err;
      ows.append = func;

      if (!kd_output_wde((void *) &wde, (void *) &ows))
	 return(0);

      return(1);
   } else {
      if (!do_by_userid(tid, userid, len, flags, maxkeys, func, filt, c, err))
	 return(0);
   }

   return(1);
}

