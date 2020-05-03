const char rcsid_kd_add_c[] = "$Id: kd_add.c,v 1.7 2003/01/25 16:32:02 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <db.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <string.h>

#include "armor.h"
#include "pgputil.h"
#include "database.h"
#include "globals.h"
#include "llist.h"
#include "kd_types.h"
#include "kd_internal.h"
#include "kd_search.h"
#include "util.h"

/* for all of these, the first element will come from the database,
   the second from the request */

typedef struct _merge_state {
   /* statistics */
   int new_sigs;
   int repl_sigs;
   int new_userids;
   int changed_primary_userids;
   int new_revocations;
   int new_pubkeys;
   int not_changed_revocation_sig;
   /* added stuff */
   int save_add;
   llist add_keys;
   llist add_userids;
   llist add_sigs;
   xbuffer *add_xb;
   /* verbose printing state */
   int verbose;
   keys_elem *this_ke;
   unsigned char *this_userid;
   int this_userid_len;
} merge_state;

typedef struct _dkm_state {
   merge_state ms;
   int no_strip_disabled;
   error *err;
} dkm_state;

typedef struct _dkm1_state {
   kd_txn tid;
   dkm_state *dkms;
} dkm1_state;

int words_elem_merge(llist *lout, void *e1, void *e2, void *c)
{
   int o;

   if (!e1) {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_2);
   }

   if (!e2) {
      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_1);
   }

   o = words_elem_order(e1, e2);

   /* if the word from the database is less than the word
      from the request, go on to the next database word */

   if (o < 0) {
      malloc_elem_free(e1, NULL);
      return(LLIST_MERGE_DEL_1);
   }

   /* if the word is already in the database version, then the word
      is already in the word table, and isn't needed */

   if (o == 0) {
      malloc_elem_free(e1, NULL);
      malloc_elem_free(e2, NULL);
      return(LLIST_MERGE_DEL_1 | LLIST_MERGE_DEL_2);
   }

   /* otherwise, if the word from the request is less than the word
      from the database, then keep it: put it in the output list and
      delete it from the input list */

   if (!llist_add(lout, e2)) {
      dabort();
      return(LLIST_MERGE_FAIL);
   }

   return(LLIST_MERGE_DEL_2);
}

void display_new_sig(merge_state *s, xbuffer *xb)
{
   char buf[1024];

   sprintf(buf,
	   "new sig %d by %02X%02X%02X%02X added to %02X%02X%02X%02X %.*s%s",
	   s->new_sigs,
	   xb->buf[xb->len-4],
	   xb->buf[xb->len-3],
	   xb->buf[xb->len-2],
	   xb->buf[xb->len-1],
	   s->this_ke->keyidbits.buf[4],
	   s->this_ke->keyidbits.buf[5],
	   s->this_ke->keyidbits.buf[6],
	   s->this_ke->keyidbits.buf[7],
	   ((s->this_userid_len<=30)?(int) s->this_userid_len:30),
	   s->this_userid,
	   (s->this_userid_len<=30)?"":"...");
   log_debug("display_new_sig", buf);
}

void display_repl_sig(merge_state *s, xbuffer *xb)
{
   char buf[1024];

   sprintf(buf,
	   "newer sig %d by %02X%02X%02X%02X "
	   "replaced old on %02X%02X%02X%02X %.*s%s",
	   s->repl_sigs,
	   xb->buf[xb->len-4],
	   xb->buf[xb->len-3],
	   xb->buf[xb->len-2],
	   xb->buf[xb->len-1],
	   s->this_ke->keyidbits.buf[4],
	   s->this_ke->keyidbits.buf[5],
	   s->this_ke->keyidbits.buf[6],
	   s->this_ke->keyidbits.buf[7],
	   ((s->this_userid_len<=30)?(int) s->this_userid_len:30),
	   s->this_userid,
	   (s->this_userid_len<=30)?"":"...");
   log_debug("display_repl_sig", buf);
}

/* this function has the potential problem that if there are two keys
   out there with the same keyid, if both of them have signatures,
   they are indistinguishable without access to the public keys.  Even
   then, the only way to tell is to attempt to verify the signature
   with each public key to see if that is, in fact, the correct public
   key.  And even then, you can't ever decide that a signature is
   invalid, because you could just be missing the public key.  This
   seems to be a fundamental flaw in the keyring packet formats. */

int kd_sigs_elem_merge(llist *lout, void *e1, void *e2, void *c)
{
   sigs_elem *se1 = (sigs_elem *) e1;
   sigs_elem *se2 = (sigs_elem *) e2;
   merge_state *s = (merge_state *) c;
   int o;

   if (!e1) {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (s) {
	 s->new_sigs++;

	 /* store pointer to added packets */

	 if (s->save_add) {
	    if (!llist_add(&(s->add_sigs), e2)) {
	       dabort();
	       return(LLIST_MERGE_FAIL);
	    }
	 }
	 if (s->verbose)
	    display_new_sig(s, &(se2->keyid));
      }
      return(LLIST_MERGE_DEL_2);
   }

   if (!e2) {
      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_1);
   }

   o = sigs_elem_order(e1, e2);

   /* if the sig keyids are different, move the smaller keyid
      to the output list */

   if (o < 0) {
      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_1);
   }

   if (o > 0) {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (s) {
	 s->new_sigs++;

	 /* store pointer to added packets */

	 if (s->save_add) {
	    if (!llist_add(&(s->add_sigs), e2)) {
	       dabort();
	       return(LLIST_MERGE_FAIL);
	    }
	 }
	 if (s->verbose)
	    display_new_sig(s, &(se2->keyid));
      }
      return(LLIST_MERGE_DEL_2);
   }

   /* if the sig keyids are the same, move the more recent signature
      to the output list and delete the less recent.  If they are
      the same, take the database sig so the stats work out right */

   if (se1->sig_time >= se2->sig_time) {
      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      sigs_elem_free(se2, NULL);
   } else {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (s) {
	 s->repl_sigs++;

	 /* store pointer to added packets */

	 if (s->save_add) {
	    if (!llist_add(&(s->add_sigs), e2)) {
	       dabort();
	       return(LLIST_MERGE_FAIL);
	    }
	 }
	 if (s->verbose)
	    display_repl_sig(s, &(se2->keyid));
      }
      sigs_elem_free(se1, NULL);
   }

   return(LLIST_MERGE_DEL_1 | LLIST_MERGE_DEL_2);
}

void display_new_userid(merge_state *s, userids_elem *ue)
{
   char buf[1024];

   sprintf(buf,
	   "new userid %d on keyid %02X%02X%02X%02X: %.*s%s",
	   s->new_userids,
	   s->this_ke->keyidbits.buf[4],
	   s->this_ke->keyidbits.buf[5],
	   s->this_ke->keyidbits.buf[6],
	   s->this_ke->keyidbits.buf[7],
	   ((ue->uidplen<=40)?(int) ue->uidplen:40),
	   ue->uidprint,
	   (ue->uidplen<=40)?"":"...");
   log_debug("display_new_userid", buf);
}

/* this takes into account that the possibly new primary userid
   (s->this_ke->primary) might appear in the database userid list
   (e1).  If it's there, then the database userid (e1) should be
   merged into the primary userid (s->this_ke->primary), not added to
   the new userid list (e2) */

int kd_userids_elem_merge(llist *lout, void *e1, void *e2, void *c)
{
   userids_elem *ue1 = (userids_elem *) e1;
   userids_elem *ue2 = (userids_elem *) e2;
   merge_state *s = (merge_state *) c;
   llist merged_sigs;
   int o;

   if (!e1) {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (s) {
	 s->new_userids++;

	 /* store pointer to added packets */

	 if (s->save_add) {
	    userids_elem *ue;

	    if (((ue = (userids_elem *) malloc(sizeof(userids_elem)))
		 == NULL) ||
		((ue->uid = ue2->uid),
		 (llist_alloc(&(ue->sigs))),
		 (!llist_copy(&(ue->sigs), &(ue2->sigs)))) ||
		(!llist_add(&(s->add_userids), ue))) {
	       dabort();
	       return(LLIST_MERGE_FAIL);
	    }
	 }
	 if (s->verbose)
	    display_new_userid(s, ue2);
      }
      return(LLIST_MERGE_DEL_2);
   } else if (s && (userids_elem_order(e1, s->this_ke->primary) == 0)) {
      ue2 = s->this_ke->primary;
      e2 = (void *) ue2;

      /* If this happens, that means that the new primary was present in the
	 database's userid list, and it's not really a new userid at all.
	 Therefore, *subtract* one from the new userid count, and call
	 it a changed primary userid instead. */

      s->new_userids--;
      s->changed_primary_userids++;
   } else if (!e2) {
      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_1);
   }

   o = userids_elem_order(e1, e2);

   /* if the userid's are different, then move the lesser uid
      to the output list */

   if (o < 0) {
      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_1);
   }

   if (o > 0) {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (s) {
	 s->new_userids++;	

	 /* store pointer to added packets */

	 if (s->save_add) {
	    userids_elem *ue;

	    if (((ue = (userids_elem *) malloc(sizeof(userids_elem)))
		 == NULL) ||
		((ue->uid = ue2->uid),
		 (llist_alloc(&(ue->sigs))),
		 (!llist_copy(&(ue->sigs), &(ue2->sigs)))) ||
		(!llist_add(&(s->add_userids), ue))) {
	       dabort();
	       return(LLIST_MERGE_FAIL);
	    }
	 }
	 if (s->verbose)
	    display_new_userid(s, ue2);
      }
      return(LLIST_MERGE_DEL_2);
   }

   if (s && s->verbose) {
      s->this_userid = ue2->uidprint;
      s->this_userid_len = ue2->uidplen;
   }

   /* if the userids are the same, merge the sigs from the database
      into the userid list from the request */

   llist_alloc(&merged_sigs);
   
   if (!llist_merge(&merged_sigs, &(ue1->sigs), &(ue2->sigs),
		    kd_sigs_elem_merge, c, sigs_elem_free, NULL)) {
      dabort();
      return(LLIST_MERGE_FAIL);
   }

   ue2->sigs = merged_sigs;

   /* store pointer to added packets */

   if (s && s->save_add && llist_count(&(s->add_sigs))) {
      userids_elem *ue;

      if (((ue = (userids_elem *) malloc(sizeof(userids_elem)))
	   == NULL) ||
	  ((ue->uid = ue2->uid),
	   (llist_alloc(&(ue->sigs))),
	   (!llist_copy(&(ue->sigs), &(s->add_sigs)))) ||
	  (!llist_add(&(s->add_userids), ue))) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      llist_free(&(s->add_sigs));
   }

   /* if this was a merge into the primary userid, don't add it to
      any lists, and don't delete whatever was in e2 */

   if (s && (ue2 == s->this_ke->primary)) {
      userids_elem_free(ue1, NULL);
      return(LLIST_MERGE_DEL_1);
   }
   
   /* move this new userid list into the output list, and delete
      the other input */

   if (!llist_add(lout, e2)) {
      dabort();
      return(LLIST_MERGE_FAIL);
   }
   userids_elem_free(ue1, NULL);

   return(LLIST_MERGE_DEL_1 | LLIST_MERGE_DEL_2);
}

void display_new_revocation(merge_state *s, xbuffer *xb)
{
   char buf[1024];

   /* there doesn't seem to be an aesthetic place to put a count
      of new revocations, but that doesn't seem to be a big deal
      to me */

   sprintf(buf,
	   "keyid %02X%02X%02X%02X revoked",
	   xb->buf[4],
	   xb->buf[5],
	   xb->buf[6],
	   xb->buf[7]);
   log_debug("display_new_revocation", buf);
}

void display_new_key(merge_state *s, xbuffer *xb)
{
   char buf[1024];

   sprintf(buf,
	   "new keyid %d %02X%02X%02X%02X",
	   s->new_pubkeys,
	   xb->buf[4],
	   xb->buf[5],
	   xb->buf[6],
	   xb->buf[7]);
   log_debug("display_new_key", buf);
}

int kd_keys_elem_merge(llist *lout, void *e1, void *e2, void *c)
{
   keys_elem *ke1 = (keys_elem *) e1;
   keys_elem *ke2 = (keys_elem *) e2;
   merge_state *s = (merge_state *) c;
   llist merged_sigs, merged_userids, merged_words;
   int new_revocation = 0, new_primary = 0;
   
   int o;

   if (!e1) {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (s) {
	 s->new_pubkeys++;

	 /* store pointer to added packets */

	 if (s->save_add) {
	    keys_elem *ke;

	    if (((ke = (keys_elem *) malloc(sizeof(keys_elem)))
		 == NULL) ||
		((ke->primary = (userids_elem *) malloc(sizeof(userids_elem)))
		 == NULL) ||
		((ke->pubkey = ke2->pubkey),
		 (ke->revocation = ke2->revocation),
		 (ke->disabled = ke2->disabled),
		 (ke->primary->uid = ke2->primary->uid),
		 (ke->subkey = ke2->subkey),
		 (ke->subkeysig = ke2->subkeysig),
		 (llist_alloc(&(ke->primary->sigs))),
		 (!llist_copy(&(ke->primary->sigs), &(ke2->primary->sigs)))) ||
		((llist_alloc(&(ke->userids))),
		 (!llist_copy(&(ke->userids), &(ke2->userids)))) ||
		(!llist_add(&(s->add_keys), ke))) {
	       dabort();
	       return(LLIST_MERGE_FAIL);
	    }
	 }
	 if (s->verbose)
	    display_new_key(s, &(ke2->keyidbits));
      }
      return(LLIST_MERGE_DEL_2);
   }

   if (!e2) {
      /* zero out the wordlist from a db key, it's already
	 in the database */
      llist_iterate(&(ke1->words), malloc_elem_free, NULL);
      llist_free(&(ke1->words));
      llist_alloc(&(ke1->words));

      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_1);
   }

   o = keys_elem_order(e1, e2);

   /* if the moduli are different, then move the lesser modulus
      to the output list */

   if (o < 0) {
      /* zero out the wordlist from a db key, it's already
	 in the database */
      llist_iterate(&(ke1->words), malloc_elem_free, NULL);
      llist_free(&(ke1->words));
      llist_alloc(&(ke1->words));

      if (!llist_add(lout, e1)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      return(LLIST_MERGE_DEL_1);
   }

   if (o > 0) {
      if (!llist_add(lout, e2)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (s) {
	 s->new_pubkeys++;

	 /* store pointer to added packets */

	 if (s->save_add) {
	    keys_elem *ke;

	    if (((ke = (keys_elem *) malloc(sizeof(keys_elem)))
		 == NULL) ||
		((ke->primary = (userids_elem *) malloc(sizeof(userids_elem)))
		 == NULL) ||
		((ke->pubkey = ke2->pubkey),
		 (ke->revocation = ke2->revocation),
		 (ke->disabled = ke2->disabled),
		 (ke->primary->uid = ke2->primary->uid),
		 (ke->subkey = ke2->subkey),
		 (ke->subkeysig = ke2->subkeysig),
		 (llist_alloc(&(ke->primary->sigs))),
		 (!llist_copy(&(ke->primary->sigs), &(ke2->primary->sigs)))) ||
		((llist_alloc(&(ke->userids))),
		 (!llist_copy(&(ke->userids), &(ke2->userids)))) ||
		(!llist_add(&(s->add_keys), ke))) {
	       dabort();
	       return(LLIST_MERGE_FAIL);
	    }
	 }
	 if (s->verbose)
	    display_new_key(s, &(ke2->keyidbits));
      }
      return(LLIST_MERGE_DEL_2);
   }

   /* if the moduli are the same... */

   /* if the new key has the disabled bit set, keep it */

   if (!ke1->disabled && ke2->disabled)
      ke1->disabled = ke2->disabled;

   /* if the revocation signatures are different, keep the old one, take
      note, and keep going. */

   if (ke1->revocation.len && ke2->revocation.len &&
       (bytestr_order(ke1->revocation.buf, ke1->revocation.len,
		      ke2->revocation.buf, ke2->revocation.len) != 0)) {
      char buf[80];
      
      sprintf(buf, "changed revocation on keyid 0x%02X%02X%02X%02X ignored",
	      ke2->keyidbits.buf[4], ke2->keyidbits.buf[5],
	      ke2->keyidbits.buf[6], ke2->keyidbits.buf[7]);
      log_info("kd_keys_elem_merge", buf);

      if (s)
	 s->not_changed_revocation_sig++;
      /*
       * Go on with the keyring, but delete the new revocation
       * so it will not be accounted for below (avoids incremental loops)
       */
      xbuffer_free(&(ke2->revocation));
/*
      ke2->revocation = ke1->revocation;
      xbuffer_alloc(&(ke1->revocation));
*/
   }

   if (s)
      s->this_ke = ke2;

   /* keep a new revocation */

   if ((ke1->revocation.len == 0) && (ke2->revocation.len != 0)) {
      if (s) {
	 s->new_revocations++;
	 if (s->save_add)
	    new_revocation++;
	 if (s->verbose)
	    display_new_revocation(s, &(ke2->keyidbits));
      }
   }

   if ((ke2->revocation.len == 0) && (ke1->revocation.len != 0)) {
      ke2->revocation = ke1->revocation;
      xbuffer_alloc(&(ke1->revocation));
   }

   /* merge the word lists.  this would be more logical, I think, done
      after userid merging, except that the word lists point into the
      userids, so if those are freed first, we end up reading freed
      memory */

   llist_alloc(&merged_words);
   
   if (!llist_merge(&merged_words, &(ke1->words), &(ke2->words),
		    words_elem_merge, c, malloc_elem_free, NULL)) {
      dabort();
      return(LLIST_MERGE_FAIL);
   }

   ke2->words = merged_words;

   /* if the primary userids are different, keep the new one,
      and add the old one to the old userid list */

   if (userids_elem_order(ke1->primary, ke2->primary) != 0) {
      int ret;

      if (!(ret = llist_add_sorted(&(ke1->userids), ke1->primary,
				   userids_elem_order))) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }
      if (ret == -1) {
	 /* in the database, duplicate userids should already have been
	    merged together, making this an error */
	 userids_elem_free(ke1->primary, NULL);
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }

      ke1->primary = NULL;

      if (s) {
	 s->new_userids++;
	 if (s->save_add)
	    new_primary++;
      }
   }

   /* merge the userid lists */

   llist_alloc(&merged_userids);
   
   if (!llist_merge(&merged_userids, &(ke1->userids), &(ke2->userids),
		    kd_userids_elem_merge, c, userids_elem_free, NULL)) {
      dabort();
      return(LLIST_MERGE_FAIL);
   }

   ke2->userids = merged_userids;

   /* merge the primary uid sig lists */

   if (s && s->verbose) {
      s->this_userid = ke2->primary->uidprint;
      s->this_userid_len = ke2->primary->uidplen;
   }

   if (ke1->primary) {
      llist_alloc(&merged_sigs);
   
      if (!llist_merge(&merged_sigs, &(ke1->primary->sigs),
		       &(ke2->primary->sigs),
		       kd_sigs_elem_merge, c, sigs_elem_free, NULL)) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }

      ke2->primary->sigs = merged_sigs;
   }

   /* move this new keys_elem into the output list, and delete
      the other input */

   if (!llist_add(lout, e2)) {
      dabort();
      return(LLIST_MERGE_FAIL);
   }
   keys_elem_free(ke1, NULL);

   /* store pointer to added packets */

   if (s && s->save_add &&
       (new_revocation || new_primary ||
	llist_count(&(s->add_userids)) || llist_count(&(s->add_sigs)))) {
      keys_elem *ke;

      if (((ke = (keys_elem *) malloc(sizeof(keys_elem))) == NULL) ||
	  ((ke->primary = (userids_elem *) malloc(sizeof(userids_elem)))
	   == NULL) ||
	  ((ke->pubkey = ke2->pubkey),
	   (xbuffer_alloc(&(ke->revocation))),
	   (new_revocation && ((ke->revocation = ke2->revocation), 1)),
	   (ke->primary->uid = ke2->primary->uid),
	   (llist_alloc(&(ke->primary->sigs))),
	   (!llist_copy(&(ke->primary->sigs), &(s->add_sigs)))) ||
	  ((llist_alloc(&(ke->userids))),
	   (!llist_copy(&(ke->userids), &(s->add_userids)))) ||

	  ((ke->subkey = ke2->subkey),
	   (ke->subkeysig = ke2->subkeysig),
	   (ke->disabled= 0),
	   !llist_add(&(s->add_keys), ke))) {
	 dabort();
	 return(LLIST_MERGE_FAIL);
      }

      llist_free(&(s->add_userids));
      llist_free(&(s->add_sigs));
   }

   return(LLIST_MERGE_DEL_1 | LLIST_MERGE_DEL_2);
}

int add_userids_elem_free(void *e, void *c)
{
   userids_elem *ue = (userids_elem *) e;

   llist_free(&(ue->sigs));
   malloc_elem_free(e, c);

   return(1);
}

int add_keys_elem_free(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;

   if (ke->primary)
      add_userids_elem_free(ke->primary, c);

   llist_iterate(&(ke->userids), add_userids_elem_free, c);
   llist_free(&(ke->userids));
   malloc_elem_free(e, c);

   return(1);
}

typedef struct _aetd_state {
   kd_txn tid;
   unsigned char entry[12];
   int writing;
   int pks_errno;
} aetd_state;

int add_entry_to_db(DB *db, DBT *key, aetd_state *s)
{
   int ret;
   int needfree = 0;
   DBT data, newdata;

   memset(&data, 0, sizeof(data));
   memset(&newdata, 0, sizeof(newdata));

   ret = (*(db->get))(db, s->tid, key, &data, 0);

   if (ret == DB_NOTFOUND) {
      /* word not in file, create DBT for insert */

      newdata.size = 12*KEYDB_MIN_ALLOC;
      if ((newdata.data = (void *) malloc(newdata.size)) == NULL)
	 fail();
	 
      needfree = 1;
      memcpy(newdata.data, s->entry, 12);
      if (newdata.size > 12)
	 memset(((unsigned char *) newdata.data)+12, 0, newdata.size-12);
   } else if (ret) {
      s->writing = 0;
      s->pks_errno = ret;
      fail();
   } else {
      int i, o;

      if (data.size%12)
	 fail();

      /* allocate data to store */

      /* scan for insertion point.  This is O(n), but so is the
	 copy which follows it */

      for (KD_FIRST_ENTRY(i); KD_LAST_ENTRY(i, data); KD_NEXT_ENTRY(i)) {
	 o = memcmp((void *) (((unsigned char *) data.data)+i),
		    (void *) s->entry, 12);
	 if (o < 0)
	    break;

	 if (o == 0) {
	    /* no duplicates */
	    return(1);
	 }
      }

      if (memcmp((((unsigned char *) data.data)+(data.size-12)), zeros, 12)
	  == 0) {
	 /* move data after insertion point and insert */
	 memmove((void *) (((unsigned char *) data.data)+i+12),
		 (void *) (((unsigned char *) data.data)+i),
		 data.size - (i+12));
	 memcpy((void *) (((unsigned char *) data.data)+i),
		(void *) s->entry, 12);

	 newdata = data;
      } else {
	 if (data.size < KEYDB_MAX_ALLOC)
	    newdata.size = data.size*2;
	 else
	    newdata.size = data.size+(12*KEYDB_MAX_ALLOC);

	 if ((newdata.data = (void *) malloc(newdata.size)) == NULL)
	    fail();
	 needfree = 1;

	 /* copy data to newdata, inserting entry */
	 memcpy(newdata.data, data.data, i);
	 memcpy((void *) (((unsigned char *) newdata.data)+i),
		(void *) s->entry, 12);
	 memcpy((void *) (((unsigned char *) newdata.data)+(i+12)),
		(void *) (((unsigned char *) data.data)+i),
		data.size - i);
	 memset((void *) (((unsigned char *) newdata.data)+(data.size+12)),
		0, newdata.size - (data.size+12));
      }
   }

   if ((ret = (*(db->put))(db, s->tid, key, &newdata, 0))) {
      s->writing = 1;
      s->pks_errno = ret;
      if (needfree)
	 free(newdata.data);
      fail();
   }

   if (needfree)
      free(newdata.data);

   return(1);
}

int add_word_to_worddb(void *e, void *c)
{
   words_elem *we = (words_elem *) e;
   aetd_state *s = (aetd_state *) c;
   /* since no userid can be > 255, it follows that no
      word can be, either */
   unsigned char word[256];
   DBT key, data;
   int i;
   int ret;

   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   for (i=0; i<we->len && i < sizeof(word); i++)
      word[i] = tolower((we->ptr)[i]);

   key.data = (void *) word;
   key.size = (size_t) we->len;

   data.data = s->entry;
   data.size = 12;

   if ((ret = (*(worddb->put))(worddb, s->tid, &key, &data, 0))) {
      s->writing = 1;
      s->pks_errno = ret;
      fail();
   }

   return(1);
}

int add_key_to_worddb(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   aetd_state *s = (aetd_state *) c;
   
   kd_make_worddb_entry(ke, s->entry);

   if (!llist_iterate(&(ke->words), add_word_to_worddb, c))
      fail();

   return(1);
}

int db_store_wordlist(kd_txn tid, llist *keys, error *err)
{
   aetd_state aetds;

   aetds.tid = tid;
   aetds.pks_errno = 0;

   if (!llist_iterate(keys, add_key_to_worddb, &aetds)) {
      err->fatal = 1;
      if (aetds.pks_errno) {
	 sprintf(err->buf, "error %s worddb, errno = %d",
		 aetds.writing?"writing to":"reading from", aetds.pks_errno);
      } else {
	 err->str = "internal error while storing wordlist";
      }
      fail();
   }

   return(1);
}

int add_key_to_timedb(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   aetd_state *s = (aetd_state *) c;
   time_t now;
   unsigned char nowkey[4];
   DBT key;

   memset(&key, 0, sizeof(key));

   if (time(&now) < 0) {
      s->writing = 0;
      s->pks_errno = errno;
      fail();
   }

   nowkey[0] = now>>24;
   nowkey[1] = now>>16;
   nowkey[2] = now>>8;
   nowkey[3] = now>>0;

   key.data = (void *) nowkey;
   key.size = 4;

   kd_make_worddb_entry(ke, s->entry);

   return(add_entry_to_db(timedb, &key, s));
}

int db_store_timestamp(kd_txn tid, llist *keys, error *err)
{
   aetd_state aetds;

   aetds.tid = tid;
   aetds.pks_errno = 0;

   /* all the keyid's are the same, only need to deal with the first,
      instead of iterating over all */

   if (!add_key_to_timedb(*((void **) keys->xb.buf), (void *) &aetds)) {
      err->fatal = 1;
      if (aetds.pks_errno) {
	 sprintf(err->buf, "error %s timedb, errno = %d",
		 aetds.writing?"writing to":"reading from", aetds.pks_errno);
      } else {
	 err->str = "internal error while storing timestamp";
      }
      fail();
   }

   return(1);
}

const char bad_key_errstr[] =
"Part or all of the request could not be processed\n"
"because one of the keys had a different %s\n"
"than the key currently in the database.  The key ID of the\n"
"unprocessable key is %02X%02X%02X%02X.\n";
const char revocation_sig[] = "revocation signature";

int db_key_merge_1(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   dkm1_state *s = (dkm1_state *) c;

   llist db_keys;

   llist_alloc(&db_keys);

   /* first, clear the disabled bit in files from a user */

   if (s->dkms->no_strip_disabled && ke->disabled)
      ke->disabled = -1;
   else
      ke->disabled = 0;

   ke->disabled = s->dkms->no_strip_disabled?(ke->disabled?-1:0):0;

   if (!kd_get_keys_by_keyid(s->tid, ke->keyidbits.buf /* 8 byte keyid */,
			     &db_keys, s->dkms->err))
      return(0);

   if (llist_count(&db_keys) == 0) {
      /* key not in file, this is a new entry.  Add the
	 key to the keylist */

      if (!llist_add(&db_keys, e)) {
	 llist_free(&db_keys);

	 s->dkms->err->fatal = 1;
	 s->dkms->err->str = "adding request key to db_keys failed";
	 fail();
      }

      s->dkms->ms.new_pubkeys++;
      if (s->dkms->ms.verbose)
	 display_new_key(&(s->dkms->ms), &(ke->keyidbits));

      /* this is definitely a new key.  marshall it into the add
	 xbuffer for later */

      if (s->dkms->ms.save_add) {
	 if (!kd_keys_elem_marshall(ke, s->dkms->ms.add_xb)) {
	    s->dkms->err->fatal = 1;
	    s->dkms->err->str = "failed marshalling new key";
	    fail();
	 }
      }
   } else {
      /* got keys from the file */

      llist request_key, merged_keys;

      /* put the request key into a list so it can be merged */

      llist_alloc(&request_key);
      /* order doesn't matter when there's only one */
      if (!llist_add(&request_key, e)) {
	 llist_free(&request_key);

	 llist_iterate(&db_keys, keys_elem_free, NULL);
	 llist_free(&db_keys);

	 s->dkms->err->fatal = 1;
	 s->dkms->err->str = "adding request key to request_key failed";
	 fail();
      }

      /* merge the key lists */

      llist_alloc(&merged_keys);
   
      if (!llist_merge(&merged_keys, &db_keys, &request_key,
		       kd_keys_elem_merge, (void *) &(s->dkms->ms),
		       keys_elem_free, NULL)) {
	 /* if this ever becomes non-fatal, remember this:
	    // merge will destroy the input lists

	    // since ke is destroyed, make it clean and empty, so 
	    // it can be safely freed in kd_keyblock_iterate 
	    keys_elem_alloc(ke);
	    */

	 s->dkms->err->fatal = 1;
	 s->dkms->err->str = "merging database key with request key failed";
	 fail();
      }

      db_keys = merged_keys;

      if (s->dkms->ms.save_add) {
	 /* check to see if anything was added, and if so, marshall it
	    into the add xbuffer for later */

	 if (!llist_iterate(&(s->dkms->ms.add_keys), kd_keys_elem_marshall,
			    s->dkms->ms.add_xb) ||
	     !llist_iterate(&(s->dkms->ms.add_keys), add_keys_elem_free,
			    NULL)) {
	    s->dkms->err->fatal = 1;
	    s->dkms->err->str = "failed marshalling added keys";
	    fail();
	 }

	 llist_free(&(s->dkms->ms.add_keys));
      }
   }

   /* check to see if the key actually changed.  Don't bother writing
      if nothing did */

   if (!s->dkms->ms.new_sigs &&
       !s->dkms->ms.repl_sigs &&
       !s->dkms->ms.new_userids &&
       !s->dkms->ms.changed_primary_userids &&
       !s->dkms->ms.new_revocations &&
       !s->dkms->ms.new_pubkeys) {
      llist_iterate(&db_keys, keys_elem_free, NULL);
      llist_free(&db_keys);

      return(1);
   }

   /* At this point, db_keys contains a key list which needs to be stored
      into the database:
      - the key list should be marshalled into a keyblock and stored
        in the primary database
      - the words in the wordlists (only one wordlist should have
        words in it, anyway) should be added to the word hash
      - the keyid should be added to the timestamp btree
      */

   /* any errors past this point are fatal */

   if (!kd_db_store_keyblock(s->tid, &db_keys, s->dkms->err)) {
      llist_iterate(&db_keys, keys_elem_free, NULL);
      llist_free(&db_keys);

      fail();
   }

   if (!db_store_wordlist(s->tid, &db_keys, s->dkms->err)) {
      llist_iterate(&db_keys, keys_elem_free, NULL);
      llist_free(&db_keys);

      fail();
   }

   if (!db_store_timestamp(s->tid, &db_keys, s->dkms->err)) {
      llist_iterate(&db_keys, keys_elem_free, NULL);
      llist_free(&db_keys);

      fail();
   }

   llist_iterate(&db_keys, keys_elem_free, NULL);
   llist_free(&db_keys);

   return(1);
}

int db_key_merge(void *e, void *c)
{
   dkm1_state dkm1s;
   dkm_state *s = (dkm_state *) c;

   dkm1s.dkms = s;

   if (kd_txn_begin(&(dkm1s.tid), s->err) &&
       db_key_merge_1(e, &dkm1s) &&
       kd_txn_commit(dkm1s.tid, s->err))
      return(1);

   kd_txn_abort(dkm1s.tid, s->err);

   return(0);
}

int kd_add_1(unsigned char *keys, long len, int flags,
	     xbuffer *win_msg, xbuffer *newkeys_xb, error *err)
{
   dkm_state s;
   ki_softerr softerr;
   int ret;
   char debugmsg[1024];

   softerr.count = 0;

   s.ms.new_sigs = 0;
   s.ms.repl_sigs = 0;
   s.ms.new_userids = 0;
   s.ms.changed_primary_userids = 0;
   s.ms.new_revocations = 0;
   s.ms.new_pubkeys = 0;
   s.ms.not_changed_revocation_sig = 0;
   s.ms.verbose = flags & KD_ADD_VERBOSE;

   if (newkeys_xb) {
      s.ms.save_add = 1;
      llist_alloc(&(s.ms.add_keys));
      llist_alloc(&(s.ms.add_userids));
      llist_alloc(&(s.ms.add_sigs));
      s.ms.add_xb = newkeys_xb;
   } else {
      s.ms.save_add = 0;
   }

   s.no_strip_disabled = (flags & KD_ADD_NO_STRIP_DISABLED)?1:0;
   s.err = err;

   /* this routine iterates through the keyblock.  For each public
      key, a structure describing that key is allocated and processed
      by db_key_merge() (which destroys the structure). 

      db_key_merge() retrieves the relevant keyblock from the
      database, merge the two, and write out records to all three
      databases. */

   ret = kd_keyblock_iterate(keys, len, db_key_merge, &s, err, &softerr, 1);

   kd_sync();

   if (!ret) {
      if (newkeys_xb)
	 xbuffer_free(newkeys_xb);
      return(0);
   }

   if (newkeys_xb && newkeys_xb->len) {
      if (!s.ms.new_sigs &&
          !s.ms.repl_sigs &&
          !s.ms.new_userids &&
          !s.ms.new_revocations &&
          !s.ms.new_pubkeys &&
          !s.ms.not_changed_revocation_sig) {
         /* Nothing new, except probably primary uid changes;
          * do not propagate them to avoid loops */
         sprintf(debugmsg, "Not propagating %d lonely primary uid changes",
                 s.ms.changed_primary_userids);
         log_info("kd_add", debugmsg);
         xbuffer_free(newkeys_xb);
      } else {
         ddesc binary, armored;

         binary.data = newkeys_xb->buf;
         binary.size = newkeys_xb->len;
         binary.offset = 0;

         armored.size = encode_ascii_size(&binary, "PUBLIC KEY BLOCK");
         if ((armored.data = (unsigned char *) malloc(armored.size)) == NULL) {
            xbuffer_free(newkeys_xb);
            err->fatal = 1;
            err->str = "Allocating memory for ascii armor added key block failed";
            fail();
         }
         armored.offset = 0;

         if (!encode_ascii(&binary, "PUBLIC KEY BLOCK", &armored)) {
            free(armored.data);
            xbuffer_free(newkeys_xb);
            err->fatal = 1;
            err->str = "Converting added key block to ascii armor failed";
            fail();
         }

         xbuffer_free(newkeys_xb);

         /* it saves a copy.  sigh. */

         newkeys_xb->alloclen = armored.offset;
         newkeys_xb->len = armored.offset;
         newkeys_xb->buf = armored.data;
      }
   }
   
   /* Give statistics */
   sprintf(debugmsg, "pub+%d sig+%d sig=%d uid+%d uid=%d rev+%d rev!%d",
           s.ms.new_pubkeys, s.ms.new_sigs, s.ms.repl_sigs,
           s.ms.new_userids, s.ms.changed_primary_userids,
           s.ms.new_revocations, s.ms.not_changed_revocation_sig);
   log_debug("kd_add", debugmsg);

   if (!s.ms.new_sigs &&
       !s.ms.repl_sigs &&
       !s.ms.new_userids &&
       !s.ms.changed_primary_userids &&
       !s.ms.new_revocations &&
       !s.ms.new_pubkeys &&
       !s.ms.not_changed_revocation_sig) {
      if (newkeys_xb && newkeys_xb->len) {
         sprintf(debugmsg, "Strange: nothing changed, but newkeys_xb->len=%ld",
                 newkeys_xb->len);
         log_error("kd_add", debugmsg);
      }
      
      if (!xbuffer_append_str(win_msg,
			      "Key block in add request contained no new\n"
			      "keys, userid's, or signatures.\n")) {
	 xbuffer_free(newkeys_xb);
	 err->fatal = 1;
	 err->str = "Failed allocating space for success string";
	 fail();
      }
   } else {
      if (!xbuffer_append_str(win_msg,
			      "Key block added to key server database.\n")) {
	 xbuffer_free(newkeys_xb);
	 err->fatal = 1;
	 err->str = "Failed allocating space for success string";
	 fail();
      }

      if (s.ms.new_pubkeys) {
	 sprintf(s.err->buf, "%d", s.ms.new_pubkeys);
	 if (!xbuffer_append_str(win_msg, "  New public keys added: ") ||
	     !xbuffer_append_str(win_msg, s.err->buf) ||
	     !xbuffer_append_str(win_msg, "\n")) {
	    xbuffer_free(newkeys_xb);
	    err->fatal = 1;
	    err->str = "Failed allocating space for success string";
	    fail();
	 }
      }
      if (s.ms.new_revocations) {
	 sprintf(s.err->buf, "%d", s.ms.new_revocations);
	 if (!xbuffer_append_str(win_msg,
				 "  New revocation signatures added: ") ||
	     !xbuffer_append_str(win_msg, s.err->buf) ||
	     !xbuffer_append_str(win_msg, "\n")) {
	    xbuffer_free(newkeys_xb);
	    err->fatal = 1;
	    err->str = "Failed allocating space for success string";
	    fail();
	 }
      }
      if (s.ms.new_userids) {
	 sprintf(s.err->buf, "%d", s.ms.new_userids);
	 if (!xbuffer_append_str(win_msg, "  New userid's added: ") ||
	     !xbuffer_append_str(win_msg, s.err->buf) ||
	     !xbuffer_append_str(win_msg, "\n")) {
	    xbuffer_free(newkeys_xb);
	    err->fatal = 1;
	    err->str = "Failed allocating space for success string";
	    fail();
	 }
      }
      if (s.ms.changed_primary_userids) {
	 sprintf(s.err->buf, "%d", s.ms.changed_primary_userids);
	 if (!xbuffer_append_str(win_msg, "  Primary userid's changed: ") ||
	     !xbuffer_append_str(win_msg, s.err->buf) ||
	     !xbuffer_append_str(win_msg, "\n")) {
	    xbuffer_free(newkeys_xb);
	    err->fatal = 1;
	    err->str = "Failed allocating space for success string";
	    fail();
	 }
      }
      if (s.ms.repl_sigs) {
	 sprintf(s.err->buf, "%d", s.ms.repl_sigs);
	 if (!xbuffer_append_str(win_msg, "  Signature updated: ") ||
	     !xbuffer_append_str(win_msg, s.err->buf) ||
	     !xbuffer_append_str(win_msg, "\n")) {
	    xbuffer_free(newkeys_xb);
	    err->fatal = 1;
	    err->str = "Failed allocating space for success string";
	    fail();
	 }
      }
      if (s.ms.new_sigs) {
	 sprintf(s.err->buf, "%d", s.ms.new_sigs);
	 if (!xbuffer_append_str(win_msg, "  New signatures added: ") ||
	     !xbuffer_append_str(win_msg, s.err->buf) ||
	     !xbuffer_append_str(win_msg, "\n")) {
	    xbuffer_free(newkeys_xb);
	    err->fatal = 1;
	    err->str = "Failed allocating space for success string";
	    fail();
	 }
      }
      if (s.ms.not_changed_revocation_sig) {
	 sprintf(s.err->buf, "%d", s.ms.not_changed_revocation_sig);
	 if (!xbuffer_append_str(win_msg,  "Changed revocations ignored: ") ||
	     !xbuffer_append_str(win_msg, s.err->buf) ||
	     !xbuffer_append_str(win_msg, "\n")) {
	    xbuffer_free(newkeys_xb);
	    err->fatal = 1;
	    err->str = "Failed allocating space for success string";
	    fail();
	 }
      }
   }

   if (softerr.count > 0) {
      char err_count[20];

      sprintf(err_count, "%d", softerr.count);
      if (!xbuffer_append_str(win_msg, "Your key block contained ") ||
          !xbuffer_append_str(win_msg, err_count) ||
          !xbuffer_append_str(win_msg, " format errors,\n"
                              "which were treated as if the erroneous elements\n"
                              "hadn't been part of your submission.\n")) {
	 xbuffer_free(newkeys_xb);
	 err->fatal = 1;
	 err->str = "Failed allocating space for success string";
	 fail();
      }

      if (softerr.keyid_set) {
         char keyid[20];

         sprintf(keyid, "%02x%02x%02x%02x", softerr.keyid[0],
                 softerr.keyid[1], softerr.keyid[2], softerr.keyid[3]);
         if (!xbuffer_append_str(win_msg, "The last error was on key 0x") ||
             !xbuffer_append_str(win_msg, keyid) ||
             !xbuffer_append_str(win_msg, ":\n") ||
             !xbuffer_append_str(win_msg, softerr.buf) ||
             !xbuffer_append_str(win_msg, "\n")) {
            xbuffer_free(newkeys_xb);
            err->fatal = 1;
            err->str = "Failed allocating space for success string";
            fail();
         }
      } else {
         if (!xbuffer_append_str(win_msg,
                                 "The errors were outside of any PGP public key;\n"
                                 "maybe you didn't send a public key block at all.\n"
                                 "Anyway, the last error encountered was:\n") ||
             !xbuffer_append_str(win_msg, softerr.buf) ||
             !xbuffer_append_str(win_msg, "\n")) {
            xbuffer_free(newkeys_xb);
            err->fatal = 1;
            err->str = "Failed allocating space for success string";
            fail();
         }
      }
   }
   
   return(1);
}

int kd_add(unsigned char *keys, long len, int flags,
	   unsigned char **ret, long *retlen,
	   unsigned char **newkeys, long *newkeyslen)
{
   error err;
   xbuffer msg, addkeys;

   err.str = err.buf;
   xbuffer_alloc(&msg);

   if (newkeys)
      xbuffer_alloc(&addkeys);

   kd_log_start("kd_add", NULL, 0, flags);

   if (kd_add_1(keys, len, flags, &msg, newkeys?&addkeys:NULL, &err)) {
      *ret = msg.buf;
      *retlen = msg.len;
      if (newkeys) {
	 *newkeys = addkeys.buf;
	 *newkeyslen = addkeys.len;
      }

      kd_log_finish("kd_add", 1);

      return(1);
   }

   if (!err.fatal) {
      if (!(*ret = (unsigned char *) my_strdup(err.str))) {
	 err.fatal = 1;
	 err.str = "Failed allocating space for error string";
	 dabort();

	 /* fall through to fatal error handler */
      } else {
	 *retlen = strlen((char *) *ret);
	 if (newkeys) {
	    xbuffer_free(&addkeys);
	    *newkeys = NULL;
	    *newkeyslen = 0;
	 }

         kd_log_finish("kd_add", 0);

	 return(0);
      }
   }

   /* fatal errors */

   if (err.fatal) {
      log_fatal("kd_add", err.str);
      /* never returns */
   }

   /* keep the compiler quiet */

   return(0);
}

