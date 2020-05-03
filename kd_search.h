#ifndef _KD_SEARCH_H_
#define _KD_SEARCH_H_

/*
 * $Id: kd_search.h,v 1.3 2003/01/25 16:32:02 dmshaw Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "llist.h"
#include "kd_internal.h"
#include "kd_types.h"

typedef int (*search_llist_filter)(void *e, llist *new_list,
				   void *c, error *err);

typedef struct _ow_state {
   kd_txn tid;
   unsigned char *userid;
   long userid_len;
   void *c;
   search_llist_filter filter;
   int return_disabled;
   llist_iter append;
   error *err;
} ow_state;

typedef struct _ki_softerr {
   int count;
   char buf[1024];
   int keyid_set;
   unsigned char keyid[4];
} ki_softerr;

int kd_keyblock_iterate(unsigned char *block, long blocklen,
			llist_iter iter, void *c, error *err,
			ki_softerr *softerr, int errorhack);
int kd_get_keys_by_keyid(kd_txn tid, unsigned char *keyid,
			 llist *keys, error *err);
void kd_make_worddb_entry(keys_elem *ke, unsigned char entry[]);
int kd_output_wde(void *e, void *c);
int kd_search_1(kd_txn tid, unsigned char *userid, long len, int flags,
		int maxkeys, llist_iter func, search_llist_filter filt,
		void *c, error *err);

#endif
