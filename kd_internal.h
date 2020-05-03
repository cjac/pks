#ifndef _KD_INTERNAL_H_
#define _KD_INTERNAL_H_

/*
 * $Id: kd_internal.h,v 1.3 2002/09/08 19:27:34 rlaager Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include <db.h>
#include "llist.h"

/* Checkpoint after so many successful transactions */
#define KD_MAX_TXN_WO_CKPT 256

/* keydb elements will be allocated with exponential size, starting
   with the min_alloc, until the max_alloc elements is reached, then
   the size will be incremented linearly by max_alloc elements.  These
   are tunable parameters, and should be changeable without rebuilding
   the database. */

#define KEYDB_MIN_ALLOC 2
#define KEYDB_MAX_ALLOC 8*1024

#define KEYDB_KEYID_BYTES 4

typedef struct _error {
   int fatal;
   char *str;
   char buf[1024];
} error;

typedef DB_TXN *kd_txn;

extern int num_keydb;
extern DB **keydb_files;
extern DB *keydb(DBT *key), *worddb, *timedb;

#define KD_FIRST_ENTRY(i) (i) = 0
#define KD_LAST_ENTRY(i, dbt) \
(((i)<(dbt).size) && \
 (memcmp(((unsigned char *) (dbt).data) + (i), zeros, 12) != 0))
#define KD_NEXT_ENTRY(i) (i)+=12

int kd_add_userid_to_wordlist(llist *wl,
			      unsigned char *userid, long userid_len);
int kd_keys_elem_marshall(void *e, void *c);
int kd_db_store_keyblock(kd_txn tid, llist *keys, error *err);

int kd_txn_begin(kd_txn *tid, error *err);
int kd_txn_commit(kd_txn tid, error *err);
int kd_txn_abort(kd_txn tid, error *err);

void kd_log_start(char *fct, unsigned char *userid, long len, int flags);
void kd_log_finish(char *fct, int success);

/* from kd_add.c */

int kd_sigs_elem_merge(llist *lout, void *e1, void *e2, void *c);
int kd_userids_elem_merge(llist *lout, void *e1, void *e2, void *c);
int kd_keys_elem_merge(llist *lout, void *e1, void *e2, void *c);

#endif
