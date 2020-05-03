const char rcsid_kd_delete_c[] = "$Id: kd_delete.c,v 1.5 2002/11/12 05:03:36 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "database.h"
#include "globals.h"
#include "llist.h"
#include "kd_types.h"
#include "kd_internal.h"
#include "kd_search.h"
#include "pgputil.h"
#include "util.h"

typedef struct _dwfw_state {
   kd_txn tid;
   unsigned char entry[12];
   error *err;
} dwfw_state;

typedef struct _dkfw_state {
   kd_txn tid;
   xbuffer *deleted;
} dkfw_state;


/* this isn't particularly efficient, but deletes aren't all that common. */
int delete_word_from_worddb(void *e, void *c)
{
   words_elem *we = (words_elem *) e;
   dwfw_state *s = (dwfw_state *) c;

   unsigned char word[256];
   DBC *cursor;
   DBT key, data;
   int i, ret;

   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   for (i=0; i<we->len && i < sizeof(word); i++)
      word[i] = tolower((we->ptr)[i]);

   key.data = (void *) word;
   key.size = (size_t) we->len;

   data.data = s->entry;
   data.size = 12;

   ret = (*(worddb->cursor))(worddb, s->tid, &cursor, 0);

   if (ret && (ret != DB_NOTFOUND)) {
      s->err->fatal = 1;
      s->err->str = "database read error creating worddb cursor for delete";
      fail();
   }

   if ((ret = (*(cursor->c_get))(cursor, &key, &data, DB_GET_BOTH))) {
     /* We can't pass non-fatal error messages back, so we have to print
	them ourselves.  This should be OK since only pksclient does
	deletions. */
     (*(cursor->c_close))(cursor);
     fflush (stdout);
     fprintf(stderr,
	     "warning:  consistency error reading worddb for delete: %.*s not found\n",
	     (int) we->len, we->ptr);
     return (1);
   }

   /* loop over the matching entries, deleting as we go.  Normally, there
      can be only one matching entry, but there was once a bug which
      would leave extra matches around */

   for (;
	ret == 0;
	ret = (*(cursor->c_get))(cursor, &key, &data, DB_NEXT_DUP)) {
      if (memcmp(data.data, s->entry, 12) != 0)
	 break;

      if ((ret = (*(cursor->c_del))(cursor, 0)))
	 break;
   }

   (*(cursor->c_close))(cursor);

   if (ret && (ret != DB_NOTFOUND)) {
      s->err->fatal = 1;
      sprintf(s->err->buf,
	      "error reading worddb entry for delete (errno = %d)", ret);
      fail();
   }

   return(1);
}

int delete_key_from_worddb(void *e, llist *new_list, void *c, error *err)
{
   keys_elem *ke = (keys_elem *) e;
   dkfw_state *s = (dkfw_state *) c;
   dwfw_state dwfws;
   char buf[128];

   dwfws.tid = s->tid;
   kd_make_worddb_entry(ke, dwfws.entry);
   dwfws.err = err;

   if (!llist_iterate(&(ke->words), delete_word_from_worddb, &dwfws))
      return(0);

   sprintf(buf, "key id %02X%02X%02X%02X deleted\n",
	   ke->keyidbits.buf[4],
	   ke->keyidbits.buf[5],
	   ke->keyidbits.buf[6],
	   ke->keyidbits.buf[7]);

   if (!xbuffer_append_str(s->deleted, buf))
      return(0);

   keys_elem_free(e, NULL);

   return(1);
}

int kd_delete_1(kd_txn tid, unsigned char *userid, long len, int flags,
		xbuffer *deleted, error *err)
{
   dkfw_state dkfws;
   int ret;

   /* the NULL here as the append function means that any matching key
      will just disappear.  delete_key_from_worddb will remove the
      words as a side effect. */

   dkfws.tid = tid;
   dkfws.deleted = deleted;

   ret = kd_search_1(tid, userid, len, KD_SEARCH_EXACT, -1,
		     NULL, delete_key_from_worddb, &dkfws, err);

   kd_sync();

   if (!ret)
      return(0);

   if (deleted->len == 0) {
      /* no matching keys in database */

      err->fatal = 0;
      err->str = "No matching keys in database";
      return(0);
   }

   return(1);
}

int kd_delete(unsigned char *userid, long len, int flags,
              unsigned char **ret, long *retlen)
{
   error err;
   xbuffer deleted;
   kd_txn tid;

   err.str = err.buf;

   xbuffer_alloc(&deleted);

   kd_log_start("kd_delete", userid, len, flags);

   if (kd_txn_begin(&tid, &err) &&
       kd_delete_1(tid, userid, len, flags, &deleted, &err) &&
       kd_txn_commit(tid, &err)) {
      *ret = deleted.buf;
      *retlen = deleted.len;

      kd_log_finish("kd_delete", 1);

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

	 kd_log_finish("kd_delete", 0);

         return(0);
      }
   }

   /* fatal errors */

   if (err.fatal) {
      log_fatal("ks_delete", err.str);
      /* never returns */
   }

   /* keep the compiler quiet */

   return(0);
}   
