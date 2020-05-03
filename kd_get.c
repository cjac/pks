const char rcsid_kd_get_c[] = "$Id: kd_get.c,v 1.3 2002/10/08 04:04:42 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pgputil.h"
#include "armor.h"
#include "database.h"
#include "globals.h"
#include "llist.h"
#include "kd_types.h"
#include "kd_internal.h"
#include "kd_search.h"

typedef struct _kkec_state {
   FILE *out;
   xbuffer keys;
} kkec_state;

int kd_keys_elem_cout(void *e, void *c)
{
   kkec_state *s = (kkec_state *) c;

   if (!kd_keys_elem_marshall(e, &s->keys))
      fail();

   fwrite(s->keys.buf, s->keys.len, 1, s->out);

   /* "remove" the data from the buffer, but don't free it.
      this will save a lot of malloc/free calls */
   s->keys.len = 0;

   return(1);
}

int kd_get_1(kd_txn tid, unsigned char *userid, long len, int flags,
	     int maxkeys, ddesc *armored, error *err)
{
   xbuffer keys;
   ddesc binary;

   xbuffer_alloc(&keys);

   /* This is called violating abstractions in the interest of
      efficiency.  Whee. */

   if (flags & KD_GET_STDOUT) {
      kkec_state kkecs;
      int ret;

      kkecs.out = stdout;
      xbuffer_alloc(&kkecs.keys);

      ret = kd_search_1(tid, userid, len, flags & KD_SEARCH_FLAGS, maxkeys,
			kd_keys_elem_cout, NULL, &kkecs, err);

      xbuffer_free(&kkecs.keys);

      if (!ret)
	 return(0);

      armored->data = keys.buf;
      armored->size = keys.len;
      armored->offset = keys.len;

      return(1);
   }

   if (!kd_search_1(tid, userid, len, flags & KD_SEARCH_FLAGS, maxkeys,
		    kd_keys_elem_marshall, NULL, &keys, err))
      return(0);

   if (keys.len == 0) {
      /* this should only happen if the keys requested are disabled
	 or the database is corrupt.  If the latter is the case, lie. */

      err->fatal = 0;
      err->str = "The requested key has been disabled";
      return(0);
   }

   if (flags & KD_GET_BINARY) {
      armored->data = keys.buf;
      armored->size = keys.len;
      armored->offset = keys.len;
   } else {
      /* ascii-armor the keyblock */

      binary.data = keys.buf;
      binary.size = keys.len;
      binary.offset = 0;

      armored->size = encode_ascii_size(&binary, "PUBLIC KEY BLOCK");
      if ((armored->data = (unsigned char *) malloc(armored->size)) == NULL) {
	 xbuffer_free(&keys);
	 err->fatal = 1;
	 err->str = "Allocating memory for ascii armor key block failed";
	 fail();
      }
      armored->offset = 0;

      if (!encode_ascii(&binary, "PUBLIC KEY BLOCK", armored)) {
	 free(armored->data);
	 xbuffer_free(&keys);
	 err->fatal = 1;
	 err->str = "Converting key block to ascii armor failed";
	 fail();
      }

      xbuffer_free(&keys);
   }

   return(1);
}

int kd_get(unsigned char *userid, long len, int flags, int maxkeys,
           unsigned char **ret, long *retlen)
{
   error err;
   ddesc armored;
   kd_txn tid;

   err.str = err.buf;

   kd_log_start("kd_get", userid, len, flags);

   if (kd_txn_begin(&tid, &err) &&
       kd_get_1(tid, userid, len, flags, maxkeys, &armored, &err) &&
       kd_txn_commit(tid, &err)) {
      *ret = armored.data;
      *retlen = armored.offset;

      kd_log_finish("kd_get", 1);

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

	 kd_log_finish("kd_get", 0);

         return(0);
      }
   }

   /* fatal errors */

   if (err.fatal)
      log_fatal("ks_get", err.str);

   /* keep the compiler quiet */

   return(0);
}
