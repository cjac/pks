const char rcsid_kd_disable_c[] = "$Id: kd_disable.c,v 1.3 2002/10/08 04:04:42 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "database.h"
#include "globals.h"
#include "llist.h"
#include "kd_types.h"
#include "kd_internal.h"
#include "kd_search.h"
#include "pgputil.h"

typedef struct _cd_state {
   xbuffer *xb;
   int set;
} cd_state;

int change_disable(void *e, llist *new_list, void *c, error *err)
{
   keys_elem *ke = (keys_elem *) e;
   cd_state *s = (cd_state *) c;
   char buf[128];

   ke->disabled = (s->set)?-1:0;

   if (!llist_add(new_list, e)) {
      err->fatal = 1;
      err->str =
	 (s->set
	  ?"appending disabled key to new_list failed"
	  :"appending undisabled key to new_list failed");
      fail();
   }

   sprintf(buf, "key id %02X%02X%02X%02X %s\n",
	   ke->keyidbits.buf[4],
	   ke->keyidbits.buf[5],
	   ke->keyidbits.buf[6],
	   ke->keyidbits.buf[7],
	   s->set?"disabled":"undisabled");

   if (!xbuffer_append_str(s->xb, buf))
      return(0);

   return(1);
}

int kd_disable_1(kd_txn tid, unsigned char *userid, long len, int flags,
		 xbuffer *disabled, error *err)
{
   int ret;
   cd_state cds;

   cds.xb = disabled;
   cds.set = (flags & KD_DISABLE_CLEAR)?0:1;

   ret = kd_search_1(tid, userid, len, KD_SEARCH_EXACT, -1,
		     NULL, change_disable, &cds, err);

   kd_sync();

   if (!ret)
      return(0);

   if (disabled->len == 0) {
      /* no matching keys in database */

      err->fatal = 0;
      err->str = "No matching keys in database";
      return(0);
   }

   return(1);
}

int kd_disable(unsigned char *userid, long len, int flags,
	       unsigned char **ret, long *retlen)
{
   error err;
   xbuffer disabled;
   kd_txn tid;

   err.str = err.buf;

   xbuffer_alloc(&disabled);

   kd_log_start("kd_disable", userid, len, flags);

   if (kd_txn_begin(&tid, &err) &&
       kd_disable_1(tid, userid, len, flags, &disabled, &err) &&
       kd_txn_commit(tid, &err)) {
      *ret = disabled.buf;
      *retlen = disabled.len;

      kd_log_finish("kd_disabled", 1);

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

	 kd_log_finish("kd_disable", 0);

         return(0);
      }
   }

   /* fatal errors */

   if (err.fatal) {
      log_fatal("kd_disable", err.str);
      /* never returns */
   }

   /* keep the compiler quiet */

   return(0);
}   

