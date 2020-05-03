const char rcsid_kd_since_c[] = "$Id: kd_since.c,v 1.2 2002/09/04 21:00:23 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "pgputil.h"
#include "armor.h"
#include "database.h"
#include "globals.h"
#include "kd_search.h"
#include "util.h"

static int sort_twelvebytes(const void *a, const void *b)
{
   /* the result should be most recent first, so reverse args to memcmp */
   return(memcmp(b, a, 12));
}

int kd_since_1(kd_txn tid, time_t since, int flags, int maxkeys,
	       time_t *last, ddesc *armored, error *err)
{
   xbuffer entries, keys;
   ddesc binary;
   int ret, i;
   unsigned char firstkey[4];
   DBC *cursor;
   DBT key, data;
   ow_state ows;
   unsigned char *tmp;
   unsigned long ul_last;

   memset(&key, 0, sizeof(key));
   memset(&data, 0, sizeof(data));

   xbuffer_alloc(&entries);

   firstkey[0] = since>>24;
   firstkey[1] = since>>16;
   firstkey[2] = since>>8;
   firstkey[3] = since;

   key.data = firstkey;
   key.size = sizeof(firstkey);

   if ((ret = (*(timedb->cursor))(timedb, tid, &cursor, 0))) {
      err->fatal = 1;
      sprintf(err->buf, "error creating timedb cursor: error = %d", ret);
      fail();
   }

   for (ret = (*(cursor->c_get))(cursor, &key, &data, DB_SET_RANGE);
	ret == 0;
	ret = (*(cursor->c_get))(cursor, &key, &data, DB_NEXT)) {
      if (data.size%12) {
	 (*(cursor->c_close))(cursor);

	 err->fatal = 1;
	 err->str = "consistency error iterating timedb, data.size%12 != 0";
	 fail();
      }

      for (KD_FIRST_ENTRY(i); KD_LAST_ENTRY(i, data); KD_NEXT_ENTRY(i))
	 ;

      if ((maxkeys >= 0) &&
	  ((entries.len+i)/12 > maxkeys)) {
	 xbuffer_free(&entries);
	 (*(cursor->c_close))(cursor);

	 err->fatal = 0;
	 sprintf(err->buf,"Number of keys in reply would exceeded maximum "
		 "allowed (%d)\nTry a smaller time.\n",
		 maxkeys);
	 return(0);
      }

      if (!xbuffer_append(&entries, (unsigned char *) data.data,
			  (long) i)) {
	 xbuffer_free(&entries);
	 (*(cursor->c_close))(cursor);

	 err->fatal = 1;
	 err->str = "failed appending to entry list";
	 fail();
      }
   }

   (*(cursor->c_close))(cursor);

   if (ret != DB_NOTFOUND) {
      err->fatal = 1;
      sprintf(err->buf, "error iterating timedb: errno = %d", errno);
      fail();
   }

   if (entries.len == 0) {
      /* no matching keys in database */

      err->fatal = 0;
      err->str = "No matching keys in database";
      return(0);
   }

   qsort(entries.buf, (size_t) (entries.len/12), 12, sort_twelvebytes);

   xbuffer_alloc(&keys);

   ows.tid = tid;
   ows.userid = NULL;
   ows.userid_len = 0;
   ows.filter = NULL;
   ows.return_disabled = 0;
   ows.c = (void *) &keys;
   ows.err = err;
   ows.append = kd_keys_elem_marshall;

   for (i=0; i<entries.len; i+=12)
      if (i && memcmp((void *) (entries.buf+i-12),
		      (void *) (entries.buf+i), 12) &&
	  (!kd_output_wde((void *) (entries.buf+i), (void *) &ows)))
	 return(0);

   xbuffer_free(&entries);

   if (flags & KD_SINCE_BINARY) {
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

   if (last) {
      tmp = key.data;
      ul_last = (tmp[0]<<24)|(tmp[1]<<16)|(tmp[2]<<8)|(tmp[3]);

      *last = ul_last;
   }

   return(1);
}

int kd_since(time_t since, int flags, int maxkeys,
	     time_t *last, unsigned char **ret, long *retlen)
{
   error err;
   ddesc armored;
   kd_txn tid;
   err.str = err.buf;

   {
      char buf[1024];

      sprintf(buf, "(times >= %ld)", (long) since);
      kd_log_start("kd_since", (unsigned char *) buf, (long) strlen(buf),
		   flags);
   }

   if (kd_txn_begin(&tid, &err) &&
       kd_since_1(tid, since, flags, maxkeys, last, &armored, &err) &&
       kd_txn_commit(tid, &err)) {
      *ret = armored.data;
      *retlen = armored.offset;

      kd_log_finish("kd_since", 1);

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

	 kd_log_finish("kd_since", 0);

         return(0);
      }
   }

   /* fatal errors */

   if (err.fatal)
      log_fatal("ks_get", err.str);

   /* keep the compiler quiet */

   return(0);
}
