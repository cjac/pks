const char rcsid_pks_incr_c[] = "$Id: pks_incr.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include "pks_incr.h"
#include "llist.h"
#include "util.h"
#include "globals.h"

typedef struct _mih_state {
   xbuffer *xsentto;
   xbuffer *incr_to;
} mih_state;

static const char xsentto_str[] = "X-KeyServer-Sent:";
static int xsentto_len = sizeof(xsentto_str)-1;

static const unsigned char incr_str[] = "incremental";
static long incr_len = sizeof(incr_str)-1;

static const unsigned char pgpkeys_str[] =
	"Content-type: application/pgp-keys\n";
static int pgpkeys_len = sizeof(pgpkeys_str)-1;

int make_incr_header(void *e, void *c)
{
   char *str = (char *) e;
   mih_state *s = (mih_state *) c;
   xbuffer tmp;

   /* construct an xb containing a header for the address in question */

   xbuffer_alloc(&tmp);

   if (!xbuffer_append(&tmp, (unsigned char *) xsentto_str, xsentto_len) ||
       !xbuffer_append_str(&tmp, " ") ||
       !xbuffer_append_str(&tmp, str) ||
       !xbuffer_append_str(&tmp, "\n")) {
      xbuffer_free(&tmp);
      return(0);
   }

   /* if the message has never been anywhere before, or if it has, but
      not to this place, then add the address to the to list for this
      incremental */

   if (!s->xsentto || !s->xsentto->len ||
       (my_memcasemem(s->xsentto->buf, tmp.buf,
		      s->xsentto->len, tmp.len) == NULL)) {
      if ((s->incr_to->len && !xbuffer_append_str(s->incr_to, ", ")) ||
 	  !xbuffer_append_str(s->incr_to, str)) {
	 xbuffer_free(&tmp);
	 return(0);
      }
   }

   xbuffer_free(&tmp);

   return(1);
}

int pks_incr_make_header(pks_incr_conf *conf, xbuffer *xsentto,
			 xbuffer *incr_to)
{
   mih_state mihs;

   mihs.xsentto = xsentto;
   mihs.incr_to = incr_to;

   if (!llist_iterate(conf->syncsites, make_incr_header, &mihs)) {
      xbuffer_free(mihs.incr_to);
      return(0);
   }

   return(1);
}

int pks_incr_post(pks_incr_conf *conf,
		  xbuffer *xsentto, xbuffer *incr_to,
		  unsigned char *incrmsg, long incrmsglen)
{
   char buf[1024];
   xbuffer me, headers, new_incr_to;

   /* if the to address isn't specified, then make it now */

   xbuffer_alloc(&new_incr_to);

   if (!incr_to) {
      if (!pks_incr_make_header(conf, xsentto, &new_incr_to)) {
	 xbuffer_free(&headers);
	 xbuffer_free(&new_incr_to);
	 return(0);
      }
      incr_to = &new_incr_to;
   }

   /* if the the to list for this incremental is empty, then don't
      send it anywhere */

   if (incr_to->len == 0) {
      log_info("pks_post_incr", "no incremental needed");
      return(1);
   }

   /* if this message been somewhere before, then append those headers
      to the header buffer for this message */

   xbuffer_alloc(&headers);

   if (xsentto && xsentto->len)
      xbuffer_append(&headers, xsentto->buf, xsentto->len);

   /* if this message has never been anywhere, or if it has, but this host
      is not listed, then add this host. */

   xbuffer_alloc(&me);

   if (!xbuffer_append(&me, (unsigned char *) xsentto_str, xsentto_len) ||
       !xbuffer_append_str(&me, " ") ||
       !xbuffer_append_str(&me, conf->this_site) ||
       !xbuffer_append_str(&me, "\n"))
      return(0);
	    
   if (!xsentto || !xsentto->len ||
       (my_memcasemem(xsentto->buf, me.buf,
		      xsentto->len, me.len) == NULL)) {
      if (!xbuffer_append(&headers, me.buf, me.len))
	 return(0);
   }

   xbuffer_free(&me);

   mail_send(conf->msc, MAIL_SEND_NO_INTRO,
	     incr_to->buf, incr_to->len,
	     incr_str, incr_len,
	     headers.buf, headers.len,
	     pgpkeys_str, pgpkeys_len,
	     incrmsg, incrmsglen,
	     NULL, NULL);

   sprintf(buf, "posted incremental to %.*s",
	   (int) incr_to->len, incr_to->buf);
   log_info("pks_post_incr", buf);

   xbuffer_free(&headers);
   xbuffer_free(&new_incr_to);

   return(1);
}
