#ifndef _PKS_INCR_H_
#define _PKS_INCR_H_

/*
 * $Id: pks_incr.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "mail_send.h"
#include "llist.h"

typedef struct _pks_incr_conf {
   char *this_site;
   llist *syncsites;
   mail_send_conf *msc;
} pks_incr_conf;

#define pks_incr_have_syncsites(conf) (llist_count((conf)->syncsites))

int pks_incr_make_header(pks_incr_conf *conf, xbuffer *xsentto,
			 xbuffer *incr_to);

int pks_incr_post(pks_incr_conf *conf, xbuffer *xsentto, xbuffer *incr_to,
		  unsigned char *incrmsg, long incrmsglen);

#endif
