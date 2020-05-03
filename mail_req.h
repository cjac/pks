#ifndef _MAIL_REQ_H_
#define _MAIL_REQ_H_

/*
 * $Id: mail_req.h,v 1.2 2002/09/08 19:27:34 rlaager Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "mail_send.h"
#include "pks_incr.h"

typedef struct _mail_req_conf {
   mail_send_conf *msc;
   pks_incr_conf *pic;
   int max_last;
   int max_last_reply_keys;
   int max_reply_keys;
} mail_req_conf;

void mail_req(unsigned char *msg, long len, mail_req_conf *conf,
	      mail_send_cleanup msc, void *c);

#endif
