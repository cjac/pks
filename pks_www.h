#ifndef _PKS_WWW_H_
#define _PKS_WWW_H_

/*
 * $Id: pks_www.h,v 1.5 2002/11/05 04:07:38 rlaager Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "pks_incr.h"

typedef struct _pks_www_conf {
   char *addr;
   int port;
   int readonly;
   int max_reply_keys;
   char *www_dir;
   pks_incr_conf *pic;
} pks_www_conf;

void pks_www_init(pks_www_conf *conf);

#endif
