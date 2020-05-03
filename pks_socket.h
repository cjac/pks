#ifndef _PKS_SOCKET_H_
#define _PKS_SOCKET_H_

/*
 * $Id: pks_socket.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "mail_req.h"

typedef struct _pks_socket_conf {
   char *socket;
   mail_req_conf *mrc;
} pks_socket_conf;

void pks_socket_init(pks_socket_conf *psc);

#endif
