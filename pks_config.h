#ifndef _PKS_CONFIG_H_
#define _PKS_CONFIG_H_

/*
 * $Id: pks_config.h,v 1.5 2002/11/05 04:07:38 rlaager Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "llist.h"

typedef struct _pks_config {
   /* database stuff */
   char db_dir[1024];

   /* web server stuff */
   char www_dir[1024];
   int www_port;
   char www_addr[1024];
   int www_readonly;

   /* mail server stuff */
   char socket_name[1024];

   char mail_delivery_client[1024];
   char maintainer_email[1024];
   char mail_intro_file[1024];
   char help_dir[1024];
   char default_lang[1024];

   /* incremental stuff */
   char this_site[1024];
   llist syncsites;

   /* policy stuff */
   int max_last;
   int max_last_reply_keys;
   int max_reply_keys;
} pks_config;

int pks_read_conf_file(const char *filename, pks_config *pc);

#endif
