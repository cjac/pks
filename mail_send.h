#ifndef _MAIL_SEND_H_
#define _MAIL_SEND_H_

/*
 * $Id: mail_send.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

typedef void (*mail_send_cleanup)(int error, void *c);

typedef struct _mail_send_conf {
   char *mail_delivery_client;
   char *maintainer_email;
   char *mail_intro_file;
   char *help_dir;
   char *default_lang;
} mail_send_conf;

/* Mail send flags (bit mask) */
#define MAIL_SEND_NO_INTRO       1

void mail_send(mail_send_conf *conf, int mail_send_flags,
	       const unsigned char *reply_to, long reply_to_len,
	       const unsigned char *subject, long subject_len,
	       const unsigned char *headers, long headers_len,
	       const unsigned char *bodyheaders, long bodyheaders_len,
	       const unsigned char *body, long body_len,
	       mail_send_cleanup msc, void *c);

void mail_help(mail_send_conf *conf,
	       const unsigned char *reply_to, long reply_to_len,
	       const unsigned char *subject, long subject_len,
	       const unsigned char *headers, long headers_len,
	       const unsigned char *help_file, long help_file_len,
	       mail_send_cleanup msc, void *c);

#endif
