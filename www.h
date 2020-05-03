#ifndef _WWW_H_
#define _WWW_H_

/*
 * $Id: www.h,v 1.3 2003/01/04 20:57:39 dmshaw Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

/* If bodylen is nonzero, then the request was a GET with a ?query, or
   a POST.  Otherwise, it's just a GET */

typedef void (*httphandler)(int fd, int vers, unsigned char *uri, long urilen,
			    unsigned char *body, long bodylen,
			    void *c);

void www_init(char *addr, int port, httphandler h, void *c);
void www_reply(int fd, int vers, int status_code, const char *reason_phrase,
	       const char *content_type,
	       const unsigned char *reply, long replylen);
int www_urldecode(unsigned char *str, long *len);

#endif
