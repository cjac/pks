const char rcsid_wwwtest_c[] = "$Id: wwwtest.c,v 1.2 2003/02/07 01:01:21 rlaager Exp $";

/* 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>

#include "www.h"
#include "util.h"
#include "globals.h"
#include "multiplex.h"

/* This is a dummy for log_fatal.  there isn't actually a database
   to close */

int kd_close()
{
   return(1);
}

void wwwtest(int fd, int vers, unsigned char *uri, long urilen,
	     unsigned char *body, long bodylen, void *c)
{
   xbuffer xb;

   xbuffer_alloc(&xb);

   if (!xbuffer_append_str(&xb, "uri: ") ||
       !xbuffer_append(&xb, uri, urilen) ||
       !xbuffer_append_str(&xb, "<br>body:") ||
       !xbuffer_append(&xb, body, bodylen) ||
       !xbuffer_append_str(&xb, "\015\012")) {
      xbuffer_free(&xb);
      log_fatal("wwwtest", "appending to www reply");
   }

   www_reply(fd, vers, 200, "OK", "text/plain", xb.buf, xb.len);

   xbuffer_free(&xb);
}

int main(int argc, char *argv[])
{
   if (!mp_init())
      log_fatal("main", "failed initializing multiplexor");

   www_init("", 8888, wwwtest, NULL);
   www_init("", 9999, wwwtest, NULL);

   printf("wwwtest server started\n");

   if (!mp_go())
      log_fatal("main", "error in multiplexor main loop");
      

   exit(0);
}
