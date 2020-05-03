const char rcsid_kd_signal_c[] = "$Id: kd_signal.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


/* this is necessary on some platforms (solaris) for sigaction()
   to work */
#define _POSIX_SOURCE
#include <signal.h>
#include <stdio.h>

#include "globals.h"
#include "database.h"
#include "multiplex.h"

void kd_sig_handler()
{
   mp_terminate(EXIT_SIGNAL);
}

int kd_install_sig_handler(void (*h)())
{
   struct sigaction sa;
   
   sa.sa_flags = 0;
   sigemptyset(&(sa.sa_mask));
   sa.sa_handler = h;

   if (sigaction(SIGINT, &sa, NULL) < 0)
      return(0);

   if (sigaction(SIGTERM, &sa, NULL) < 0)
      return(0);

   if (sigaction(SIGHUP, &sa, NULL) < 0)
      return(0);

   if (sigaction(SIGQUIT, &sa, NULL) < 0)
      return(0);

   return(1);
}
