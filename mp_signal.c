const char rcsid_mp_signal_c[] = "$Id: mp_signal.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


/* this is necessary on some platforms (solaris) for sigaction()
   to work */
#define _POSIX_SOURCE

#include <sys/types.h>
#include <sys/wait.h>

#include <signal.h>
#include <stdio.h>
#include <errno.h>

#include "multiplex.h"

static void mp_wait_children()
{
   int pid;

   do {
      pid = waitpid(-1, NULL, WNOHANG);
   } while ((pid > 0) ||
	    ((pid == -1) && (errno == EINTR)));
}

int mp_ignore_signals(void)
{
   struct sigaction sa;

   sa.sa_flags = 0;
   sigemptyset(&(sa.sa_mask));

   sa.sa_handler = SIG_IGN;

   if (sigaction(SIGPIPE, &sa, NULL) < 0)
      return(0);

   /* in theory, setting SIGCHLD to SIG_IGN should work, but some OS's
      (irix, at least) are broken.  So we set a handler to call waitpid
      nonblockingly */

   sa.sa_handler = mp_wait_children;

   if (sigaction(SIGCHLD, &sa, NULL) < 0)
      return(0);

   return(1);
}
