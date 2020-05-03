const char rcsid_logging_c[] = "$Id: logging.c,v 1.2 2002/10/08 04:04:42 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <syslog.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "globals.h"
#include "database.h"

#ifndef DEBUG
#define debug 0
#endif

int log_terminal;

static char *current_time()
{
      time_t t;
      char *time_str;
      t = time(NULL);
      time_str = ctime(&t);
      time_str[strlen(time_str) -1 ]='\0';
      return time_str;
 
}

void log_debug(const char *fct, const char *msg)
{
   if (debug || log_terminal)
      fprintf(stdout, "[%s] %s: %s\n", current_time(), fct, msg);
   else
      syslog(LOG_DEBUG, "pksd: %s: %s", fct, msg);
}

void log_info(const char *fct, const char *msg)
{
   if (debug || log_terminal)
      fprintf(stderr, "[%s] %s: %s\n", current_time(), fct, msg);
   else
      syslog(LOG_INFO, "pksd: %s: %s", fct, msg);
}

void log_error(const char *fct, const char *msg)
{
   if (debug || log_terminal)
      fprintf(stderr, "[%s] %s: %s\n", current_time(), fct, msg);
   else
      syslog(LOG_ERR, "pksd: %s: %s", fct, msg);
}

void log_fatal(const char *fct, const char *msg)
{
   /* try to keep the database intact */
   kd_close();

   if (debug || log_terminal)
      fprintf(stderr, "[%s] FATAL ERROR in %s: %s\n", current_time(), fct,
	      msg);
   else
      syslog(LOG_CRIT, "pksd: %s: %s", fct, msg);

   exit(1);
}

