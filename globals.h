#ifndef _GLOBALS_H_
#define _GLOBALS_H_

/*
 * $Id: globals.h,v 1.6 2003/02/07 04:31:29 rlaager Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

/* If you create a modified version of the key server, instead of
   incrementing this number, append a descriptive string, like
   "42.17.2+magicfeature", or "42.17.3+joe".  Don't remove any
   existing modifiers. */

#define PKS_VERSION "0.9.6"

#ifdef DEBUG
extern int debug;

#define dabort() if (debug) abort()
#define fail() {dabort(); else return(0); }
#else
#define dabort()
#define fail() return(0)
#endif

extern int log_terminal;

void log_debug(const char *fct, const char *msg);
void log_info(const char *fct, const char *msg);
void log_error(const  char *fct, const char *msg);
void log_fatal(const char *fct, const char *msg);

#define EXIT_SIGNAL	1
#define EXIT_SHUTDOWN	2

#endif
