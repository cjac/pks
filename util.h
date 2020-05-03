#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/types.h>
#include <stdio.h>

/*
 * $Id: util.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

typedef struct _xbuffer {
   long alloclen, len;
   unsigned char *buf;
} xbuffer;

typedef struct _xfilecontents {
/* these are "public" */
   long len;
   unsigned char *buf;
/* these are "private" */
   xbuffer xb;
#ifdef HAVE_MMAP
   int mmapped;
#endif
} xfilecontents;

extern const unsigned char zeros[];

void xbuffer_alloc(xbuffer *xb);
int xbuffer_append(xbuffer *xb, const unsigned char *data, long len);
int xbuffer_append_str(xbuffer *xb, const char *data);
void xbuffer_free(xbuffer *xb);

/* XXX easiest, certainly wrt error handling */
int xfilecontents_get(xfilecontents *xfc, FILE *f);
void xfilecontents_free(xfilecontents *xfc);

char *my_strdup(const char *s);
int my_strncasecmp(const char *s1, const char *s2, int n);
void *my_memmem(const void *mem, const void *s, size_t memn, size_t mems);
void *my_memcasemem(const void *mem, const void *s, size_t memn, size_t mems);
void *my_memstr(const void *mem, const char *s, size_t n);

#endif
