const char rcsid_util_c[] = "$Id: util.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#ifdef HAVE_MMAP
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#include "util.h"

const unsigned char zeros[1024]; /* globals are initialized to zero */

void xbuffer_alloc(xbuffer *xb)
{
   xb->alloclen = 0;
   xb->len = 0;
   xb->buf = NULL;
}

void xbuffer_free(xbuffer *xb)
{
   if (xb->buf) {
      free(xb->buf);
      xb->alloclen = 0;
      xb->len = 0;
      xb->buf = NULL;
   }
}

int xbuffer_append(xbuffer *xb, const unsigned char *data, long len)
{
   if (len == 0)
      return(1);

   if (xb->alloclen < (xb->len + len)) {
      if (xb->alloclen == 0) {
	 xb->alloclen = (len > 512)?len:512;

	 if ((xb->buf = (unsigned char *) malloc(xb->alloclen)) == NULL)
	    return(0);
      } else {
	 unsigned char *tmp;

	 xb->alloclen = (((xb->alloclen*3/2) > (xb->alloclen + len))?
			 xb->alloclen*3/2 : xb->alloclen+len);

	 if ((tmp = (unsigned char *) realloc(xb->buf, xb->alloclen)) == NULL)
	    return(0);

	 xb->buf = tmp;
      }
   }

   memcpy((void *) (xb->buf+xb->len), (const void *) data, (size_t) len);

   xb->len += len;

   return(1);
}

int xbuffer_append_str(xbuffer *xb, const char *data)
{
   return(xbuffer_append(xb, (unsigned char *) data,
			 (long) strlen(data)));
}

int xfilecontents_get(xfilecontents *xfc, FILE *f)
{
#ifdef HAVE_MMAP
   int fd;
   struct stat fst;
#endif
   unsigned char buf[1024];
   int cnt;

   xbuffer_alloc(&(xfc->xb));

#ifdef HAVE_MMAP
   fd = fileno(f);

   if (fstat(fd, &fst))
      return(0);

   xfc->len = fst.st_size;

   xfc->buf = (unsigned char *) mmap(0, xfc->len, PROT_READ, MAP_SHARED,
				     fd, 0);

   if (xfc->buf != ((void *) -1)) {
      xfc->mmapped = 1;

#if defined(HAVE_MADVISE) && defined(MADV_SEQUENTIAL)
      madvise((char *) xfc->buf, xfc->len, MADV_SEQUENTIAL);
      /* ignore the error.  some systems don't support all the kinds of
	 advice, and there's nothing to do, anyway. */
#endif

      return(1);
   }

   if ((errno != ENODEV) && (errno != EINVAL)) {
      xbuffer_free(&(xfc->xb));
      return(0);
   }
#endif

   while(!feof(f)) {
      cnt = fread((void *) buf, 1, sizeof(buf), f);

      if (cnt)
	 if (!xbuffer_append(&(xfc->xb), buf, cnt)) {
	    xbuffer_free(&(xfc->xb));
	    return(0);
	 }

      if (cnt < 1024)
	 break;
   }
	 
   if (ferror(f)) {
      xbuffer_free(&(xfc->xb));
      return(0);
   }

   xfc->len = xfc->xb.len;
   xfc->buf = xfc->xb.buf;

#if HAVE_MMAP
   xfc->mmapped = 0;
#endif
   return(1);
}

void xfilecontents_free(xfilecontents *xfc)
{
#ifdef HAVE_MMAP
   if (xfc->mmapped)
      munmap((char *) xfc->buf, xfc->len);
#endif
   xbuffer_free(&(xfc->xb));
}

char *my_strdup(const char *s)
{
   char *ns;

   if ((ns = (char *) malloc(strlen(s)+1)) == NULL)
      return(NULL);

   strcpy(ns, s);

   return(ns);
}

int my_strncasecmp(const char *s1, const char *s2, int n)
{
   int tmp;

   for (; n && *s1 && *s2; n--, s1++, s2++) {
      if (*s1 == *s2)
	 continue;
      if ((tmp = (tolower(*s1) - tolower(*s2))) != 0)
	 return(tmp);
   }

   return(0);
}

void *my_memmem(const void *mem, const void *s, size_t memn, size_t mems)
{
   const char *cmem = (const char *) mem;
   const char *cs = (const char *) s;

   char *cptr;

   for (cptr = (char *) memchr(mem, (int) cs[0], memn);
	cptr;
	cptr = (char *) memchr(((void *) (cptr+1)), (int) cs[0],
			       memn - (cptr+1 - cmem))) {
      if ((memn - (cptr - cmem)) < mems)
	 return(NULL);
      if (memcmp(cptr, cs, mems) == 0)
	 break;
   }

   return((void *) cptr);
}

void *my_memcasemem(const void *mem, const void *s, size_t memn, size_t mems)
{
   const char *cmem = (const char *) mem;
   const char *cs = (const char *) s;

   char *cptr;

   for (cptr = (char *) memchr(mem, toupper((int) cs[0]), memn);
	cptr;
	cptr = (char *) memchr(((void *) (cptr+1)), toupper((int) cs[0]),
			       memn - (cptr+1 - cmem))) {
      if ((memn - (cptr - cmem)) < mems)
	 return(NULL);
      if (my_strncasecmp(cptr, cs, mems) == 0)
	 break;
   }

   if (!cptr && isalpha((int) cs[0])) {
      for (cptr = (char *) memchr(mem, (int) tolower((int) cs[0]), memn);
	   cptr;
	   cptr = (char *) memchr(((void *) (cptr+1)), tolower((int) cs[0]),
				  memn - (cptr+1 - cmem))) {
	 if ((memn - (cptr - cmem)) < mems)
	    return(NULL);
	 if (my_strncasecmp(cptr, cs, mems) == 0)
	    break;
      }
   }

   return((void *) cptr);
}

void *my_memstr(const void *mem, const char *s, size_t n)
{
   return(my_memmem(mem, (const void *) s, n, strlen(s)));
}
