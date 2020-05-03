const char rcsid_multiplex_c[] = "$Id: multiplex.c,v 1.5 2003/01/18 02:07:22 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <errno.h>
#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#include "util.h"
#include "multiplex.h"

#ifdef EINTR
#define INTR1(e) ((e) == EINTR)
#else
#define INTR1(e) (0)
#endif

#ifdef EAGAIN
#define INTR2(e) ((e) == EAGAIN)
#else
#define INTR2(e) (0)
#endif

#define INTR(e) (INTR1((e)) || INTR2((e)))

typedef struct _ifd_desc {
   int fd;
   int valid;
   int listener;
   int lasttime;
   mp_input_handler h;
   void *c;
} ifd_desc;

typedef struct _ofd_desc {
   int fd;
   int valid;
   int lasttime;
   unsigned char *output;
   long len, offset;
   mp_output_handler h;
   void *c;
} ofd_desc;

long nfds;
fd_set ifds;
fd_set ofds;

int mp_count;
int mp_exit;

static ifd_desc **ifd = NULL;
static ofd_desc **ofd = NULL;

int mp_init()
{
   int i;

/* XXXX I might want to call getdtablesize under some condition, but I don't
   know what, right now */

#ifdef _SC_OPEN_MAX
   nfds = sysconf(_SC_OPEN_MAX);
#else
   nfds = NOFILE;
#endif

   if (nfds > FD_SETSIZE)
      nfds = FD_SETSIZE;

   FD_ZERO(&ifds);
   FD_ZERO(&ofds);
   mp_count = 0;
   mp_exit = 0;

   if ((ifd = (ifd_desc **) malloc(nfds*sizeof(ifd_desc *))) == NULL)
      return(0);

   if ((ofd = (ofd_desc **) malloc(nfds*sizeof(ofd_desc *))) == NULL) {
      free(ifd);
      ifd = NULL;
      return(0);
   }

   for (i=0; i<nfds; i++) {
      ifd[i] = NULL;
      ofd[i] = NULL;
   }

   return(1);
}

void mp_terminate(int code)
{
   mp_exit = code;
}

int mp_add_read(int fd, int expire, mp_input_handler ih, void *c)
{
   int n;

   /* make sure that the same fd isn't being added again */

   if (ifd[fd] && ifd[fd]->valid)
      return(0);

   /* malloc and fill in the descriptor structure */

   if (ifd[fd] == NULL)
      if ((ifd[fd] = (ifd_desc *) malloc(sizeof(ifd_desc))) == NULL)
	 return(0);

   ifd[fd]->fd = fd;
   ifd[fd]->valid = 1;
   ifd[fd]->listener = 0;
   ifd[fd]->lasttime = expire ? time(NULL) : 0;
   ifd[fd]->h = ih;
   ifd[fd]->c = c;

   /* make the fd non-blocking, just in case */

   n = fcntl (fd, F_GETFL);
   if (n >= 0) {
      n |= O_NONBLOCK;
      fcntl (fd, F_SETFL, n);
   }

   /* add the fd to the input fd_set */

   FD_SET(fd, &ifds);
   mp_count++;

   return(1);
}

int mp_add_listen(int fd, int expire, mp_input_handler ih, void *c)
{
   /* make sure that the same fd isn't being added again */

   if (ifd[fd] && ifd[fd]->valid)
      return(0);

   /* malloc and fill in the descriptor structure */

   if (ifd[fd] == NULL)
      if ((ifd[fd] = (ifd_desc *) malloc(sizeof(ifd_desc))) == NULL)
	 return(0);

   ifd[fd]->fd = fd;
   ifd[fd]->valid = 1;
   ifd[fd]->listener = 1;
   ifd[fd]->lasttime = expire ? time(NULL) : 0;
   ifd[fd]->h = ih;
   ifd[fd]->c = c;

   /* add the fd to the input fd_set */

   FD_SET(fd, &ifds);
   mp_count++;

   return(1);
}

void mp_delete_read(int fd)
{
   if (ifd[fd] && ifd[fd]->valid) {
      FD_CLR(ifd[fd]->fd, &ifds);
      mp_count--;

      ifd[fd]->valid = 0;
   }
}

static void mp_read(ifd_desc *ifd)
{
   unsigned char buf[1024];
   int cc;

   /* just call the handler for a listener */

   if (ifd->listener) {
      (*(ifd->h))(ifd->fd, NULL, 0, 1, ifd->c);
      return;
   }

   /* otherwise, read from the fd and deal */

   cc = read(ifd->fd, (void *) buf, sizeof(buf));

   if (cc > 0) {
      (*(ifd->h))(ifd->fd, buf, cc, 0, ifd->c);
   } else if (cc == 0) {
      (*(ifd->h))(ifd->fd, NULL, 0, 1, ifd->c);
   } else {
      /* if interrupted, just return.  it will be readable again
	 next time */
      if ((cc < 0) && (INTR(errno)))
	 return;

      (*(ifd->h))(ifd->fd, NULL, 0, -1, ifd->c);
      mp_delete_read(ifd->fd);

      if (ofd[ifd->fd] && ofd[ifd->fd]->valid) {
	 (*(ofd[ifd->fd]->h))(ifd->fd,
			      ofd[ifd->fd]->output, -1, ofd[ifd->fd]->c);
	 mp_delete_write(ifd->fd);
      }
   }

   /* check if the fd should be cleaned up */

   if ((!ifd->valid) &&
       (!(ofd[ifd->fd] && ofd[ifd->fd]->valid)))
      close(ifd->fd);

   return;
}

int mp_add_write(int fd, int expire, unsigned char *output, long len,
		 mp_output_handler oh, void *c)
{
   int n;

   /* make sure that the same fd isn't being added again */

   if (ofd[fd] && ofd[fd]->valid)
      return(0);

   /* malloc and fill in the descriptor structure */

   if (ofd[fd] == NULL)
      if ((ofd[fd] = (ofd_desc *) malloc(sizeof(ofd_desc))) == NULL)
	 return(0);

   ofd[fd]->fd = fd;
   ofd[fd]->valid = 1;
   ofd[fd]->lasttime = expire ? time(NULL) : 0;
   ofd[fd]->output = output;
   ofd[fd]->len = len;
   ofd[fd]->offset = 0;
   ofd[fd]->h = oh;
   ofd[fd]->c = c;

   /* make the fd non-blocking, just in case */

   n = fcntl (fd, F_GETFL);
   if (n >= 0) {
      n |= O_NONBLOCK;
      fcntl (fd, F_SETFL, n);
   }

   /* add the fd to the output fd_set */

   FD_SET(fd, &ofds);
   mp_count++;

   return(1);
}

void mp_delete_write(int fd)
{
   if (ofd[fd] && ofd[fd]->valid) {
      FD_CLR(ofd[fd]->fd, &ofds);
      mp_count--;

      ofd[fd]->valid = 0;
   }
}

static void mp_write(ofd_desc *ofd)
{
   int cc;

   cc = write(ofd->fd,ofd->output+ofd->offset,ofd->len-ofd->offset);

   if (cc > 0) {
      /* increment the offset */

      ofd->offset += cc;

      if (ofd->offset == ofd->len) {
	 (*(ofd->h))(ofd->fd, ofd->output, 1, ofd->c);
	 mp_delete_write(ofd->fd);
      }
   } else {
      /* if interrupted, just return.  it will be writeable again
	 next time */
      if (INTR(errno))
	  return;

      (*(ofd->h))(ofd->fd, ofd->output, -1, ofd->c);
      mp_delete_write(ofd->fd);

      if (ifd[ofd->fd] && ifd[ofd->fd]->valid) {
	 (*(ifd[ofd->fd]->h))(ofd->fd, NULL, 0, -1, ifd[ofd->fd]->c);
	 mp_delete_read(ofd->fd);
      }
   }

   /* check if the fd should be cleaned up */

   if ((!(ifd[ofd->fd] && ifd[ofd->fd]->valid)) &&
       (!ofd->valid))
      close(ofd->fd);

   return;
}

int mp_go()
{
   int ret, fd, tsel;
   fd_set r, w;
   struct timeval timeout, t;

   timeout.tv_sec = 60;
   timeout.tv_usec = 0;

   while (mp_count && !mp_exit) {
      r = ifds;
      w = ofds;
      t = timeout;
      tsel = time(NULL);

      ret = select(nfds, &r, &w, NULL, &t);

      if (ret < 0) {
	 if (INTR(errno))
	    continue;
	 return(0);
      }

      for (fd=0; fd<nfds; fd++) {
	 if (ofd[fd] && ofd[fd]->valid && FD_ISSET(fd, &w)) {
	    mp_write(ofd[fd]);
	    if (ofd[fd]->lasttime)
	       ofd[fd]->lasttime = time(NULL);
	 }

	 if (ifd[fd] && ifd[fd]->valid && FD_ISSET(fd, &r)) {
	    mp_read(ifd[fd]);
	    if (ifd[fd]->lasttime)
	       ifd[fd]->lasttime = time(NULL);
	 }

	 if ((ofd[fd] && ofd[fd]->valid && ofd[fd]->lasttime &&
	      ofd[fd]->lasttime < tsel - 300) ||
	     (ifd[fd] && ifd[fd]->valid && ifd[fd]->lasttime &&
	      ifd[fd]->lasttime < tsel - 300)) {
	    if (ofd[fd] && ofd[fd]->valid) {
	       (*(ofd[fd]->h))(fd, ofd[fd]->output, -1, ofd[fd]->c);
	       mp_delete_write(fd);
	    }
	    if (ifd[fd] && ifd[fd]->valid) {
	       (*(ifd[fd]->h))(fd, NULL, 0, -1, ifd[fd]->c);
	       mp_delete_read(fd);
	    }
	    close(fd);
	 }
      }
   }

   if (mp_exit)
      return(mp_exit);

   return(-1);
}
