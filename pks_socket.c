const char rcsid_pks_socket_c[] = "$Id: pks_socket.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "pks_socket.h"
#include "mail_send.h"
#include "mail_req.h"
#include "multiplex.h"
#include "util.h"
#include "parse.h"
#include "globals.h"
#include "database.h"

static char mail_str[] = "mail";
static int mail_len = sizeof(mail_str)-1;

static char disable_str[] = "disable";
static int disable_len = sizeof(disable_str)-1;

#if 0
static char backup_str[] = "backup";
static int backup_len = sizeof(backup_str)-1;
#endif

static char shutdown_str[] = "shutdown";
static int shutdown_len = sizeof(shutdown_str)-1;

static char done_str[] = "done";
static int done_len = sizeof(done_str)-1;

void del_file(int error, void *c)
{
   char *fn = (char *) c;

   if (! error) {
      if (unlink(fn) < 0) {
	 char buf[1024];

	 sprintf(buf, "failed deleting mail file %s", fn);

	 log_error("del_file", buf);
      }
   }

   free(fn);
}

typedef struct _ps_state {
   xbuffer xb;
   pks_socket_conf *pfc;
} ps_state;

static void pks_socket(int fd, unsigned char *input, long len,
		       int done, void *c)
{
   ps_state *s = (ps_state *) c;
   long lptr, cptr, cnt, line, line_len;
   long cmd, cmd_len;
   xbuffer tmp;

   if (done < 0) {
      xbuffer_free(&(s->xb));
      free(s);
      return;
   }

   xbuffer_alloc(&tmp);

   if (!xbuffer_append(&tmp, s->xb.buf, s->xb.len) ||
       !xbuffer_append(&tmp, input, len))
      log_fatal("pks_socket", "failure appending new socket input");

   xbuffer_free(&(s->xb));

   input = tmp.buf;
   len = tmp.len;

   for (lptr = 0;
	cnt = scan_line(input, len, &lptr, &line, &line_len),
	cnt || (lptr < len);
	) {
      line_len = cnt;
      if (line < 0) {
	 if (done == 0) {
	    /* incomplete line.  stash it and return */
	    xbuffer_append(&(s->xb), input+lptr, cnt);
	    xbuffer_free(&tmp);
	    return;
	 } else {
	    line = lptr;
	    lptr += cnt;
	 }
      }

      cptr = 0;

      scan_space(input+line, line_len, &cptr);
      scan_token(input+line, line_len, &cptr, &cmd, &cmd_len);
      scan_space(input+line, line_len, &cptr);

      cmd += line;

      if (is_token(input+cmd, cmd_len, mail_str, mail_len, 1)) {
	 long file, file_len;
	 char buf[1024];
	 char *fn;
	 FILE *f;
	 xfilecontents xfc;

	 scan_token(input+line, line_len, &cptr, &file, &file_len);

	 file += cmd;

	 if ((fn = (char *) malloc(file_len+1)) == NULL)
	    log_fatal("reader [pks_info]",
		      "failed allocating memory for file name");

	 sprintf(fn, "%.*s", (int) file_len, input+file);

	 if ((f = fopen(fn, "r")) == NULL) {
	    sprintf(buf, "error opening mail file %s: errno = %d",
		    fn, errno);
	    log_error("pks_socket", buf);

	    continue;
	 }

	 if (!xfilecontents_get(&xfc, f)) {
	    sprintf(buf, "error reading mail file %s", fn);
	    log_error("pks_socket", buf);
	    fclose(f);

	    continue;
	 }

	 fclose(f);

	 mail_req(xfc.buf, xfc.len, s->pfc->mrc, del_file, fn);

	 xfilecontents_free(&xfc);
      } else if (is_token(input+cmd, cmd_len, disable_str, disable_len, 1)) {
	 unsigned char *ret;
	 long retlen;

	 /* XXX this ignores any return or error.  Until I change
	    pksdctl to deal with responses, this can't change */

	 kd_disable(input+line+cptr, line_len-cptr, 0, &ret, &retlen);

	 if (ret && retlen)
	    free(ret);
#if 0
      } else if (is_token(input+cmd, cmd_len, backup_str, backup_len, 1)) {
	 kd_backup();
#endif
      } else if (is_token(input+cmd, cmd_len, shutdown_str,
			  shutdown_len, 1)) {
	 mp_terminate(EXIT_SHUTDOWN);
      } else if (is_token(input+cmd, cmd_len, done_str, done_len, 1)) {
	 /* this is a necessary evil, since some platforms (hpux
	    is what bit me) don't see eof on a unix domain socket when
	    the peer calls shutdown(s, 1) */
	 xbuffer_free(&tmp);

	 mp_delete_read(fd);
	 free(s);
	 return;
      } else {
	 char buf[1024];

	 sprintf(buf, "unknown socket command \"%.*s\"",
		 (int) line_len, input+line);
	 log_error("pks_socket", buf);
      }
   }

   xbuffer_free(&tmp);

   if (done > 0) {
      mp_delete_read(fd);
      free(s);
   }
}

static void pks_socket_listener(int fd, unsigned char *input, long len,
			      int done, void *c)
{
   ps_state *s = (ps_state *) c;
   ps_state *pss;
   char buf[1024];

   struct sockaddr_un s_un;
#ifdef HAVE_SOCKLEN_T
   socklen_t sunlen;
#else
   int sunlen;
#endif
   int srv;

   sunlen = sizeof(s_un);

   if ((srv = accept(fd, (struct sockaddr *) &s_un, &sunlen)) < 0) {
      sprintf(buf,
	      "error accepting new control socket connection: errno = %d",
	      errno);
      log_fatal("pks_socket_listener", buf);
   }

   if (fcntl(srv, F_SETFD, 1) < 0) {
      sprintf(buf, "failed making socket close-on-exec: %d", errno);
      log_fatal("pks_socket_listener", buf);
   }

   if ((pss = (ps_state *) malloc(sizeof(ps_state))) == NULL)
      log_fatal("pks_socket_listener",
		"failed allocating memory for ps_state");

   *pss = *s;

   if (!mp_add_read(srv, 1, &pks_socket, (void *) pss))
      log_fatal("pks_socket_listener", "failed adding new input stream");
}

void pks_socket_init(pks_socket_conf *pfc)
{
   int s;
   struct sockaddr_un s_un;
   char buf[1024];
   ps_state *pss;

   if ((pss = (ps_state *) malloc(sizeof(ps_state))) == NULL)
      log_fatal("pks_socket_init", "failed allocating ps_state");

   if (sizeof(s_un.sun_path) < (sizeof(pfc->socket)+1))
      log_fatal("pks_socket_init",
		"socket name length doesn't fit in sockaddr_un");

   xbuffer_alloc(&(pss->xb));
   pss->pfc = pfc;

   if ((unlink(pfc->socket) < 0) && (errno != ENOENT)) {
      sprintf(buf, "failed removing old socket: %d", errno);
      log_fatal("pks_socket_init", buf);
   }

   if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
      sprintf(buf, "failed creating control socket: %d", errno);
      log_fatal("pks_socket_init", buf);
   }

   if (fcntl(s, F_SETFD, 1) < 0) {
      sprintf(buf, "failed making control socket close-on-exec: %d", errno);
      log_fatal("pks_socket_init", buf);
   }

   memset(&s_un, '\0', sizeof(s_un));

   s_un.sun_family = AF_UNIX;
   strcpy(s_un.sun_path, pfc->socket);

   if (bind(s, (struct sockaddr *) &s_un, sizeof(s_un)) < 0) {
      sprintf(buf, "failed binding control socket: %d", errno);
      log_fatal("pks_socket_init", buf);
   }

   if (listen(s, 5) < 0) {
      sprintf(buf, "failed listening on control socket: %d", errno);
      log_fatal("pks_socket_init", buf);
   }

   if (!mp_add_listen(s, 0, &pks_socket_listener, (void *) pss))
      log_fatal("pks_socket_init", "error adding new listener for socket");
}
