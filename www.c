const char rcsid_www_c[] = "$Id: www.c,v 1.9 2003/02/07 01:01:21 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "multiplex.h"
#include "util.h"
#include "www.h"
#include "globals.h"
#include "parse.h"
#include "pks_www.h"

#ifdef HAVE_LIBWRAP
	#include <tcpd.h>
	#include <syslog.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#define TCPDSERVICE "pksd"
	int allow_severity=LOG_WARNING ;
	int deny_severity=LOG_WARNING ;
	char *yp_get_default_domain=""  ;
	extern int hosts_ctl(char *daemon,
		char *client_name, char *client_addr,char *client_user) ;


#endif
	
static const long hexchar[] = {
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
     0, -1, -2, -3, -4, -5, -6, -7, -8, -9,256,256,256,256,256,256,

   256,-10,-11,-12,-13,-14,-15,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,-10,-11,-12,-13,-14,-15,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,

   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,

   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
   256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,
};

int www_urldecode(unsigned char *str, long *len)
{
   long ptr, i, tmp;

   for (i=0, ptr=0; i<*len; i++, ptr++) {
      if (str[i] == '%') {
	 if (i+2 >= *len)
	    return(0);
	 if ((tmp = hexchar[str[i+1]]*16+hexchar[str[i+2]]) > 0)
	    return(0);
	 str[ptr] = -tmp;
	 i+=2;
      } else if (str[i] == '+') {
	 str[ptr] = ' ';
      } else {
	 str[ptr] = str[i];
      }
   }

   *len = ptr;

   return(1);
}

static const char content_length[] = "content-length:";
static int content_length_len = sizeof(content_length)-1;

static const char get[] = "get";
static int get_len = sizeof(get)-1;

static const char post[] = "post";
static int post_len = sizeof(post)-1;

static void writer(int fd, unsigned char *output, long len, void *c)
{
   xbuffer_free((xbuffer *) c);
   free(c);
}

void www_reply(int fd, int vers, int status_code, const char *reason_phrase,
	       const char *content_type,
	       const unsigned char *reply, long replylen)
{
   xbuffer *xb;
   char num[20];

   if(content_type==NULL)
     content_type="text/html";

   if ((xb = (xbuffer *) malloc(sizeof(xbuffer))) == NULL)
      log_fatal("www_reply", "failed allocating memory for xbuffer");

   xbuffer_alloc(xb);

   if (vers < 1000) {
      if (!xbuffer_append(xb, reply, replylen)) {
	 xbuffer_free(xb);
	 log_fatal("www_reply", "failed constructing www 0.9 reply");
      }
   } else {
      sprintf(num, "%d ", status_code);

      if (!xbuffer_append_str(xb, "HTTP/1.0 ") ||
	  !xbuffer_append_str(xb, num) ||
	  !xbuffer_append_str(xb, reason_phrase) ||
	  !xbuffer_append_str(xb, "\015\012") ||
	  !xbuffer_append_str(xb, "Server: pks_www/" PKS_VERSION "\015\012") ||
	  !xbuffer_append_str(xb, "Content-type: ") ||
	  !xbuffer_append_str(xb, content_type) ||
	  !xbuffer_append_str(xb, "\015\012") ||
	  !xbuffer_append_str(xb, "\015\012")) {
	 xbuffer_free(xb);
	 log_fatal("www_reply", "failed constructing www reply header");
      }

      if ((status_code/100) == 4) {
	 if (!xbuffer_append_str(xb, "<HEAD><TITLE>") ||
	     !xbuffer_append_str(xb, num) ||
	     !xbuffer_append_str(xb, reason_phrase) ||
	     !xbuffer_append_str(xb, "</TITLE></HEAD><BODY>") ||
	     !xbuffer_append(xb, reply, replylen) ||
	     !xbuffer_append_str(xb, "</BODY>\015\012")) {
	    xbuffer_free(xb);
	    log_fatal("www_reply", "failed constructing www error reply");
	 }
      } else {
	 if (!xbuffer_append(xb, reply, replylen)) {
	    xbuffer_free(xb);
	    log_fatal("www_reply", "failed constructing www success reply");
	 }
      }
   }

   if (!mp_add_write(fd, 1, xb->buf, xb->len, &writer, (void *) xb))
      log_fatal("www_reply", "failed adding new output stream");
}

static const char bad_request[] = "Bad Request";

typedef struct _hh_state {
   httphandler h;
   xbuffer xb;
  unsigned int readonly;
   void *c;
   long ptr;
   long method, uri, method_len, uri_len;
   long content_length, body;
} hh_state;

static void reader(int fd, unsigned char *input, long len, int done, void *c)
{

   hh_state *s = (hh_state *) c;
   long ptr, cnt;
   long dummy, dummy_len;
   unsigned int readonly = s->readonly;


   if (done < 0) {
      xbuffer_free(&(s->xb));
      free(s);
      return;
   }

   if (!xbuffer_append(&(s->xb), input, len))
      log_fatal("reader [www]", "failed appending to www request buffer");

   input = s->xb.buf;
   len = s->xb.len;

   if (!len) {
      if (done == 0)
	 return;

      /* if there's no input at end of file, that's an error */

      www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
      mp_delete_read(fd);
      xbuffer_free(&(s->xb));
      free(s);
      return;
   }
      
   /*** parse an HTML request */

   if (s->uri < 0) {
      scan_token(input, len, &(s->ptr), &(s->method), &(s->method_len));
      scan_space(input, len, &(s->ptr));

      scan_token(input, len, &(s->ptr), &(s->uri), &(s->uri_len));
      scan_space(input, len, &(s->ptr));

      cnt = scan_line(input, len, &(s->ptr), &dummy, &dummy_len);

      /* if the first line isn't complete, and the stream has
	 not ended, reset for next time */
      if ((dummy_len == 0) && (done == 0)) {
	 s->ptr = 0;
	 s->method = -1;
	 s->uri = -1;

	 return;
      }

      /* the first line is done (either because it is, or because
	 the input stream ended).
	 if there's no method or no uri, that's an error */
      if ((s->method == -1) || (s->uri == -1)) {
	 www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
	 mp_delete_read(fd);
	 xbuffer_free(&(s->xb));
	 free(s);
	 return;
      }

      /* if there's nothing else on the first line, it's an 0.9 request */
      if (cnt == 0) {
	 s->body = 0;
	 s->content_length = 0;
	 /* fall all the way through to the request parser/handler */
      }
 
      /* the first line is now dealt with.  the next block deals with the
	 headers, if any */
   }

   if (s->body < 0) {
      /* Scan headers, store away content-length, stop after blank line */

      while (1) {
	 cnt = scan_line(input, len, &(s->ptr), &dummy, &dummy_len);

	 /* check for complete line */

	 if (dummy_len) {
	    /* if blank, go on to scan for body */
	    if (cnt == 0)
	       break;

	    /* if non-blank, check for useful headers */
	    if (is_token(input+dummy, cnt,
			 content_length, content_length_len, 0))
	       s->content_length =
		  atol((char *) input+dummy+content_length_len);

	    continue;
	 }

	 /* incomplete line, input is ended for now.  return and try again
	       when there's more data */

	 if (done == 0)
	    return;

	 /* incomplete line, input stream has reached eof mid-headers.
	    this is an error */

	 www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
	 mp_delete_read(fd);
	 xbuffer_free(&(s->xb));
	 free(s);
	 return;
      }

      if (s->content_length) {
	 /* find first non-blank line */

	 while (1) {
	    cnt = scan_line(input, len, &(s->ptr), &(s->body), &dummy_len);

	    /* if there is non-blankness at the beginning of the line,
	       this is the beginning of the body */

	    if (cnt) {
	       /* s->body not set above if the line is incomplete */
	       if (!dummy_len)
		  s->body = s->ptr;

	       break;
	    }

	    /* if this is a blank line, go on to the next one */

	    if (dummy_len)
	       continue;

	    /* the end of input has been reached for now and there's
	       nothing interesting.  back up one char so that the
	       next call to reader() sees a blank line, and try again
	       when there's more data */

	    if (done == 0) {
	       s->ptr--;
	       return;
	    }

	    /* the input stream got eof before the body started.
	       this is an error */

	    www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
	    mp_delete_read(fd);
	    xbuffer_free(&(s->xb));
	    free(s);
	    return;
	 }
      }

      /* when this point is passed, s->body is set above to the
	 first line of the body.  Thus, this block will never be
	 entered again */
   }

   if (s->content_length) {
      if ((len - s->body) < s->content_length) {
	 /* if there's not enough data, try again when there's more */
	 if (done == 0)
	    return;

	 /* if the input stream has ended, and there's not enough
	    body, that's an error */

	 www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
	 mp_delete_read(fd);
	 xbuffer_free(&(s->xb));
	 free(s);
	 return;
      }
   }

   {
      char buf[1024];

      sprintf(buf, "request received: %.*s%s %.*s%s",
	      (int) ((s->method_len<=50)?s->method_len:50), input+s->method,
	      (s->method_len<=50)?"":" (truncated)",
	      (int) ((s->uri_len<=850)?s->uri_len:850), input+s->uri,
	      (s->uri_len<=850)?"":" (truncated)");

      log_info("reader [www]", buf);
   }
	      

   /* handle the request */

   if (is_token(input+s->method, s->method_len, get, get_len, 0)) {
      if (s->content_length > 0) {
	 www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
	 mp_delete_read(fd);
	 xbuffer_free(&(s->xb));
	 free(s);
	 return;
      } else {
	 s->body = 0;

	 ptr = scan_char(input+s->uri, s->uri_len, &(s->body), '?',
			 &dummy, &dummy_len);

	 if (ptr < s->uri_len) {
	    s->content_length = s->uri_len - s->body;
	    s->uri_len = ptr;

	    s->body += s->uri;
	 }
      }
   } else if (is_token(input+s->method, s->method_len, post, post_len, 0)) {
      if ((s->content_length == 0) || readonly) {
	 www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
	 mp_delete_read(fd);
	 xbuffer_free(&(s->xb));
	 free(s);
	 return;
      }
   } else {
      www_reply(fd, 1000, 400, bad_request, NULL, NULL, 0);
      mp_delete_read(fd);
      xbuffer_free(&(s->xb));
      free(s);
      return;
   }

   if (s->content_length == 0) {
      (*(s->h))(fd, 1000, input+s->uri, s->uri_len, NULL, 0, s->c);
   } else {
      (*(s->h))(fd, 1000, input+s->uri, s->uri_len,
		input+s->body, s->content_length, s->c);
   }

   mp_delete_read(fd);
   xbuffer_free(&(s->xb));
   free(s);
}

static void listener(int fd, unsigned char *input, long len, int done, void *c)
{
   hh_state *s = (hh_state *) c;
   hh_state *hhs;

   struct sockaddr_in sin;
#ifdef HAVE_SOCKLEN_T
   socklen_t sinlen;
#else
   int sinlen;
#endif
   int srv;
   unsigned long addr;
   char buf[1024];

#ifdef HAVE_LIBWRAP 
	char *ip ;
	char message[1024] ;
	struct hostent *jostia ;
	char strtmp[256] ;
#endif

   sinlen = sizeof(sin);

   if ((srv = accept(fd, (struct sockaddr *) &sin, &sinlen)) < 0) {
      sprintf(buf, "error accepting new www connection: errno = %d", errno);
     switch (errno) {
#ifdef ECONNABORTED
     /* This happens on Solaris and FreeBSD. */
     case ECONNABORTED:
#endif
#ifdef EINTR
     case EINTR:
#endif
#ifdef EPROTO
     /* This happens on Solaris, but it's transient. */
     case EPROTO:
#endif
#if defined(ECONNABORTED) || defined (EINTR) || defined(EPROTO)
       /* Logging an error and returning allows the daemon to recover. */
       log_error("listener", buf);
       return;
       break;
#endif
     default:
       log_fatal("listener", buf);
       break;
     } /* switch errno */
   } /* if accept failed */

#ifdef HAVE_LIBWRAP 
	/* Host allow control */
	ip=inet_ntoa(sin.sin_addr) ;
	/* We need to check that the IP HAS reverse IP resolution */
	if ((jostia=gethostbyaddr ((char *)&(sin.sin_addr),
				sizeof(sin.sin_addr), AF_INET))!= NULL) 
	{ strncpy ( strtmp, jostia->h_name,255) ; }
       	else { strncpy ( strtmp, "",255) ; }
	
	if (!hosts_ctl(TCPDSERVICE, strtmp , ip, STRING_UNKNOWN)) {
		/* Not allowed to connect */
		snprintf (message,1023,
		"pksd: host %s/%s not allowed to connect to this server",
			strtmp, ip) ;
		log_error("listener", message) ;
		close (srv) ;
		return ;
		}
	/* host allowed to connect */
	snprintf(message, 1023,"pksd: host %s/%s connected", strtmp,ip) ;
	log_error("listener",message) ;
#endif
   if (fcntl(srv, F_SETFD, 1) < 0) {
      sprintf(buf, "failed making http connection close-on-exec: %d", errno);
      log_fatal("www_init", buf);
   }

   addr = ntohl(sin.sin_addr.s_addr);

   sprintf(buf, "new www connection from %d.%d.%d.%d",
	   (int) (addr>>24)&0xff, (int) (addr>>16)&0xff, 
	   (int) (addr>>8)&0xff, (int) addr&0xff);

   log_info("listener [www]", buf);

   if ((hhs = (hh_state *) malloc(sizeof(hh_state))) == NULL)
      log_fatal("listener", "failed allocating memory for hh_state");

   *hhs = *s;

   if (!mp_add_read(srv, 1, &reader, (void *) hhs))
      log_fatal("listener", "failed adding new input stream");
}

void www_init(char *addr, int port, httphandler h, void *c)
{
   int s;
   struct sockaddr_in sin;
   char buf[1024];
   hh_state *hhs;
   int one = 1;

   if ((hhs = (hh_state *) malloc(sizeof(hh_state))) == NULL)
      log_fatal("www_init", "failed allocating memory for hh_state");

   if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
      sprintf(buf, "failed creating www socket: %d", errno);
      log_fatal("www_init", buf);
   }

   if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		  (char *) &one, sizeof(one)) < 0) {
      sprintf(buf, "failed setting SO_REUSEADDR on www socket: %d", errno);
      log_fatal("www_init", buf);
   }

   if (fcntl(s, F_SETFD, 1) < 0) {
      sprintf(buf, "failed making www socket close-on-exec: %d", errno);
      log_fatal("www_init", buf);
   }

   sin.sin_family = AF_INET;
   sin.sin_port = htons(port);
   if (addr != NULL && addr[0] != 0) {
      sin.sin_addr.s_addr = inet_addr(addr);
   } else {
      sin.sin_addr.s_addr = htonl(INADDR_ANY);
   }

   if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
      sprintf(buf, "failed binding www socket to port %d: %d", port, errno);
      log_fatal("www_init", buf);
   }

   if (listen(s, 5) < 0) {
      sprintf(buf, "failed listening on www socket: %d", errno);
      log_fatal("www_init", buf);
   }

   hhs->h = h;
   hhs->c = c;
   hhs->readonly = ((pks_www_conf *)c)->readonly;
   xbuffer_alloc(&(hhs->xb));
   hhs->ptr = 0;
   hhs->uri = -1;
   hhs->body = -1;
   hhs->content_length = 0;

   if (!mp_add_listen(s, 0, &listener, (void *) hhs))
      log_fatal("www_init", "failed adding new listener for www");
}
