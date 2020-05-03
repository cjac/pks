const char rcsid_mail_send_c[] = "$Id: mail_send.c,v 1.2 2002/09/13 14:40:24 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "parse.h"
#include "multiplex.h"
#include "globals.h"
#include "util.h"
#include "mail_send.h"

/* all mail replies are structured like this:

   smtp headers (To, From, Subject)
   pks header (disclaimer, maintainer email, etc)
   one of the following:
	a help file
	a reply from kd_*()
	an error from kd_*()
	* the complete index file
	* the complete keyring file

   For now, we don't handle sendmail exit status, since that's
   too hairy.  We also don't handle file output, since that's
   extremely inefficient without changes to the multiplexor.

   Lines received on stdin from sendmail will be logged at LOG_INFO.
   Lines received on stderr from sendmail will be logged at LOG_ERR.
   If sendmail prints nothing to stderr, the input file will be
   deleted.

   If there is no input received, the message will be considered
   delivered, and the request file will be deleted.
*/

typedef struct _mr_read_state {
   xbuffer xb;
   long ptr;
   mail_send_cleanup msc;
   void *c;
} mr_read_state;

void log_to(int fd, unsigned char *input, long len, int eof,
	    void *c, int info)
{
   mr_read_state *s = (mr_read_state *) c;
   long cnt, line, line_len;
   char buf[1024];

   if (eof < 0) {
      if (s->msc)
	 (*(s->msc))(1, s->c);
      xbuffer_free(&(s->xb));
      free(c);
   }

   if (!xbuffer_append(&(s->xb), input, len))
      log_fatal("log_to", "failed appending to mailer output log");

   input = s->xb.buf;
   len = s->xb.len;

   while (s->ptr < len) {
      cnt = scan_line(input, len, &(s->ptr), &line, &line_len);

      if (line_len) {
	 sprintf(buf, "%.*s", (int) cnt, (char *) input+line);
      } else if (cnt && eof) {
	 sprintf(buf, "%.*s", (int) cnt, (char *) input+s->ptr);
	 s->ptr += cnt;
      }

      if (info)
	 log_info("mail_delivery_client [stdout]", buf);
      else
	 log_error("mail_delivery_client [stderr]", buf);
   }

   if (eof > 0) {
      if (s->msc)
	 (*(s->msc))(s->ptr, s->c);
      xbuffer_free(&(s->xb));
      free(c);
      mp_delete_read(fd);
   }
}

void log_to_info(int fd, unsigned char *input, long len, int eof, void *c)
{
   log_to(fd, input, len, eof, c, 1);
}

void log_to_err(int fd, unsigned char *input, long len, int eof, void *c)
{
   log_to(fd, input, len, eof, c, 0);
}

void free_output(int fd, unsigned char *output, long len, void *c)
{
   free(output);
}

static const unsigned char maintainer_str[] = "$maintainer";
static int maintainer_len = sizeof(maintainer_str)-1;

static const unsigned char version_str[] = "$version";
static int version_len = sizeof(version_str)-1;

#define MIME_BOUNDARY "---PKSD-----"

void mail_send(mail_send_conf *conf, int mail_send_flags,
	       const unsigned char *reply_to, long reply_to_len,
	       const unsigned char *subject, long subject_len,
	       const unsigned char *headers, long headers_len,
	       const unsigned char *bodyheaders, long bodyheaders_len,
	       const unsigned char *body, long body_len,
	       mail_send_cleanup msc, void *c)
{
   xbuffer xb;
   xfilecontents mif_xfc;
   FILE *mif;
   int p0[2], p1[2], p2[2];
   pid_t pid;
   char buf[1024];
   unsigned char *tmp1, *tmp2;
   mr_read_state *s;

   xbuffer_alloc(&xb);

   if (!xbuffer_append_str(&xb, "To: ") ||
       !xbuffer_append(&xb, reply_to, reply_to_len) ||
       !xbuffer_append_str(&xb, "\nFrom: ") ||
       !xbuffer_append_str(&xb, conf->maintainer_email) ||
       !xbuffer_append_str(&xb, "\nSubject: ") ||
       !xbuffer_append(&xb, subject, subject_len) ||
       !xbuffer_append_str(&xb, "\n") ||
       !xbuffer_append(&xb, headers, headers_len) ||
       /* I'm told Precedence: list" will cause bounces not to include
	  bodies.  This would seem to be beneficial to the mail spool.  */
       !xbuffer_append_str(&xb, ("Precedence: list\n"
				 "MIME-Version: 1.0\n")))
      log_fatal("mail_send", "creating mail reply headers");
   if (!(mail_send_flags & MAIL_SEND_NO_INTRO)) {
       if (!xbuffer_append_str(&xb, ("Content-Type: multipart/mixed; "
                                     "boundary=\"" MIME_BOUNDARY "\"\n\n"
                                     "--" MIME_BOUNDARY "\n")))
           log_fatal("mail_send", "creating mail reply headers (2nd part)");
   
       /* the mail intro file is expected to have a blank line at the top,
          or to include MIME part headers and then a blank line */

       if (conf->mail_intro_file && conf->mail_intro_file[0]) {
           if ((mif = fopen(conf->mail_intro_file, "r")) == NULL) {
               sprintf(buf, "error opening mail header file %s",
                       conf->mail_intro_file);

               log_error("mail_send", buf);
           } else {
               if (!xfilecontents_get(&mif_xfc, mif)) {
                   sprintf(buf, "error reading mail header file %s",
                           conf->mail_intro_file);

                   log_error("mail_send", buf);
               }
               fclose(mif);

               for (tmp1 = mif_xfc.buf; tmp1 < mif_xfc.buf+mif_xfc.len; ) {
                   if ((tmp2 = my_memcasemem(tmp1, maintainer_str,
                                             mif_xfc.len-(tmp1-mif_xfc.buf),
                                             maintainer_len))) {
                       if (!xbuffer_append(&xb, tmp1, tmp2-tmp1) ||
                           !xbuffer_append_str(&xb, conf->maintainer_email))
                           log_fatal("mail_send", "creating mail reply intro text (1)");

                       tmp1 = tmp2+maintainer_len;
                   } else if ((tmp2 = my_memcasemem(tmp1, version_str,
                                                    mif_xfc.len-(tmp1-mif_xfc.buf),
                                                    version_len))) {
                       if (!xbuffer_append(&xb, tmp1, tmp2-tmp1) ||
                           !xbuffer_append_str(&xb, PKS_VERSION))
                           log_fatal("mail_send", "creating mail reply intro text (2)");
                       tmp1 = tmp2+version_len;
                   } else {
                       if (!xbuffer_append(&xb, tmp1, (mif_xfc.buf+mif_xfc.len)-tmp1))
                           log_fatal("mail_send", "creating mail reply intro text (3)");
                       break;
                   }
               }

               if (mif_xfc.len && body_len) {
                   if (!xbuffer_append_str(&xb, "--" MIME_BOUNDARY "\n"))
                       log_fatal("mail_send", "appending MIME boundary");
               }

               xfilecontents_free(&mif_xfc);
           }
       }
   }
   

   /* if the bodyheaders are zero-length, then the body is assumed to
      include headers.  otherwise, the headers are included, and an extra
      newline is appended.  if the caller wants no headers, it should pass
      "\n", length 1.  This will result in two blank lines, but that's
      ok. */

   if (bodyheaders_len) {
      if (!xbuffer_append(&xb, bodyheaders, bodyheaders_len) ||
	  !xbuffer_append_str(&xb, "\n"))
	 log_fatal("mail_send", "appending mail reply body headers");
   }

   if (!xbuffer_append(&xb, body, body_len))
      log_fatal("mail_send", "appending mail reply body");

   if (!(mail_send_flags & MAIL_SEND_NO_INTRO)) {
       if (!xbuffer_append_str(&xb, "\n\n--" MIME_BOUNDARY "--\n"))
           log_fatal("mail_send", "appending MIME terminator");
   }

   if (pipe(p0) < 0) {
      sprintf(buf, "error creating mail reply stdin pipe: errno = %d",
	      errno);
      log_fatal("mail_send", buf);
   }

   if (pipe(p1) < 0) {
      sprintf(buf, "error creating mail reply stdout pipe: errno = %d",
	      errno);
      log_fatal("mail_send", buf);
   }

   if (pipe(p2) < 0) {
      sprintf(buf, "error creating mail reply stderr pipe: errno = %d",
	      errno);
      log_fatal("mail_send", buf);
   }

   if (!mp_add_write(p0[1], 1, xb.buf, xb.len, free_output, NULL))
      log_fatal("mail_send", "failed adding mailer writer");

   if ((s = (mr_read_state *) malloc(sizeof(mr_read_state))) == NULL)
      log_fatal("mail_send", "error allocating state for log_to_info");

   xbuffer_alloc(&(s->xb));
   s->ptr = 0;
   s->msc = NULL;
   s->c = NULL;

   if (!mp_add_read(p1[0], 0, log_to_info, (void *) s))
      log_fatal("mail_send", "failed adding log_to_info reader");

   if ((s = (mr_read_state *) malloc(sizeof(mr_read_state))) == NULL)
      log_fatal("mail_send", "error allocating state for log_to_err");

   xbuffer_alloc(&(s->xb));
   s->ptr = 0;
   s->msc = msc;
   s->c = c;

   if (!mp_add_read(p2[0], 0, log_to_err, (void *) s))
      log_fatal("mail_send", "failed adding log_to_err reader");

   pid = vfork();

   if (pid < 0) {
      sprintf(buf, "error forking for mail reply: errno = %d; sleeping",
              errno);
      log_error("mail_send", buf);
      /* Try again */
      sleep(10);
      pid = vfork();
      if (pid < 0) {
          sprintf(buf, "error forking for mail reply: errno = %d", errno);
          log_fatal("mail_send", buf);
      }
   }

   if (pid == 0) {
      /* child */

      if (dup2(p0[0], 0) < 0) {
	 sprintf(buf, "error duplicating pipe onto STDIN: errno = %d", errno);
	 log_fatal("mail_send [child]", buf);
      }
      close(p0[0]);
      close(p0[1]);
      if (dup2(p1[1], 1) < 0) {
	 sprintf(buf, "error duplicating pipe onto STDOUT: errno = %d", errno);
	 log_fatal("mail_send [child]", buf);
      }
      close(p1[0]);
      close(p1[1]);
      if (dup2(p2[1], 2) < 0) {
	 sprintf(buf, "error duplicating pipe onto STDERR: errno = %d", errno);
	 log_fatal("mail_send [child]", buf);
      }
      close(p2[0]);
      close(p2[1]);
	 
      sprintf(buf, "exec %s", conf->mail_delivery_client);

      execl("/bin/sh", "sh", "-c", buf, NULL);
      log_fatal("mail_send [child]", "exec for mail reply returned");
   }

   close(p0[0]);
   close(p1[1]);
   close(p2[1]);

   return;
}

static const unsigned char textplain_str[] = "Content-type: text/plain\n";
static int textplain_len = sizeof(textplain_str)-1;

static const unsigned char nohelp_str[] = "Configuration error: no help available";
static int nohelp_len = sizeof(nohelp_str)-1;

void mail_help(mail_send_conf *conf,
	       const unsigned char *reply_to, long reply_to_len,
	       const unsigned char *subject, long subject_len,
	       const unsigned char *headers, long headers_len,
	       const unsigned char *help_file, long help_file_len,
	       mail_send_cleanup msc, void *c)
{
   char helpfile[1024];
   xfilecontents xfc;
   long len;
   unsigned char *buf;
   FILE *hfh;
   long i, j;

   if (help_file_len == 0) {
      help_file = (unsigned char *) conf->default_lang;
      help_file_len = strlen((char *) help_file);
   }

   {
      strcpy(helpfile, conf->help_dir);
      strcat(helpfile, "/pks_help.");

      for (i=0, j=strlen(helpfile); i<help_file_len; i++, j++)
	 helpfile[j] = tolower(help_file[i]);
      helpfile[j] = '\0';

      if ((hfh = fopen(helpfile, "r")) == NULL) {
	 /* This language failed, try again with default */
         help_file = (unsigned char *) conf->default_lang;
         help_file_len = strlen((char *) help_file);
         strcpy(helpfile, conf->help_dir);
         strcat(helpfile, "/pks_help.");

         for (i=0, j=strlen(helpfile); i<help_file_len; i++, j++)
            helpfile[j] = tolower(help_file[i]);
         helpfile[j] = '\0';
	 hfh = fopen(helpfile, "r");
      }
      if (hfh == NULL) {
	 char buf[1024];

	 sprintf(buf, "error opening help file %s", helpfile);
	 log_error("mail_help", buf);

	 mail_send(conf, 0, reply_to, reply_to_len,
		   subject, subject_len,
		   headers, headers_len,
		   textplain_str, textplain_len,
		   nohelp_str, nohelp_len,
		   msc, c);
	 return;
      }

      if (!xfilecontents_get(&xfc, hfh)) {
	 char buf[1024];

	 fclose(hfh);

	 sprintf(buf, "error reading help file %s", helpfile);
	 log_error("mail_help", buf);

	 mail_send(conf, 0, reply_to, reply_to_len,
		   subject, subject_len,
		   headers, headers_len,
		   textplain_str, textplain_len,
		   nohelp_str, nohelp_len,
		   msc, c);
	 return;
      }

      fclose(hfh);

      len = xfc.len;
      buf = xfc.buf;
   }

   mail_send(conf, 0, reply_to, reply_to_len,
	     subject, subject_len,
             headers, headers_len,
	     NULL, 0,
	     buf, len,
	     msc, c);

   xfilecontents_free(&xfc);
}

