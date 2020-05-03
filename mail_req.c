const char rcsid_mail_req_c[] = "$Id: mail_req.c,v 1.3 2002/09/08 19:27:34 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "parse.h"
#include "globals.h"
#include "util.h"
#include "database.h"
#include "mail_send.h"
#include "mail_req.h"

long scan_header(unsigned char *input, long len, long *offset,
		 long *header, long *header_len)
{
   long cnt, line, line_len, ret;

   cnt = scan_line(input, len, offset, &line, &line_len);

   /* end of input, return length of partial header */
   if (line_len == 0) {
      *header = -1;
      *header_len = 0;

      return(cnt);
   }

   *header = line;

   /* end of headers, scan all the blank lines, return 0 */
   if (cnt == 0) {
      while (cnt == 0) {
	 cnt = scan_line(input, len, offset, &line, &line_len);

	 /* input ended, offset points at the end of the last blank line.
	    the next scan_line will read the incomplete and only
	    body line */
	 if (line_len == 0) {
	    *header_len = *offset - *header;
	    return(0);
	 }
      }

      /* line with data found after blank lines.  back up over it,
	 and return the blank lines */

      *offset = line;
      *header_len = *offset - *header;
      return(0);
   }

   while (1) {
      ret = (line - *header) + cnt;

      /* there's a header here.  look for continuation lines */
      cnt = scan_line(input, len, offset, &line, &line_len);

      /* the header was incomplete at end of file */
      if (line_len == 0) {
	 *offset = *header;
	 *header = -1;
	 *header_len = 0;
	 return(len - *header);
      }

      /* the headers ended entirely, or a new header begins.
	 back up to beginning of line and return */
      if (cnt == 0 || (!isspace(input[line]))) {
	 *offset = line;
	 *header_len = *offset - *header;
	 return(ret);
      }

      /* otherwise, just go on to the next line */
   }
}

static const char from_str[] = "from:";
static int from_len = sizeof(from_str)-1;

static const char reply_to_str[] = "reply-to:";
static int reply_to_len = sizeof(reply_to_str)-1;

static const char subject_str[] = "subject:";
static int subject_len = sizeof(subject_str)-1;

static const char xsentto_str[] = "X-KeyServer-Sent:";
static int xsentto_len = sizeof(xsentto_str)-1;

static const char in_reply_to_str[] = "In-Reply-To:";
static int in_reply_to_len = sizeof(in_reply_to_str)-1;

static const char message_id_str[] = "message-id:";
static int message_id_len = sizeof(message_id_str)-1;

static const char no_cmd_str[] = "(none)";
static int no_cmd_len = sizeof(no_cmd_str)-1;

static const char help_str[] = "HELP";
static int help_len = sizeof(help_str)-1;

static const char add_str[] = "ADD";
static int add_len = sizeof(add_str)-1;

static const char incr_str[] = "INCREMENTAL";
static int incr_len = sizeof(incr_str)-1;

static const char vindex_str[] = "VERBOSE INDEX";
static int vindex_len = sizeof(vindex_str)-1;

static const char index_str[] = "INDEX";
static int index_len = sizeof(index_str)-1;

static const char get_str[] = "GET";
static int get_len = sizeof(get_str)-1;

static const char last_str[] = "LAST";
static int last_len = sizeof(last_str)-1;

static const unsigned char pgpkeys_str[] =
	"Content-type: application/pgp-keys\n";
static int pgpkeys_len = sizeof(pgpkeys_str)-1;

static const unsigned char textplain_str[] = "Content-type: text/plain\n";
static int textplain_len = sizeof(textplain_str)-1;

void mail_req(unsigned char *msg, long len, mail_req_conf *conf,
	      mail_send_cleanup msc, void *c)
{
   long ptr, cnt;
   long header, header_len;
   long hfrom, hfrom_len, hreply_to, hreply_to_len, hsubject, hsubject_len;
   long hmessage_id, hmessage_id_len;
   long body, body_len, userid, userid_len;
   xbuffer reply_subject;
   xbuffer oldxsentto;
   xbuffer reply_headers;

   int ret, incr;
   unsigned char *retstr;
   long ret_len;
   const unsigned char *retheaders;
   long retheaders_len;

   ptr = 0;

   hfrom = -1;
   hfrom_len = 0;
   hreply_to = -1;
   hreply_to_len = 0;
   hmessage_id = -1;
   hmessage_id_len = 0;
   hsubject = -1;
   hsubject_len = 0;
   xbuffer_alloc(&oldxsentto);

   incr = 0;

   while (1) {
      cnt = scan_header(msg, len, &ptr, &header, &header_len);

      /* end of file in headers */
      if (header_len == 0) {
	 log_error("mail_req", "mail message ended during headers");
	 return;
      }

      /* end of headers */
      if (cnt == 0)
	 break;

      header_len = cnt;

      if (is_token(msg+header, header_len, from_str, from_len, 0)) {
	 hfrom = from_len;

	 scan_space(msg+header, header_len, &hfrom);

	 hfrom_len = header_len - hfrom;
	 hfrom += header;
      } else if (is_token(msg+header, header_len,
			  reply_to_str, reply_to_len, 0)) {
	 hreply_to = reply_to_len;

	 scan_space(msg+header, header_len, &hreply_to);

	 hreply_to_len = header_len - hreply_to;
	 hreply_to += header;
      } else if (is_token(msg+header, header_len,
			  message_id_str, message_id_len, 0)) {
	 hmessage_id = message_id_len;

	 scan_space(msg+header, header_len, &hmessage_id);

	 hmessage_id_len = header_len - hmessage_id;
	 hmessage_id += header;
      } else if (is_token(msg+header, header_len,
			  subject_str, subject_len, 0)) {
	 hsubject = subject_len;

	 scan_space(msg+header, header_len, &hsubject);

	 hsubject_len = header_len - hsubject;
	 hsubject += header;
      } else if (is_token(msg+header, header_len,
			  xsentto_str, xsentto_len, 0)) {
	 long hxsentto, hxsentto_len;

	 hxsentto = xsentto_len;

	 scan_space(msg+header, header_len, &hxsentto);

	 hxsentto_len = header_len - hxsentto;
	 hxsentto += header;

	 if (!xbuffer_append(&oldxsentto,
			     (unsigned char *) xsentto_str, xsentto_len) ||
	     !xbuffer_append_str(&oldxsentto, " ") ||
	     !xbuffer_append(&oldxsentto, msg+hxsentto, hxsentto_len) ||
	     !xbuffer_append_str(&oldxsentto, "\n"))
	    log_fatal("mail_req", "failed creating new X-KeyServer-Sent");
      }
   }

   body = ptr;
   body_len = len - body;

   if (hfrom == -1 || hfrom_len == 0) {
      log_error("mail_req", "mail message does not have From: header");
      return;
   }

   {
      char buf[1024];

      if (hsubject_len == 0) {
          sprintf(buf, "request received from %.*s%s: (none)",
                  (int) ((hfrom_len<=450)?hfrom_len:450), msg+hfrom,
                  (hfrom_len<=450)?"":" (truncated)");
      } else {
          sprintf(buf, "request received from %.*s%s: %.*s%s",
                  (int) ((hfrom_len<=450)?hfrom_len:450), msg+hfrom,
                  (hfrom_len<=450)?"":" (truncated)",
                  (int) ((hsubject_len<=450)?hsubject_len:450), msg+hsubject,
                  (hsubject_len<=450)?"":" (truncated)");
      }
      
      log_info("mail_req", buf);
   }

   if (hreply_to == -1) {
      hreply_to = hfrom;
      hreply_to_len = hfrom_len;
   }

   xbuffer_alloc(&reply_headers);

   if (hmessage_id != -1) {
       if (!xbuffer_append(&reply_headers,
                           (unsigned char *)in_reply_to_str,
                           in_reply_to_len) ||
	   !xbuffer_append_str(&reply_headers, " ") ||
           !xbuffer_append(&reply_headers, msg+hmessage_id, hmessage_id_len) ||
           !xbuffer_append_str(&reply_headers, "\n"))
           log_fatal("mail_req", "failed creating reply_headers");
   }

   xbuffer_alloc(&reply_subject);

   if (!xbuffer_append_str(&reply_subject, "Your command, ") ||
       (hsubject_len?
	!xbuffer_append(&reply_subject, msg+hsubject, hsubject_len):
	!xbuffer_append(&reply_subject,
			(unsigned char *) no_cmd_str, no_cmd_len)))
      log_fatal("mail_req", "failed creating reply_subject");

   retheaders = textplain_str;
   retheaders_len = textplain_len;

   if (hsubject_len &&
       is_token(msg+hsubject, hsubject_len, help_str, help_len, 0)) {
      userid = help_len;

      scan_space(msg+hsubject, hsubject_len, &userid);

      userid_len = hsubject_len - userid;
      userid += hsubject;

      /* this will dtrt if userid_len == 0 */

      mail_help(conf->msc, msg+hreply_to, hreply_to_len,
		reply_subject.buf, reply_subject.len,
                reply_headers.buf, reply_headers.len,
		msg+userid, userid_len,
		msc, c);
      xbuffer_free(&reply_headers);
      xbuffer_free(&reply_subject);
      xbuffer_free(&oldxsentto);
      return;
   } else if (hsubject_len &&
	      ((is_token(msg+hsubject, hsubject_len, add_str, add_len, 0)) ||
	       (is_token(msg+hsubject, hsubject_len, incr_str, incr_len, 0) &&
		++incr))) {
      xbuffer incr_to;
      unsigned char *incrmsg;
      long incrlen;

      xbuffer_alloc(&incr_to);

      if (pks_incr_have_syncsites(conf->pic)) {
	 if (!pks_incr_make_header(conf->pic, incr?&oldxsentto:NULL, &incr_to))
	    log_fatal("mail_req",
		      "failed to make to: header for incremental");
      }

      ret = kd_add(msg+body, body_len, KD_ADD_VERBOSE, &retstr, &ret_len,
		   incr_to.len?&incrmsg:NULL, incr_to.len?&incrlen:NULL);

      if ((ret == 1) && incr_to.len && incrlen) {
	 if (!pks_incr_post(conf->pic, incr?&oldxsentto:NULL, &incr_to,
			    incrmsg, incrlen))
	    log_fatal("mail_req",
		      "failed to post all incrememntals");
	 free(incrmsg);
      }

      xbuffer_free(&incr_to);
   } else if (hsubject_len &&
	      is_token(msg+hsubject, hsubject_len, index_str, index_len, 0)) {
      userid = index_len;

      scan_space(msg+hsubject, hsubject_len, &userid);

      userid_len = hsubject_len - userid;
      userid += hsubject;

      if (userid_len == 0) {
	 if (!xbuffer_append_str(&reply_subject, ", is not yet implemented"))
	    log_fatal("mail_req",
		      "failed reply_subject for unimplemented command");

	 mail_send(conf->msc, 0, msg+hreply_to, hreply_to_len,
		   reply_subject.buf, reply_subject.len,
		   reply_headers.buf, reply_headers.len,
		   textplain_str, textplain_len,
		   NULL, 0,
		   msc, c);

         xbuffer_free(&reply_headers);
	 xbuffer_free(&reply_subject);
	 xbuffer_free(&oldxsentto);
	 return;
      } else {
	 ret = kd_index(msg+userid, userid_len, KD_INDEX_EXACT, 
			conf->max_reply_keys, &retstr, &ret_len);
      }
   } else if (hsubject_len &&
	      is_token(msg+hsubject, hsubject_len,
		       vindex_str, vindex_len, 0)) {
      userid = vindex_len;

      scan_space(msg+hsubject, hsubject_len, &userid);

      userid_len = hsubject_len - userid;
      userid += hsubject;

      if (userid_len == 0) {
	 if (!xbuffer_append_str(&reply_subject, ", is not yet implemented"))
	    log_fatal("mail_req",
		      "failed reply_subject for unimplemented command");

	 mail_send(conf->msc, 0, msg+hreply_to, hreply_to_len,
		   reply_subject.buf, reply_subject.len,
		   reply_headers.buf, reply_headers.len,
		   textplain_str, textplain_len,
		   NULL, 0,
		   msc, c);

         xbuffer_free(&reply_headers);
	 xbuffer_free(&reply_subject);
	 xbuffer_free(&oldxsentto);
	 return;
      } else {
	 ret = kd_index(msg+userid, userid_len,
			KD_INDEX_VERBOSE | KD_INDEX_EXACT,
			conf->max_reply_keys, &retstr, &ret_len);
      }
   } else if (hsubject_len &&
	      is_token(msg+hsubject, hsubject_len, get_str, get_len, 0)) {
      userid = get_len;

      scan_space(msg+hsubject, hsubject_len, &userid);

      userid_len = hsubject_len - userid;
      userid += hsubject;

      if (userid_len == 0) {
	 if (!xbuffer_append_str(&reply_subject, ", is not yet implemented"))
	    log_fatal("mail_req",
		      "failed reply_subject for unimplemented command");

	 mail_send(conf->msc, 0, msg+hreply_to, hreply_to_len,
		   reply_subject.buf, reply_subject.len,
		   reply_headers.buf, reply_headers.len,
		   textplain_str, textplain_len,
		   NULL, 0,
		   msc, c);

         xbuffer_free(&reply_headers);
	 xbuffer_free(&reply_subject);
	 xbuffer_free(&oldxsentto);
	 return;
      } else {
	 ret = kd_get(msg+userid, userid_len, KD_GET_EXACT, 
		      conf->max_reply_keys, &retstr, &ret_len);

	 if (ret) {
	    retheaders = pgpkeys_str;
	    retheaders_len = pgpkeys_len;
	 }
      }
   } else if (hsubject_len &&
	      is_token(msg+hsubject, hsubject_len, last_str, last_len, 0)) {
      int days;
      time_t since;

      userid = last_len;

      scan_space(msg+hsubject, hsubject_len, &userid);

      userid_len = hsubject_len - userid;
      userid += hsubject;

      days = atoi((char *) msg+userid);

      if ((userid_len == 0) || (days <= 0)) {
	 if (!xbuffer_append_str(&reply_subject, ", was invalid (argument must be a number greater than zero)"))
	    log_fatal("mail_req", "failed reply_subject for invalid command");

	 mail_help(conf->msc, msg+hreply_to, hreply_to_len,
		   reply_subject.buf, reply_subject.len,
                   reply_headers.buf, reply_headers.len,
		   NULL, 0,
		   msc, c);
         xbuffer_free(&reply_headers);
	 xbuffer_free(&reply_subject);
	 xbuffer_free(&oldxsentto);
	 return;
      }

      if ((conf->max_last >= 0) &&
	  (days > conf->max_last)) {
	 xbuffer err;

	 xbuffer_alloc(&err);

	 if (conf->max_last == 0) {
	    if (!xbuffer_append_str(&err, "LAST is not permitted by this server\n"))
	       log_fatal("mail_req", "failed error for LAST not permitted");
	 } else {
	    char max_last_num[20];

	    sprintf(max_last_num, "%d", conf->max_last);

	    if (!xbuffer_append_str(&err, "LAST argument must be less than or rqual to ")||
		!xbuffer_append_str(&err, max_last_num) ||
		!xbuffer_append_str(&err, "\n"))
	       log_fatal("mail_req", "failed error for LAST too big");
	 }

	 retstr = err.buf;
	 ret_len = err.len;

	 ret = 0;
      } else {
	 if (time(&since) < 0)
	    log_fatal("mail_req", "failed getting current time");

	 since -= 86400*days;

	 ret = kd_since(since, 0, conf->max_last_reply_keys,
			NULL, &retstr, &ret_len);

	 if (ret) {
	    retheaders = pgpkeys_str;
	    retheaders_len = pgpkeys_len;
	 }
      }
   } else {
      if (!xbuffer_append_str(&reply_subject, ", was invalid"))
	 log_fatal("mail_req", "failed reply_subject for invalid command");

      mail_help(conf->msc, msg+hreply_to, hreply_to_len,
		reply_subject.buf, reply_subject.len,
                reply_headers.buf, reply_headers.len,
		NULL, 0,
		msc, c);
      xbuffer_free(&reply_headers);
      xbuffer_free(&reply_subject);
      xbuffer_free(&oldxsentto);
      return;
   }

   if (!ret)
      if (!xbuffer_append_str(&reply_subject, ", failed"))
	 log_fatal("mail_req", "failed reply_subject for invalid command");

   if (!incr) {
      mail_send(conf->msc, 0, msg+hreply_to, hreply_to_len,
		reply_subject.buf, reply_subject.len,
                reply_headers.buf, reply_headers.len,
		retheaders, retheaders_len,
		retstr, ret_len,
		msc, c);

      log_info("mail_req", "reply sent");
   } else {
      (*msc)(0, c);
   }

   xbuffer_free(&reply_headers);
   xbuffer_free(&reply_subject);
   xbuffer_free(&oldxsentto);

   free(retstr);
}
