const char rcsid_pks_web_c[] = "$Id: pks_www.c,v 1.10 2003/01/06 18:52:27 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "pks_www.h"
#include "database.h"
#include "www.h"
#include "util.h"
#include "globals.h"
#include "multiplex.h"
#include "parse.h"
#include "pks_incr.h"

int w_htmlify_string(xbuffer *out, unsigned char *in, long in_len)
{
   int i, j;

   for (i=0, j=0; i<in_len; i++) {
      if (in[i] == '<') {
	 /* output the preceding text, and the < */
	 if (!xbuffer_append(out, in+j, i-j) ||
	     !xbuffer_append_str(out, "&lt;"))
	    return(0);

	 j = i+1;
      } else if (in[i] == '>') {
	 /* output the preceding text */
	 if (!xbuffer_append(out, in+j, i-j) ||
	     !xbuffer_append_str(out, "&gt;"))
	    return(0);

	 j = i+1;
      } else if (in[i] == '&') {
	 /* output the preceding text and & */
	 if (!xbuffer_append(out, in+j, i-j) ||
	     !xbuffer_append_str(out, "&amp;"))
	    return(0);

	 j = i+1;
      }
   }

   /* output the remaining text and an EOL */
   if (!xbuffer_append(out, in+j, i-j) ||
       !xbuffer_append_str(out, "\015\012"))
      return(0);

   return(1);
}

void w_reply(int fd, int vers, const char *content_type,
	     unsigned char *str, long len)
{
   www_reply(fd, vers, 200, "OK", content_type, str, len);
}

void w_ok(int fd, int vers, char *op, unsigned char *search, long search_len,
	    unsigned char *str, long len)
{
   xbuffer xb;

   xbuffer_alloc(&xb);

   if (!xbuffer_append_str(&xb, "<title>Public Key Server -- ") ||
       !xbuffer_append_str(&xb, op) ||
       (search_len && !xbuffer_append_str(&xb, " ``")) ||
       (search_len && !w_htmlify_string(&xb, search, search_len)) ||
       (search_len && !xbuffer_append_str(&xb, "''")) ||
       !xbuffer_append_str(&xb, "</title><p>\015\012") ||
       !xbuffer_append_str(&xb, "<h1>Public Key Server -- ") ||
       !xbuffer_append_str(&xb, op) ||
       (search_len && !xbuffer_append_str(&xb, " ``")) ||
       (search_len && !w_htmlify_string(&xb, search, search_len)) ||
       (search_len && !xbuffer_append_str(&xb, "''")) ||
       !xbuffer_append_str(&xb, "</h1><p>\015\012") ||
       !xbuffer_append_str(&xb, "<pre>\015\012") ||
       !xbuffer_append(&xb, str, len) ||
       !xbuffer_append_str(&xb, "</pre>\015\012")) {
      log_fatal("w_ok", "constructing reply");
   }

   w_reply(fd, vers, NULL, xb.buf, xb.len);

   xbuffer_free(&xb);
}

void w_error(int fd, int vers, unsigned char *str, long len)
{
   xbuffer xb;

   xbuffer_alloc(&xb);

   if (!xbuffer_append_str(&xb, "<title>Public Key Server -- Error</title><p>\015\012") ||
       !xbuffer_append_str(&xb, "<h1>Public Key Server -- Error</h1><p>\015\012") ||
       !xbuffer_append(&xb, str, len)) {
      log_fatal("w_error", "constructing reply");
   }

   w_reply(fd, vers, NULL, xb.buf, xb.len);

   xbuffer_free(&xb);
}

void w_error_str(int fd, int vers, char *str)
{
   w_error(fd, vers, (unsigned char *) str, strlen(str));
}

static const char homepage_str[] = "/";
static int homepage_len = sizeof(homepage_str)-1;

static const char lookup_str[] = "/pks/lookup";
static int lookup_len = sizeof(lookup_str)-1;

static const char add_str[] = "/pks/add";
static int add_len = sizeof(add_str)-1;

static const char opeq_str[] = "op=";
static int opeq_len = sizeof(opeq_str)-1;

static const char searcheq_str[] = "search=";
static int searcheq_len = sizeof(searcheq_str)-1;

static const char fingerprinteq_str[] = "fingerprint=";
static int fingerprinteq_len = sizeof(fingerprinteq_str)-1;

static const char exacteq_str[] = "exact=";
static int exacteq_len = sizeof(exacteq_str)-1;

static const char optionseq_str[] = "options=";
static int optionseq_len = sizeof(optionseq_str)-1;

static const char keytexteq_str[] = "keytext=";
static int keytexteq_len = sizeof(keytexteq_str)-1;

static const char index_str[] = "index";
static int index_len = sizeof(index_str)-1;

static const char vindex_str[] = "vindex";
static int vindex_len = sizeof(vindex_str)-1;

static const char get_str[] = "get";
static int get_len = sizeof(get_str)-1;

static const char on_str[] = "on";
static int on_len = sizeof(on_str)-1;

static const char mr_str[] = "mr";
static int mr_len = sizeof(mr_str)-1;

static const char bad_uri_str[] = "unknown uri in pks request";
static int bad_uri_len = sizeof(bad_uri_str)-1;

int w_htmlify_index(xbuffer *out, unsigned char *in, long in_len)
{
   long cnt, ptr, line, line_len, i, j, keyid, inref;

   /* iterate through lines */

   keyid = 0;

   for (ptr = 0;
	cnt = scan_line(in, in_len, &ptr, &line, &line_len),
	cnt || (ptr < in_len);
	) {
      line_len = cnt;
      if (line < 0) {
	 line = ptr;
	 ptr += cnt;
      }

      i = 0;

      if ((line_len >= 19) &&
	  ((my_strncasecmp((char *) in+line, "pub", 3) == 0) ||
	   (my_strncasecmp((char *) in+line, "sig", 3) == 0))) {
	 for (i=11; i<19; i++) {
	    if (!isxdigit(in[line+i])) {
	       if (!xbuffer_append(out, in+line, line_len) ||
		   !xbuffer_append_str(out, "\015\012"))
		  return(0);
	       break;
	    }
	 }

	 if (i == 19) {
	    keyid = line+11;

	    if (!xbuffer_append(out, in+line, 11) ||
		!xbuffer_append_str(out, "<a href=\"") ||
		!xbuffer_append(out, (unsigned char *) lookup_str,
				lookup_len) ||
		!xbuffer_append_str(out, "?") ||
		!xbuffer_append(out, (unsigned char *) opeq_str,
				opeq_len) ||
		!xbuffer_append(out, (unsigned char *) get_str, get_len) ||
		!xbuffer_append_str(out, "&") ||
		!xbuffer_append(out, (unsigned char *) searcheq_str,
				searcheq_len) ||
		!xbuffer_append_str(out, "0x") ||
		!xbuffer_append(out, in+keyid, 8) ||
		!xbuffer_append_str(out, "\">") ||
		!xbuffer_append(out, in+keyid, 8) ||
		!xbuffer_append_str(out, "</a>"))
	       return(0);
	 } else {
	    i = 0;
	 }

      }

      inref = 0;

      for (j=i; i<line_len; i++) {
	 if (in[line+i] == '<') {
	    /* output the preceding text, and the < */
	    if (!xbuffer_append(out, in+line+j, i-j) ||
		!xbuffer_append_str(out, "&lt;"))
	       return(0);

	    /* if there's a > after this, output the <a> tag,
	       and remember this */

	    for (j=i; j<line_len; j++)
	       if (in[line+j] == '>') {
		  if (!xbuffer_append_str(out, "<a href=\"") ||
		      !xbuffer_append(out, (unsigned char *) lookup_str,
				      lookup_len) ||
		      !xbuffer_append_str(out, "?") ||
		      !xbuffer_append(out, (unsigned char *) opeq_str,
				      opeq_len) ||
     /*		      !xbuffer_append(out, (unsigned char *) get_str,
				      get_len) ||*/
		      !xbuffer_append(out, (unsigned char *) vindex_str,
				      vindex_len) ||
		      !xbuffer_append_str(out, "&") ||
		      !xbuffer_append(out, (unsigned char *) searcheq_str,
				      searcheq_len) ||
		      !xbuffer_append_str(out, "0x") ||
		      !xbuffer_append(out, in+keyid, 8) ||
		      !xbuffer_append_str(out, "\">"))
		     return(0);
		  inref = 1;
		  break;
	       }

	    j = i+1;
	 } else if (in[line+i] == '>') {
	    /* output the preceding text */
	    if (!xbuffer_append(out, in+line+j, i-j))
	       return(0);

	    /* output the </a> tag if necessary */
	    if (inref) {
	       if (!xbuffer_append_str(out, "</a>"))
		  return(0);
	       inref = 0;
	    }

	    /* output the > */
	    if (!xbuffer_append_str(out, "&gt;"))
	       return(0);

	    j = i+1;
	 } else if (in[line+i] == '&') {
	    /* output the preceding text and & */
	    if (!xbuffer_append(out, in+line+j, i-j) ||
		!xbuffer_append_str(out, "&amp;"))
	       return(0);

	    j = i+1;
	 }
      }

      /* output the remaining text and an EOL */
      if (!xbuffer_append(out, in+line+j, i-j) ||
	  !xbuffer_append_str(out, "\015\012"))
	 return(0);
   }

   return(1);
}

void pks_www(int fd, int vers, unsigned char *uri, long urilen,
	     unsigned char *body, long bodylen, void *c)
{
   pks_www_conf *conf = (pks_www_conf *) c;
   long ptr, cnt, property, property_len;
   long search, search_len;
   char *opdesc;
   unsigned char *retstr;
   long retstr_len;
   int ret;
   int flags=0;
   enum {DUMMY,ADD,GET,INDEX,VINDEX} opcode=DUMMY;

   search = -1;
   search_len = 0;

   if (is_token(uri, urilen, homepage_str, homepage_len, 1)) {
      FILE *homepage;
      char homepage_path[2048];
      char buf[1024];
      char *line;
      xbuffer xb;

      strncpy(homepage_path, conf->www_dir, 2035);
      strncat(homepage_path, "/index.html", 2046);
      if ((homepage = fopen(homepage_path,"r")) == NULL) {
         log_error("pks_www", "non-existent homepage");
	 return;
      }

      xbuffer_alloc(&xb);

      while ((line = fgets(buf,sizeof(buf), homepage))) {
         if (!xbuffer_append_str(&xb, line)) {
            log_error("pks_www", "displaying home page");
	    xbuffer_free(&xb);
	    fclose(homepage);
	    return;
         }
      }
   
      w_reply(fd, vers, NULL, xb.buf, xb.len);

      xbuffer_free(&xb);
      fclose(homepage);
      return;
   } 
   if (is_token(uri, urilen, lookup_str, lookup_len, 1)) {
      long op, op_len, exact, exact_len,
	   options, options_len, fingerprint, fingerprint_len;

      if (bodylen == 0) {
	 w_error_str(fd, vers, "pks request had no query string");
	 return;
      }

      op = -1;
      op_len = 0;
      fingerprint = -1;
      fingerprint_len = 0;
      exact = -1;
      exact_len = 0;
      options = -1;
      options_len = 0;

      /* iterate through properties */

      for (ptr = 0;
	   cnt = scan_char(body, bodylen, &ptr, '&',
			   &property, &property_len),
	   cnt || (ptr < bodylen);
	   ) {
	 property_len = cnt;
	 if (property < 0) {
	    property = ptr;
	    ptr += cnt;
	 }

	 if (!www_urldecode(body+property, &property_len)) {
	    w_error_str(fd, vers, "pks request had invalid url encoding");
	    return;
	 }

	 if (is_token(body+property, property_len, opeq_str, opeq_len, 0)) {
	    op = property+opeq_len;
	    op_len = property_len-opeq_len;
	 } else if (is_token(body+property, property_len,
			     searcheq_str, searcheq_len, 0)) {
	    search = property+searcheq_len;
	    search_len = property_len-searcheq_len;
	 } else if (is_token(body+property, property_len,
			     fingerprinteq_str, fingerprinteq_len, 0)) {
	    fingerprint = property+fingerprinteq_len;
	    fingerprint_len = property_len-fingerprinteq_len;
	 } else if (is_token(body+property, property_len,
			     exacteq_str, exacteq_len, 0)) {
	    exact = property+exacteq_len;
	    exact_len = property_len-exacteq_len;
	 } else if (is_token(body+property, property_len,
			     optionseq_str, optionseq_len, 0)) {
	    options = property+optionseq_len;
	    options_len = property_len-optionseq_len;
	 }
      }

      if (op == -1) {
	 w_error_str(fd, vers,
		     "pks request did not include an <b>op</b> property");
	 return;
      }

      if (search == -1) {
	 w_error_str(fd, vers,
		     "pks request did not include a <b>search</b> property");
	 return;
      }

      if (is_token(body+exact, exact_len, on_str, on_len, 1))
	 flags |= KD_SEARCH_EXACT;

      if (is_token(body+op, op_len, index_str, index_len, 1)) {
	 xbuffer xb;

	 if (is_token(body+options, options_len, mr_str, mr_len, 1))
	    flags |= KD_INDEX_MR;

	 if (is_token(body+fingerprint, fingerprint_len, on_str, on_len, 1))
	    flags |= KD_INDEX_FINGERPRINT;

	 ret = kd_index(body+search, search_len, flags, conf->max_reply_keys,
			&retstr, &retstr_len);

	 opdesc = "Index";
	 opcode=INDEX;

	 if (ret && !(flags&KD_INDEX_MR)) {
	    xbuffer_alloc(&xb);

	    if (!xbuffer_append_str(&xb,
				    "Type bits /keyID    Date       User ID\015\012") ||
		!w_htmlify_index(&xb, retstr, retstr_len))
	       log_fatal("pks", "failed creating html index reply");

	    free(retstr);

	    /* violate a little abstraction */
	    retstr = xb.buf;
	    retstr_len = xb.len;
	 }
      } else if (is_token(body+op, op_len, vindex_str, vindex_len, 1)) {
	 xbuffer xb;

	 if (is_token(body+fingerprint, fingerprint_len, on_str, on_len, 1))
	    flags |= KD_INDEX_FINGERPRINT;

	 ret = kd_index(body+search, search_len, flags | KD_INDEX_VERBOSE,
			conf->max_reply_keys, &retstr, &retstr_len);

	 opdesc = "Verbose Index";
	 opcode=VINDEX;

	 if (ret) {
	    xbuffer_alloc(&xb);

	    if (!xbuffer_append_str(&xb,
				    "Type bits /keyID    Date       User ID\015\012") ||
		!w_htmlify_index(&xb, retstr, retstr_len))
	       log_fatal("pks", "failed creating html index reply");

	    free(retstr);

	    /* violate a little abstraction */
	    retstr = xb.buf;
	    retstr_len = xb.len;
	 }
      } else if (is_token(body+op, op_len, get_str, get_len, 1)) {
	 ret = kd_get(body+search, search_len, flags, conf->max_reply_keys,
		      &retstr, &retstr_len);

	 opdesc = "Get";
	 opcode=GET;

	 if (is_token(body+options, options_len, mr_str, mr_len, 1))
	   flags |= KD_GET_MR;
      } else {
	 w_error_str(fd, vers,
		     "pks request had an invalid <b>op</b> property");
	 return;
      }
   } else if (is_token(uri, urilen, add_str, add_len, 1)) {
      long keytext, keytext_len;
      int incr;
      unsigned char *incrmsg;
      long incrlen;

      if (bodylen == 0) {
	 w_error_str(fd, vers, "pks request had no query string");
	 return;
      }

      keytext = -1;
      keytext_len = 0;

      /* iterate through properties */

      for (ptr = 0;
	   cnt = scan_char(body, bodylen, &ptr, '&',
			   &property, &property_len),
	   cnt || (ptr < bodylen);
	   ) {
	 property_len = cnt;
	 if (property < 0) {
	    property = ptr;
	    ptr += cnt;
	 }

	 if (!www_urldecode(body+property, &property_len)) {
	    w_error_str(fd, vers, "pks request had invalid url encoding");
	    return;
	 }

	 if (is_token(body+property, property_len,
		      keytexteq_str, keytexteq_len, 0)) {
	    keytext = property+keytexteq_len;
	    keytext_len = property_len-keytexteq_len;
	 } 
      }

      if (keytext == -1) {
	 w_error_str(fd, vers, 
		     "pks request did not include a <b>keytext</b> property");
	 return;
      }

      incr = pks_incr_have_syncsites(conf->pic);

      ret = kd_add(body+keytext, keytext_len, KD_ADD_VERBOSE,
		   &retstr, &retstr_len,
		   incr?&incrmsg:NULL, incr?&incrlen:NULL);

      if ((ret == 1) && incr && incrlen) {
	 if (!pks_incr_post(conf->pic, NULL, NULL, incrmsg, incrlen))
	    log_fatal("pks_www", "failed to post all incrementals");
      }

      if (incr && incrmsg)
	 free(incrmsg);

      opdesc = "Add";
      opcode=ADD;
   } else {
      www_reply(fd, vers, 404, "Not Found", NULL,
		(unsigned char *) bad_uri_str, bad_uri_len);
      return;
   }

   if (ret) {
     if(opcode==INDEX && flags&KD_INDEX_MR)
       w_reply(fd, vers, "text/plain", retstr, retstr_len);
     else if(opcode==GET && flags&KD_GET_MR)
       {
	 /* application/pgp-keys as per RFC-3156.  This is perhaps not
	    optimal, as all key responses should really have this
	    content type.  However, 99.9% of browsers out there won't
	    know what to do with this type, so only use it when MR is
	    requested. */
	 w_reply(fd, vers, "application/pgp-keys", retstr, retstr_len);
       }
     else
       w_ok(fd, vers, opdesc, body+search, search_len, retstr, retstr_len);
   } else {
      w_error(fd, vers, retstr, retstr_len);
   }

   free(retstr);
}

void pks_www_init(pks_www_conf *conf)
{
   www_init(conf->addr, conf->port, pks_www, conf);
}
