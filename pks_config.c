const char rcsid_pks_c[] = "$Id: pks_config.c,v 1.7 2002/11/05 04:07:38 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "parse.h"
#include "pks_config.h"
#include "globals.h"
#include "util.h"

const pks_config default_config = {
   "/var/spool/pks/etc/db",
   "/var/lib/pks",
   0,
   "",
   1,
   "/var/spool/pks/pksd_socket",
   "",
   "root",
   "/var/spool/pks/etc/mail_intro",
   "/var/spool/pks/etc/mail_help",
   "EN",
   "",
   /* okay, it's an abstraction violation.  I wouldn't need to do 
      this in C++ */
   { { 0, 0, NULL } },
   -1,
   -1,
};

const char db_dir_str[] = "db_dir";
long db_dir_len = sizeof(db_dir_str)-1;

const char www_dir_str[] = "www_dir";
long www_dir_len = sizeof(www_dir_str)-1;

const char www_port_str[] = "www_port";
long www_port_len = sizeof(www_port_str)-1;

const char www_addr_str[] = "www_addr";
long www_addr_len = sizeof(www_addr_str)-1;

const char www_readonly_str[] = "www_readonly";
long www_readonly_len = sizeof(www_readonly_str)-1;

const char sockname_str[] = "socket_name";
long sockname_len = sizeof(sockname_str)-1;

const char mdc_str[] = "mail_delivery_client";
long mdc_len = sizeof(mdc_str)-1;

const char maint_str[] = "maintainer_email";
long maint_len = sizeof(maint_str)-1;

const char mif_str[] = "mail_intro_file";
long mif_len = sizeof(mif_str)-1;

const char helpdir_str[] = "help_dir";
long helpdir_len = sizeof(helpdir_str)-1;

const char deflang_str[] = "default_language";
long deflang_len = sizeof(deflang_str)-1;

const char this_site_str[] = "this_site";
long this_site_len = sizeof(this_site_str)-1;

const char syncsite_str[] = "syncsite";
long syncsite_len = sizeof(syncsite_str)-1;

const char max_last_str[] = "max_last";
long max_last_len = sizeof(max_last_str)-1;

const char max_last_reply_keys_str[] = "max_last_reply_keys";
long max_last_reply_keys_len = sizeof(max_last_reply_keys_str)-1;

const char max_reply_keys_str[] = "max_reply_keys";
long max_reply_keys_len = sizeof(max_reply_keys_str)-1;

const char debug_str[] = "debug";
long debug_len = sizeof(debug_str)-1;

static int compare_strings(const void *e1, const void *e2)
{
   return(my_strncasecmp((const char *) e1, (const char *) e2, -1));
}

static int free_string(void *s, void *c)
{
   free(s);

   return(1);
}

/* this is cpp black magic */

#define noop() /**/
#define num_conf(vptr, vlen, confvar) \
      /* if ( */ is_token(line+word, word_len, (vptr), (vlen), 1)) { \
	 scan_token(line, len, &offset, &word, &word_len); \
	 (confvar) = atoi((char *) line+word); \
      } noop(
#define str_conf(vptr, vlen, confvar) \
      /* if ( */ is_token(line+word, word_len, (vptr), (vlen), 0)) { \
	 scan_space(line, len, &offset); \
	 word = offset; \
	 word_len = len-offset; \
	 while (word_len && isspace(line[word+word_len-1])) \
	    word_len--; \
	 strncpy((confvar), (char *) line+word, (size_t) word_len); \
	 (confvar)[word_len] = '\0'; \
      } noop(
#define llist_conf(vptr, vlen, confvar) \
      /* if ( */ is_token(line+word, word_len, (vptr), (vlen), 0)) { \
	 scan_space(line, len, &offset); \
	 word = offset; \
	 word_len = len-offset; \
	 while (word_len && isspace(line[word+word_len-1])) \
	 word_len--; \
         { \
	    char *str; \
	    if (((str = (char *) malloc(word_len+1)) == NULL) || \
		(strncpy(str, (char *) line+word, (size_t) word_len), \
		 (str[word_len] = '\0'), \
		 !llist_add_sorted((confvar), str, compare_strings))) { \
	       llist_iterate((confvar), free_string, NULL); \
	       llist_free((confvar)); \
	       return(0); \
	    } \
	 } \
      } noop(

int pks_read_conf_file(const char *filename, pks_config *pc)
{
   FILE *conf;
   char buf[1024];
   unsigned char *line;
   long len, offset, word, word_len;

   *pc = default_config;

   if ((conf = fopen(filename, "r")) == NULL)
      return(0);

   while ((line = (unsigned char *) fgets(buf, sizeof(buf), conf))) {
      if (line[0] == '#')
	 continue;

      len = strlen((char *) line);
      offset = 0;

      scan_token(line, len, &offset, &word, &word_len);
      scan_space(line, len, &offset);

      if (str_conf(db_dir_str, db_dir_len, pc->db_dir))
      else if (str_conf(www_dir_str, www_dir_len, pc->www_dir))
      else if (str_conf(www_addr_str, www_addr_len, pc->www_addr))
      else if (num_conf(www_port_str, www_port_len, pc->www_port))
      else if (num_conf(www_readonly_str, www_readonly_len, pc->www_readonly))
      else if (str_conf(sockname_str, sockname_len, pc->socket_name))
      else if (str_conf(mdc_str, mdc_len, pc->mail_delivery_client))
      else if (str_conf(maint_str, maint_len, pc->maintainer_email))
      else if (str_conf(mif_str, mif_len, pc->mail_intro_file))
      else if (str_conf(helpdir_str, helpdir_len, pc->help_dir))
      else if (str_conf(deflang_str, deflang_len, pc->default_lang))
      else if (str_conf(this_site_str, this_site_len, pc->this_site))
      else if (num_conf(max_last_str, max_last_len, pc->max_last))
      else if (num_conf(max_last_reply_keys_str, max_last_reply_keys_len,
	                pc->max_last_reply_keys))
      else if (num_conf(max_reply_keys_str, max_reply_keys_len,
	                pc->max_reply_keys))
      else if (llist_conf(syncsite_str, syncsite_len, &(pc->syncsites)))
      else if (num_conf(debug_str, debug_len, debug))
   }

   fclose(conf);

   return(1);
}
