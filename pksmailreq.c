const char rcsid_dmailreq_c[] = "$Id: pksmailreq.c,v 1.2 2003/02/07 01:01:21 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

#include "util.h"
#include "llist.h"
#include "mail_req.h"
#include "pks_incr.h"
#include "multiplex.h"
#include "globals.h"
#include "database.h"

void usage(const char *argv0)
{
   fprintf(stderr,
	   "usage: %s\n",
	   argv0);
   exit(1);
}

int main(int argc, char *argv[])
{
   mail_send_conf msc;
   llist empty;
   pks_incr_conf pic;
   mail_req_conf mrc;
   xfilecontents xfc;
   char *ret;

   if (argc != 1)
      usage(argv[0]);

   /* this is kinda gross, but send_mail wants to steal cat's stdout, so
      I do this. */

   if (dup2(1, 3) < 0)
      log_fatal("main", "couldn't dup fd 1 onto fd 3");

   msc.mail_delivery_client = "cat 1>&3";
   msc.maintainer_email = "marc@mit.edu";
   msc.mail_intro_file = "/tmp/mail_intro_file";
   msc.help_dir = "/tmp/help_dir";
   msc.default_lang = "EN";

   pic.this_site = ""; /* won't ever be used */
   llist_alloc(&empty);
   pic.syncsites = &empty;
   pic.msc = &msc;

   mrc.msc = &msc;
   mrc.pic = &pic;

   mrc.max_last = 3;

   log_terminal = 1;

   if (!kd_install_sig_handler(&kd_sig_handler))
      log_fatal("main", "installing kd_sig_handler");

   if (!mp_ignore_signals())
      log_fatal("main", "ignoring multiplexor signals");

   if (!kd_open("/var/tmp/db", 0, &ret))
      log_fatal("main", "database open failed");

   if (!mp_init())
      log_fatal("main", "failed initializing multiplexor");

   if (!xfilecontents_get(&xfc, stdin))
      log_fatal("main", "error reading mail message from stdin");

   mail_req(xfc.buf, xfc.len, &mrc, NULL, NULL);

   xfilecontents_free(&xfc);

   if (!mp_go())
      log_fatal("main", "error in multiplexor main loop");

   kd_close();

   exit(0);
}
