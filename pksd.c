const char rcsid_pksd_c[] = "$Id: pksd.c,v 1.8 2002/11/05 04:07:38 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include "pks_config.h"
#include "pks_socket.h"
#include "pks_www.h"
#include "pks_incr.h"
#include "mail_send.h"
#include "mail_req.h"
#include "database.h"
#include "multiplex.h"
#include "globals.h"

int main(int argc, char *argv[])
{
   char *argv0, *ret;
   pks_config pc;
   mail_send_conf msc;
   pks_incr_conf pic;
   mail_req_conf mrc;
   pks_socket_conf psc;
   pks_www_conf pwc;
   int retval;

   argv0 = argv[0];

#ifdef LOG_LOCAL2
   openlog("pksd", LOG_PID, LOG_LOCAL2);
#else
   /* bsd4.2/ultrix */
   openlog("pksd", LOG_PID);
#endif

#ifdef DEBUG
   if (argc > 1) {
      if (strcmp(argv[1], "-D") == 0) {
	 debug = 1;
	 argc--;
	 argv++;
      }
   }
#endif

   if (argc != 2) {
      char buf[1024];

      sprintf(buf, "usage: %s conf_file", argv0);
      fprintf(stderr, "%s\n", buf);
      log_fatal("main", buf);
   }

   if (!pks_read_conf_file(argv[1], &pc)) {
      fprintf(stderr, "error reading configuration file\n"
	      "Did you forget to configure the server?\n"
	      "See the INSTALL file for help.\n");
      log_fatal("main", "error reading configuration file");
   }

   msc.mail_delivery_client = pc.mail_delivery_client;
   msc.maintainer_email = pc.maintainer_email;
   msc.mail_intro_file = pc.mail_intro_file;
   msc.help_dir = pc.help_dir;
   msc.default_lang = pc.default_lang;

   pic.this_site = pc.this_site;
   pic.syncsites = &(pc.syncsites);
   pic.msc = &msc;

   mrc.msc = &msc;
   mrc.pic = &pic;
   mrc.max_last = pc.max_last;
   mrc.max_last_reply_keys = pc.max_last_reply_keys;
   mrc.max_reply_keys = pc.max_reply_keys;

   psc.socket = pc.socket_name;
   psc.mrc = &mrc;

   pwc.addr = pc.www_addr;
   pwc.port = pc.www_port;
   pwc.readonly = pc.www_readonly;
   pwc.www_dir = pc.www_dir;
   pwc.max_reply_keys = pc.max_reply_keys;
   pwc.pic = &pic;

   if (!pc.www_port && (pc.mail_delivery_client[0] == '\0')) {
      fprintf(stderr, "The configuration file did not specify any servers\n"
	      "to run.  Did you forget to configure the server?\n"
	      "See the INSTALL file for help.\n");
      log_fatal("main", "nothing to do!");
      exit(1);
   }

   if (!kd_install_sig_handler(&kd_sig_handler))
      log_fatal("main", "installing kd_sig_handler");

   if (!mp_ignore_signals())
      log_fatal("main", "ignoring multiplexor signals");

   /* XXX there is no way to run the daemon without transactions.
      I do not consider this a major problem --marc */
   if (!kd_open(pc.db_dir, 0, &ret))
      log_fatal("main", "database open failed");

   if (!mp_init())
      log_fatal("main", "failed initializing multiplexor");

   if (pc.www_port)
      pks_www_init(&pwc);

   if (pc.mail_delivery_client[0])
       pks_socket_init(&psc);

   log_info("main", "pks server started");

   retval = mp_go();

   kd_close();

   switch (retval) {
   case MP_NODESC:
      log_error("main", "last multiplexer descriptor deleted unexpectedly");
      break;
   case MP_ERROR:
      log_fatal("main", "error in multiplexor main loop");
      break;
   case EXIT_SIGNAL:
      log_info("main", "pksd terminated by signal");
      break;

   /* case EXIT_SHUTDOWN: pks server shut down by pksdctl */
   }

   log_info("main", "pks server exited");

   exit(0);
}
