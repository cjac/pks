const char rcsid_pksdctl_c[] = "$Id: pksdctl.c,v 1.3 2002/10/08 04:04:42 dmshaw Exp $";

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
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void usage(char *argv0)
{
   fprintf(stderr, "usage: %s socket string\n", argv0);
   fprintf(stderr, "usage:  %s <pksd socket> <command> [arg]\n", argv0);
   fprintf(stderr, "  commands:  mail <msg>\n");
   fprintf(stderr, "             disable <userid>\n");
   fprintf(stderr, "             shutdown\n");

   exit(1);
}

int write_all(int fd, void *buf, unsigned int nbyte)
{
   int cc, len;

   len = nbyte;

   while (len > 0) {
      cc = write(fd, buf, len);
      if (cc < 0)
	 return(-1);

      buf = (void *) (((char *) buf) + cc);
      len -= cc;
   }

   return(nbyte);
}

int main(int argc, char *argv[])
{
   int s, len;
   struct sockaddr_un s_un;
   char *str;
   char buf[1024];

   if (argc != 3)
      usage(argv[0]);

   openlog("pksdctl", LOG_PID, LOG_LOCAL2);

   if (sizeof(s_un.sun_path) < (sizeof(argv[1])+1)) {
      syslog(LOG_CRIT,
	     "socket name length doesn't fit in sockaddr_un");
      exit(0);
   }

   if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
      syslog(LOG_CRIT, "failed creating socket: %d", errno);
      exit(0);
   }

   memset(&s_un, '\0', sizeof(s_un));

   s_un.sun_family = AF_UNIX;
   strcpy(s_un.sun_path, argv[1]);

   if (connect(s, (struct sockaddr *) &s_un, sizeof(s_un)) < 0) {
      if (errno == ECONNREFUSED) {
	 syslog(LOG_INFO, "Can't write to socket: no process is reading");
	 exit(0);
      }

      syslog(LOG_ERR, "Error opening socket: errno = %d", errno);
      exit(1);
   }

   str = argv[2];
   len = strlen(str);

   if (write_all(s, str, len) < 0) {
      syslog(LOG_ERR, "Error writing socket: errno = %d", errno);
      exit(1);
   }

   if (write_all(s, "\ndone\n", 6) < 0) {
      syslog(LOG_ERR, "Error writing socket: errno = %d", errno);
      exit(1);
   }

   if (shutdown(s, 1) < 0) {
      syslog(LOG_ERR, "Error shutting down socket: errno = %d", errno);
      exit(1);
   }

   if ((len = read(s, buf, sizeof(buf))) < 0) {
      syslog(LOG_ERR, "Error reading socket: errno = %d", errno);
      exit(1);
   }

   if (len > 0)
      syslog(LOG_ERR, "Data available on socket.  This shouldn't happen.");

   exit(0);
}
