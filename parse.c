const char rcsid_parse_c[] = "$Id: parse.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <ctype.h>

#include "util.h"
#include "parse.h"

/* the return value is the number of characters in string up to
   and not including the char */

long scan_char(unsigned char *input, long len, long *offset, unsigned char ch,
	       long *str, long *str_len)
{
   int i;

   if (*offset == len) {
      *str = -1;
      *str_len = 0;
      return(0);
   } 

   for (i=*offset; i<len; i++)
      if (input[i] == ch)
	 break;

   if (i == len) {
      /* end of input reached before ch.  don't return a string
	 or move the pointer, but return the number of chars seen */
      *str = -1;
      *str_len = 0;
      return(i-*offset);
   }

   i++;

   *str = *offset;
   *str_len = i-*offset;

   *offset = i;

   return(*str_len - 1);
}

void scan_token(unsigned char *input, long len, long *offset,
		long *token, long *token_len)
{
   int i;

   if (*offset == len) {
      *token = -1;
      *token_len = 0;
      return;
   } 

   /* scan for end of token */

   for (i=*offset; i<len && !isspace(input[i]); i++)
      /* SUPPRESS 570 */
      ;

   *token = *offset;
   *token_len = i-*offset;

   *offset = i;

   return;
}

void scan_space(unsigned char *input, long len, long *offset)
{
   int i;

   for (i=*offset; i<len && (input[i] != '\n') && isspace(input[i]); i++)
      /* SUPPRESS 570 */
      ;

   *offset = i;

   return;
}

/* the return value is the number of characters in the line
   not including trailing CR*LF */

long scan_line(unsigned char *input, long len, long *offset,
	       long *line, long *line_len)
{
   int cnt;
   long tmp;

   cnt = scan_char(input, len, offset, '\012', line, line_len);

   /* strip off trailing CR */

   tmp = (*line>=0)?*line:*offset;

   while ((cnt > 0) && (input[tmp+cnt-1] == '\015'))
      cnt--;

   return(cnt);
}

int is_token(const unsigned char *str, long strlen,
	     const char *token, long toklen, int exact)
{
   if (strlen < toklen)
      return(0);

   if (exact && (strlen != toklen))
      return(0);

   return(my_strncasecmp((char *) str, (char *) token, (int) toklen) == 0);
}

