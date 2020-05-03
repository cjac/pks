#ifndef _PARSE_H_
#define _PARSE_H_

/*
 * $Id: parse.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

long scan_char(unsigned char *input, long len, long *offset, unsigned char ch,
	       long *str, long *str_len);
void scan_token(unsigned char *input, long len, long *offset,
		long *token, long *token_len);
void scan_space(unsigned char *input, long len, long *offset);
long scan_line(unsigned char *input, long len, long *offset,
	       long *line, long *line_len);
int is_token(const unsigned char *str, long strlen,
	     const char *token, long toklen, int exact);

#endif
