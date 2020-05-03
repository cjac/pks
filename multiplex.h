#ifndef _MULTIPLEX_H_
#define _MULTIPLEX_H_

/*
 * $Id: multiplex.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

typedef void (*mp_input_handler)(int fd, unsigned char *input,
				long len, int eof, void *c);
typedef void (*mp_output_handler)(int fd, unsigned char *output,
				 long len, void *c);
int mp_init();
void mp_terminate(int code);
int mp_add_read(int fd, int expire, mp_input_handler ih, void *c);
int mp_add_listen(int fd, int expire, mp_input_handler ih, void *c);
void mp_delete_read(int fd);
int mp_add_write(int fd, int expire, unsigned char *output, long len,
		 mp_output_handler oh, void *c);
void mp_delete_write(int fd);
int mp_go();
int mp_ignore_signals(void);

#define MP_NODESC	-1
#define MP_ERROR	0
/* anything else is defined by the application */

#endif

