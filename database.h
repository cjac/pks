#ifndef _DATABASE_H_
#define _DATABASE_H_

/*
 * $Id: database.h,v 1.3 2003/01/06 18:52:19 dmshaw Exp $
 * 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include <time.h>

#define KD_ADD_VERBOSE 0x100000
#define KD_ADD_NO_STRIP_DISABLED 0x200000

int kd_add(unsigned char *keys, long len, int flags,
	   unsigned char **ret, long *retlen,
	   unsigned char **newkeys, long *newkeyslen);

#define KD_SEARCH_EXACT 0x1
#define KD_SEARCH_ALL 0x4
#define KD_SEARCH_IGNORE_ERRORS 0x8
#define KD_SEARCH_RETURN_DISABLED 0x10
#define KD_SEARCH_STDOUT 0x20

#define KD_SEARCH_FLAGS (KD_SEARCH_EXACT|KD_SEARCH_ALL|\
			 KD_SEARCH_IGNORE_ERRORS|KD_SEARCH_RETURN_DISABLED|\
			 KD_SEARCH_STDOUT)

#define KD_GET_EXACT KD_SEARCH_EXACT
#define KD_GET_ALL KD_SEARCH_ALL
#define KD_GET_IGNORE_ERRORS KD_SEARCH_IGNORE_ERRORS
#define KD_GET_RETURN_DISABLED KD_SEARCH_RETURN_DISABLED
#define KD_GET_STDOUT KD_SEARCH_STDOUT
#define KD_GET_MR 0x400
#define KD_GET_BINARY 0x1000

int kd_get(unsigned char *userid, long len, int flags, int mrk,
	   unsigned char **ret, long *retlen);

#define KD_INDEX_EXACT KD_SEARCH_EXACT
#define KD_INDEX_ALL KD_SEARCH_ALL
#define KD_INDEX_IGNORE_ERRORS KD_SEARCH_IGNORE_ERRORS
#define KD_INDEX_STDOUT KD_SEARCH_STDOUT
#define KD_INDEX_VERBOSE 0x100
#define KD_INDEX_FINGERPRINT 0x200
#define KD_INDEX_MR 0x400

int kd_index(unsigned char *userid, long len, int flags, int mrk,
	     unsigned char **ret, long *retlen);

#define KD_SINCE_BINARY 0x10000

int kd_since(time_t since, int flags, int mrk, time_t *last,
	     unsigned char **ret, long *retlen);

int kd_delete(unsigned char *userid, long len, int flags,
	      unsigned char **ret, long *retlen);

#define KD_DISABLE_CLEAR 0x100000

int kd_disable(unsigned char *userid, long len, int flags,
	      unsigned char **ret, long *retlen);

int kd_create(char *dbdir, int num_files, char **ret);

#define KD_OPEN_NOTXN		0x1
#define KD_OPEN_READONLY	0x2
#define KD_OPEN_RECOVER		0x4

int kd_open(char *dbdir, int flags, char **ret);
int kd_backup();
int kd_sync();
int kd_close();

void kd_sig_handler();
int kd_install_sig_handler(void (*h)());

#endif

