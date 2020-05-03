#ifndef _ARMOR_H_
#define _ARMOR_H_

/*
 * $Id: armor.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "pgputil.h"

int decode_ascii(ddesc *data, packet_handler h, void *c);
int encode_ascii_size(ddesc *binarydata, const char *desc);
int encode_ascii(ddesc *binarydata, const char *headerline, ddesc *asciidata);

#endif
