#ifndef _PGPCRC_H_
#define _PGPCRC_H_

/*
 * $Id: pgpcrc.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "pgputil.h"

void crc_compute(ddesc *data, long *crc);

#endif
