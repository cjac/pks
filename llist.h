#ifndef _LLIST_H_
#define _LLIST_H_

/*
 * $Id: llist.h,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $
 * 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */

#include "util.h"

#define LLIST_MERGE_DEL_1  0x1
#define LLIST_MERGE_DEL_2  0x2
#define LLIST_MERGE_FAIL   0x4

typedef struct _llist {
   xbuffer xb;
} llist;

typedef int (*llist_iter)(void *e, void *c);
/* This is the same as what qsort() and bsearch() take */
typedef int (*llist_order)(const void *e1, const void *e2);
typedef int (*llist_merger)(llist *lout, void *e1, void *e2, void *c);

void llist_alloc(llist *l);
long llist_count(llist *l);
int llist_add(llist *l, void *e);
/* if this returns -1, then the element was already present,
   and should be free'd */
int llist_add_sorted(llist *l, void *e, llist_order o);
int llist_copy(llist *dst, llist *src);
int llist_sort(llist *l, llist_order o);
int llist_iterate(llist *l, llist_iter i, void *c);
void llist_free(llist *l);

/* Merges l1 and l2 destructively into lout.

   While there are elements in l1 and l2, m is called on the first
   element of each list.  Once one list's elements are exhausted,
   NULL is passed instead of an element pointer from that list.  The
   merge terminates when l1 and l2 are empty.

   m should look at the two elements passed to it.  It may do nothing,
   add one or the other to lout, or combine the two elements and add
   that to lout.  The return value must request that one or both elements
   be deleted from their respective lists.  The elements should be freed
   inside m if they are not used.

   If an error occurs, all remaining elements will be passed to i, if
   i is non-null. The merge function will then return 0, with all
   lists empty, and need not be freed
*/

int llist_merge(llist *lout, llist *l1, llist *l2, llist_merger m, void *mc,
		llist_iter i, void *ic);

#endif
