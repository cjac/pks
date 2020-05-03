const char rcsid_llist_c[] = "$Id: llist.c,v 1.1.1.1 2002/09/04 20:48:53 dtype Exp $";

/* 
 * Copyright (c) 1996, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "llist.h"
#include "globals.h"

void llist_alloc(llist *l)
{
   xbuffer_alloc(&(l->xb));
}

long llist_count(llist *l)
{
   return(l->xb.len/sizeof(void *));
}

int llist_add(llist *l, void *e)
{
   return(xbuffer_append(&(l->xb), (unsigned char *) &e, sizeof(e)));
}

int llist_add_sorted(llist *l, void *e, llist_order o)
{
   int nelems = l->xb.len/sizeof(void *);
   void **elems;
   int after, before, middle, order;

   /* stretch the list by one */
   if (!xbuffer_append(&(l->xb), (unsigned char *) &e, sizeof(e))) {
      dabort();
      return(0);
   }

   elems = (void **) l->xb.buf;

   /* if this is the first element, that's it. */

   if (nelems == 0)
      return(1);

   /* check if the element belongs at the beginning or end.  This 
      optimizes the case of adding already-sorted entries to a list */

   order = (*o)(e, elems[0]);

   if (order == 0) {
      /* don't add duplicates */
      l->xb.len -= sizeof(e);
      return(-1);
   } else if (order < 0) {
      /* this is overlapping, so memcpy() would break */
      memmove(elems+1, elems, (size_t) (nelems*sizeof(void *)));
      elems[0] = e;
      return(1);
   }

   order = (*o)(e, elems[nelems-1]);

   if (order == 0) {
      /* don't add duplicates */
      l->xb.len -= sizeof(e);
      return(-1);
   } else if (order > 0) {
      /* the new element was already added at the end */
      return(1);
   }

   /* bsearch for insertion point */

   /* initialize middle to 0 in case nelems == 0 */

   middle = 0;

   for (after = 0, before = nelems;
	after != before;
	) {
      middle = (after+before)/2;

      order = (*o)(e, elems[middle]);

      if (order < 0) {
	 before = middle;
      } else if (order == 0) {
	 /* don't add duplicates */
	 l->xb.len -= sizeof(e);
	 return(-1);
      } else {
	 after = middle+1;
      }
   }

   /* before == after == insertion point */

   /* this is an overlapping move */
   memmove(elems+after+1, elems+after,
	   (size_t) ((nelems-after)*sizeof(void *)));

   /* insert the new element in the right place */
   elems[after] = e;

   return(1);
}

int llist_copy(llist *dst, llist *src)
{
   return(xbuffer_append(&(dst->xb), src->xb.buf, src->xb.len));
}

int llist_sort(llist *l, llist_order o)
{
   int nelems = l->xb.len/4;
   void **elems = (void **) l->xb.buf;

   qsort(elems, (size_t) nelems, sizeof(void *), o);

   return(1);
}

static int llist_iterate_1(void **elems, int nelems, llist_iter i, void *c)
{
   int j;

   for (j=0; j<nelems; j++) 
      if (!(*i)(elems[j], c)) {
	 dabort();
	 return(0);
      }

   return(1);
}   

int llist_iterate(llist *l, llist_iter i, void *c)
{
   return(llist_iterate_1((void **) l->xb.buf,
			  l->xb.len/sizeof(void *),
			  i, c));
}

int llist_merge(llist *lout, llist *l1, llist *l2, llist_merger m, void *mc,
		llist_iter i, void *ic)
{
   int nelems1 = l1->xb.len/sizeof(void *);
   void **elems1 = (void **) l1->xb.buf;

   int nelems2 = l2->xb.len/sizeof(void *);
   void **elems2 = (void **) l2->xb.buf;

   int mout;

   while(1) {
      if ((nelems1 == 0) && (nelems2 == 0)) {
	 /* done */
	 llist_free(l1);
	 llist_free(l2);
	 return(1);
      }

      mout = (*m)(lout, nelems1?elems1[0]:NULL, nelems2?elems2[0]:NULL, mc);

      if ((mout & LLIST_MERGE_FAIL) ||
	  ((nelems1 == 0) && (mout & LLIST_MERGE_DEL_1)) ||
	  ((nelems2 == 0) && (mout & LLIST_MERGE_DEL_2)) ||
	  (mout == 0))
	 /* merge routine failed or returned invalid operation */
	 break;

      if (mout & LLIST_MERGE_DEL_1) {
	 elems1++;
	 nelems1--;
      }

      if (mout & LLIST_MERGE_DEL_2) {
	 elems2++;
	 nelems2--;
      }
   }

   /* the loop will only fall through if there's a problem.
      clean up and return failure */

   dabort();

   llist_iterate(lout, i, ic);
   llist_free(lout);
   llist_iterate_1(elems1, nelems1, i, ic);
   llist_free(l1);
   llist_iterate_1(elems2, nelems2, i, ic);
   llist_free(l2);

   return(0);
}


void llist_free(llist *l)
{
   xbuffer_free(&(l->xb));
}
