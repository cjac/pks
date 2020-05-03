const char rcsid_kd_types_c[] = "$Id: kd_types.c,v 1.7 2003/02/03 05:14:31 dmshaw Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "database.h"
#include "llist.h"
#include "pgputil.h"
#include "kd_types.h"

void sigs_elem_alloc(sigs_elem *se)
{
   xbuffer_alloc(&(se->keyid));
   xbuffer_alloc(&(se->sig));
}

void userids_elem_alloc(userids_elem *ue)
{
   xbuffer_alloc(&(ue->uid));
   llist_alloc(&(ue->sigs));
}

void keys_elem_alloc(keys_elem *ke)
{
   xbuffer_alloc(&(ke->pubkey));
   xbuffer_alloc(&(ke->modbits));
   xbuffer_alloc(&(ke->expbits));
   xbuffer_alloc(&(ke->keyidbits));
   ke->primary = NULL;
   xbuffer_alloc(&(ke->revocation));
   llist_alloc(&(ke->userids));
   llist_alloc(&(ke->words));
   xbuffer_alloc(&(ke->subkey));
   xbuffer_alloc(&(ke->subkeysig));
}

int malloc_elem_free(void *e, void *c)
{
   free(e);

   return(1);
}

int sigs_elem_free(void *e, void *c)
{
   sigs_elem *se = (sigs_elem *) e;

   xbuffer_free(&(se->keyid));
   xbuffer_free(&(se->sig));
   malloc_elem_free(e, c);

   return(1);
}

int userids_elem_free(void *e, void *c)
{
   userids_elem *ue = (userids_elem *) e;

   xbuffer_free(&(ue->uid));
   llist_iterate(&(ue->sigs), sigs_elem_free, c);
   llist_free(&(ue->sigs));
   malloc_elem_free(e, c);

   return(1);
}

int keys_elem_free(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;

   xbuffer_free(&(ke->pubkey));
   xbuffer_free(&(ke->modbits));
   xbuffer_free(&(ke->expbits));
   xbuffer_free(&(ke->keyidbits));
   if (ke->primary) {
      userids_elem_free((void *) ke->primary, c);
      ke->primary = NULL;
   }
   xbuffer_free(&(ke->revocation));
   llist_iterate(&(ke->userids), userids_elem_free, c);
   llist_free(&(ke->userids));
   xbuffer_free(&(ke->subkey));
   xbuffer_free(&(ke->subkeysig));
   llist_iterate(&(ke->words), malloc_elem_free, c);
   llist_free(&(ke->words));
   malloc_elem_free(e, c);

   return(1);
}

int bytestr_order(const unsigned char *s1, long s1len,
		  const unsigned char *s2, long s2len)
{
   int o;
   
   /* if the initial substrings are different */

   o = memcmp((const void *) s1, (const void *) s2,
	      ((s1len<s2len)?s1len:s2len));

   /* return that */

   if (o)
      return(o);

   /* otherwise return the shorter string, or equal if the lengths are */

   return(s1len - s2len);
}

int words_elem_order(const void *e1, const void *e2)
{
   const words_elem *we1 = (const words_elem *) e1;
   const words_elem *we2 = (const words_elem *) e2;
   int o;

   /* if the initial substrings are different */

   o = my_strncasecmp((const char *) we1->ptr, (const char *) we2->ptr,
		      ((we1->len<we2->len)?we1->len:we2->len));

   /* return that */

   if (o)
      return(o);

   /* otherwise return the shorter string, or equal if the lengths are */

   return(we1->len - we2->len);
}

int sigs_elem_order(const void *e1, const void *e2)
{
   ddesc dd1,dd2;
   long dummy,len1,len2;

   dd1.data=((const sigs_elem *)e1)->sig.buf;
   dd1.size=((const sigs_elem *)e1)->sig.len;
   dd1.offset=0;

   dd2.data=((const sigs_elem *)e2)->sig.buf;
   dd2.size=((const sigs_elem *)e2)->sig.len;
   dd2.offset=0;

   if(!decode_psf(&dd1,&dummy,&len1))
     return -1;
   if(!decode_psf(&dd2,&dummy,&len2))
     return 1;

   /* Note that we're comparing data only, and not the packet header
      information.  This is to ensure that the same signature encoded
      with different length bytes does not appear as a different
      signature.  In v4 sigs, it is possible to rearrange the unhashed
      subpackets, but arguably that's a different sig anyway. */

   return (bytestr_order(&dd1.data[dd1.offset],dd1.size-dd1.offset,
			 &dd2.data[dd2.offset],dd2.size-dd2.offset));
}

int userids_elem_order(const void *e1, const void *e2)
{
   const userids_elem *ue1 = (const userids_elem *) e1;
   const userids_elem *ue2 = (const userids_elem *) e2;

   return(bytestr_order(ue1->uid.buf, ue1->uid.len,
			ue2->uid.buf, ue2->uid.len));
}

int keys_elem_order(const void *e1, const void *e2)
{
   const keys_elem *ke1 = (const keys_elem *) e1;
   const keys_elem *ke2 = (const keys_elem *) e2;
   int o;

   /* smaller modulus first */

   if ((o = ke1->modbits.len - ke2->modbits.len) == 0)
      o = memcmp((const void *) ke1->modbits.buf,
		 (const void *) ke2->modbits.buf,
		 (size_t) ke1->modbits.len);

   return(o);
}

