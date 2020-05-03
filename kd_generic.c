const char rcsid_kd_generic_c[] = "$Id: kd_generic.c,v 1.4 2002/09/08 20:54:24 rlaager Exp $";

/* 
 * Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
 * See the LICENSE file in the release for redistribution information.
 */


#include <db.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "database.h"
#include "globals.h"
#include "llist.h"
#include "kd_types.h"
#include "kd_internal.h"

/* this file contains functions which are common to two different
   database operations, and functions which perform operations
   on the database itself. */

/* multiple keydb files are supported.  which file is used is
   determined by the lsb 16 bits of the keyid mod the number of
   databases.  The number of database files to use is specified at
   create-time, written out, and then learned at run-time by reading
   the file from the dbdir. */

static DB_ENV dbenv;

int num_keydb;
DB **keydb_files = NULL;
DB *worddb = NULL;
DB *timedb = NULL;

DB *keydb(DBT *key)
{
   /* keyid's are 8 bytes, msb first.  so start from the end.  use 16
      bits, since that's enough to divide by any small number of db
      files. */
   unsigned char *keydata = (unsigned char *) key->data;
   unsigned long keyidnum;

   keyidnum = (keydata[KEYDB_KEYID_BYTES-2]<<8)|keydata[KEYDB_KEYID_BYTES-1];

   return(keydb_files[keyidnum % num_keydb]);
}

int kd_add_userid_to_wordlist(llist *wl,
			      unsigned char *userid, long userid_len)
{
   unsigned char *start;
   unsigned char *end;
   words_elem *tmp;
   int ret;

   end = userid;

   while (end < userid+userid_len) {
      /* find beginning of word */
      start = end;
      while ((start < userid+userid_len) && !isalnum(*start))
	 start++;

      /* find end of word */
      end = start;
      while ((end < userid+userid_len) && isalnum(*end))
	 end++;

      /* store it if it's > 1 char */

      if (end-start > 1) {
	 if ((tmp = (words_elem *) malloc(sizeof(words_elem))) == NULL)
	    fail();
	 tmp->ptr = start;
	 tmp->len = end-start;
	 if (!(ret = llist_add_sorted(wl, tmp, words_elem_order))) {
	    free(tmp);
	    fail();
	 }
	 if (ret == -1)
	    free(tmp);
      }
   }

   return(1);
}

int sigs_elem_marshall(void *e, void *c)
{
   sigs_elem *se = (sigs_elem *) e;
   xbuffer *xb = (xbuffer *) c;

   return(xbuffer_append(xb, se->sig.buf, se->sig.len));
}

int userids_elem_marshall(void *e, void *c)
{
   userids_elem *ue = (userids_elem *) e;
   xbuffer *xb = (xbuffer *) c;

   if (!xbuffer_append(xb, ue->uid.buf, ue->uid.len))
      fail();

   return(llist_iterate(&(ue->sigs), sigs_elem_marshall, c));
}

int kd_keys_elem_marshall(void *e, void *c)
{
   keys_elem *ke = (keys_elem *) e;
   xbuffer *xb = (xbuffer *) c;

   if (ke->disabled > 0)
      return(1);

   if (!xbuffer_append(xb, ke->pubkey.buf, ke->pubkey.len))
      fail();

   if (ke->disabled)
      if (!xbuffer_append_str(xb, "\260\001\040"))
	 fail();

   if (!xbuffer_append(xb, ke->revocation.buf, ke->revocation.len))
      fail();

   if (!xbuffer_append(xb, ke->primary->uid.buf, ke->primary->uid.len))
      fail();

   if (!llist_iterate(&(ke->primary->sigs), sigs_elem_marshall, c))
      fail();

   if (!llist_iterate(&(ke->userids), userids_elem_marshall, c))
      fail();

   if (!xbuffer_append(xb, ke->subkey.buf, ke->subkey.len))
      fail();

   if (!xbuffer_append(xb, ke->subkeysig.buf, ke->subkeysig.len))
      fail();

  return 1;
}

int kd_db_store_keyblock(kd_txn tid, llist *keys, error *err)
{
   DBT key, newdata;
   xbuffer newxb;
   keys_elem *ke = (keys_elem *) (*((void **) keys->xb.buf));

   memset(&key, 0, sizeof(key));
   memset(&newdata, 0, sizeof(newdata));

   /* ke points to first key, which is enough to derive the keyid
      for the database key */

   xbuffer_alloc(&newxb);

   if (!llist_iterate(keys, kd_keys_elem_marshall, (void *) &newxb)) {
      xbuffer_free(&newxb);
      err->fatal = 1;
      err->str = "internal error while marshalling keyblock";
      fail();
   }

   key.data = &(ke->keyidbits.buf[4]);
   key.size = KEYDB_KEYID_BYTES;

   newdata.data = (void *) newxb.buf;
   newdata.size = (size_t) newxb.len;

   if ((*(keydb(&key)->put))(keydb(&key), tid, &key, &newdata, 0) < 0) {
      xbuffer_free(&newxb);
      err->fatal = 1;
      sprintf(err->buf, "error %s keydb, errno = %d", "writing to", errno);
      fail();
   }

   xbuffer_free(&newxb);

   return(1);
}

/* log utility functions */

void kd_log_start(char *fct, unsigned char *userid, long len, int flags)
{
   char buf[1024];

   if (userid)
      sprintf(buf, "userid=\"%.*s\"%s, flags=%x",
	      (int) ((len<=900)?len:900), userid, (len<=900)?"":" (truncated)",
	      flags);
   else
      sprintf(buf, "flags=%x", flags);

   log_info(fct, buf);
}

void kd_log_finish(char *fct, int success)
{
   if (success)
      log_info(fct, "completed successfully");
   else
      log_info(fct, "completed with error");
}

/* transaction functions */

int kd_txn_begin(kd_txn *tid, error *err)
{
    int ret;

    *tid = NULL;

    if (! dbenv.tx_info)
	return(1);

    if ((ret = txn_begin(dbenv.tx_info, NULL, tid))) {
	err->fatal = 0;
	err->str = "Failed beginning transaction";
	return(0);
    }

    return(1);
}

int kd_txn_commit(kd_txn tid, error *err)
{
    int ret;
    static int txn_count = 0;

    if (! tid)
	return(1);

    if ((ret = txn_commit(tid))) {
	err->fatal = 0;
	err->str = "Failed committing transaction";
	return(0);
    }
 
     txn_count++;
     if (txn_count > KD_MAX_TXN_WO_CKPT) {
       int count;
       for (count=0; count<10; count++) {
          if ((ret = txn_checkpoint(dbenv.tx_info, 0, 0)) == DB_INCOMPLETE) {
             sleep(1);
             continue;
          }
         /* Only reset if successful */
         txn_count = 0;
         break;
       }
      }
  
      return(1);
  }
  

int kd_txn_abort(kd_txn tid, error *err)
{
    int ret;

    if (! tid)
	return(1);

    if ((ret = txn_abort(tid))) {
	if (err) {
	    err->fatal = 0;
	    err->str = "Failed aborting transaction";
	}
	return(0);
    }

    return(1);
}

/* create/open/close/sync */

static int kd_worddata_compare(const DBT *a, const DBT *b)
{
   return(memcmp(b->data, a->data, 12));
}

static void kd_errcall(const char *db_errpfx, char *buffer)
{
   log_error(db_errpfx?db_errpfx:"db_errcall", buffer);
}

/* if create is non-zero, it specifies the number of database
   files to use.  if it is zero, then the code will read a file
   containing the number of database files to use */
int kd_open_1(char *dbdir, int create, int oflags, error *err)
{
   int i, appflags, flags, db_err, fd;
   char keydbname[20];
   DB_INFO keyinfo, wordinfo, timeinfo;

   memset(&dbenv, 0, sizeof(dbenv));

   if ((oflags & (KD_OPEN_READONLY|KD_OPEN_RECOVER)) && create) {
       err->fatal = 1;
       err->str = "Cannot create or recover database with readonly flag set";
       fail();
   }

   dbenv.db_errcall = kd_errcall;
   /* This is a tunable parameter.  Making it bigger improves
      performance at the expense of memory use.  Making it bigger
      than available physical memory will not help. */
   dbenv.mp_size = 20*1024*1024;

   appflags = DB_INIT_MPOOL|DB_INIT_LOCK|DB_CREATE;

   if (!(oflags & KD_OPEN_NOTXN))
       appflags |= DB_INIT_LOG|DB_INIT_TXN;

   if (oflags & KD_OPEN_RECOVER) {
       appflags |= DB_INIT_LOG|DB_RECOVER;
       dbenv.db_verbose = 1;
   }

   if ((db_err = db_appinit(dbdir, NULL, &dbenv, appflags))) {
      err->fatal = 1;
      sprintf(err->buf, "Error initializing db (errno = %d)", db_err);
      fail();
   }

   if (create) {
      FILE *nkdb;
      char line[1024];

      sprintf(line, "%s/num_keydb", dbdir);

      if ((nkdb = fopen(line, "r")) == NULL)
	 goto do_create;

      if (fgets(line, sizeof(line), nkdb) == NULL) {
	 fclose(nkdb);
	 goto do_create;
      }

      if (fclose(nkdb) == EOF)
	 goto do_create;

      num_keydb = atoi(line);

      if ((num_keydb < 1) || (num_keydb > 999))
	 goto do_create;

      for (i=0; i<num_keydb; i++) {
	 sprintf(line, "keydb%03d", i);
	 unlink(line);
      }

   do_create:
      flags = DB_CREATE|DB_TRUNCATE;
      num_keydb = create;

      sprintf(line, "%s/num_keydb", dbdir);

      if ((nkdb = fopen(line, "w")) == NULL) {
	 err->fatal = 1;
	 sprintf(err->buf, "Error opening num_keydb (errno = %d)", errno);
	 fail();
      }

      if (fprintf(nkdb, "%d\n", num_keydb) == 0) {
	 fclose(nkdb);
	 err->fatal = 1;
	 sprintf(err->buf, "Error writing to num_keydb (errno = %d)", errno);
	 fail();
      }

      if (fclose(nkdb) == EOF) {
	 err->fatal = 1;
	 sprintf(err->buf, "Error closing num_keydb (errno = %d)", errno);
	 fail();
      }
   } else {
      FILE *nkdb;
      char line[1024];

      flags = (oflags & KD_OPEN_READONLY)?DB_RDONLY:0;

      sprintf(line, "%s/num_keydb", dbdir);

      if ((nkdb = fopen(line, "r")) == NULL) {
	 err->fatal = 1;
	 sprintf(err->buf, "Error opening num_keydb (errno = %d)", errno);
	 fail();
      }

      if (fgets(line, sizeof(line), nkdb) == NULL) {
	 fclose(nkdb);
	 err->fatal = 1;
	 if (feof(nkdb))
	    sprintf(err->buf, "End of file reading num_keydb");
	 else
	    sprintf(err->buf, "Error reading num_keydb (errno = %d)", errno);
	 fail();
      }

      if (fclose(nkdb) == EOF) {
	 err->fatal = 1;
	 sprintf(err->buf, "Error closing num_keydb (errno = %d)", errno);
	 fail();
      }

      num_keydb = atoi(line);

      if ((num_keydb < 1) || (num_keydb > 999)) {
	 err->fatal = 1;
	 sprintf(err->buf, ("num_keydb is out of bounds (%d is not"
			    "between 1 and 999 inclusive)"), errno);
	 fail();
      }
   }

   if ((keydb_files = (DB **) malloc(sizeof(DB *)*num_keydb)) == NULL) {
      err->fatal = 1;
      sprintf(err->buf, "Error allocating keydb state array");
      fail();
   }

   for (i=0; i<num_keydb; i++)
       keydb_files[i] = 0;

   memset(&keyinfo, 0, sizeof(keyinfo));
   keyinfo.db_pagesize = 8192;

   for (i=0; i<num_keydb; i++) {
      sprintf(keydbname, "keydb%03d", i);

      if ((db_err = db_open(keydbname, DB_HASH, flags, 0644, &dbenv, &keyinfo,
			    &keydb_files[i]))) {
	 err->fatal = 1;
	 sprintf(err->buf, "Error opening %s (errno = %d)", keydbname, db_err);
	 fail();
      }

      if ((db_err = ((*(keydb_files[i]->fd))(keydb_files[i], &fd)))) {
	 err->fatal = 1;
	 sprintf(err->buf, "failed getting %s fd: %d", keydbname, db_err);
	 fail();
      }

      if (fcntl(fd, F_SETFD, 1) < 0) {
	 err->fatal = 1;
	 sprintf(err->buf, "failed making keydb close-on-exec: %d", errno);
	 fail();
      }
   }

   memset(&wordinfo, 0, sizeof(wordinfo));
   wordinfo.db_pagesize = 8192;
   wordinfo.dup_compare = kd_worddata_compare;
   wordinfo.flags = DB_DUP | DB_DUPSORT;
   
   if ((db_err = db_open("worddb", DB_BTREE, flags,
			 0644, &dbenv, &wordinfo, &worddb))) {
      err->fatal = 1;
      sprintf(err->buf, "Error opening worddb (errno = %d)", db_err);
      fail();
   }

   if ((db_err = ((*(worddb->fd))(worddb, &fd)))) {
      err->fatal = 1;
      sprintf(err->buf, "failed getting worddb fd: %d", db_err);
      fail();
   }

   if (fcntl(fd, F_SETFD, 1) < 0) {
      err->fatal = 1;
      sprintf(err->buf, "failed making worddb close-on-exec: %d", errno);
      fail();
   }

   memset(&timeinfo, 0, sizeof(timeinfo));
   keyinfo.db_pagesize = 8192;

   if ((db_err = db_open("timedb", DB_BTREE, flags, 0644, &dbenv, &timeinfo,
			 &timedb))) {
      err->fatal = 1;
      sprintf(err->buf, "Error opening timedb (errno = %d)", db_err);
      fail();
   }

   if ((db_err = ((*(timedb->fd))(timedb, &fd)))) {
      err->fatal = 1;
      sprintf(err->buf, "failed getting timedb fd: %d", db_err);
      fail();
   }

   if (fcntl(fd, F_SETFD, 1) < 0) {
      err->fatal = 1;
      sprintf(err->buf, "failed making timedb close-on-exec: %d", errno);
      fail();
   }

   return(1);
}

/* this not only copies files, but leaves holes if there's no data */

int copy_file(const char *src, const char *dst)
{
   int fsrc, fdst;
   unsigned char buf[1024];
   int cnt, total;
   int write_last = 0;

   total = 0;

   if ((fsrc = open(src, O_RDONLY, 0)) < 0)
      return(-1);

   if ((fdst = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0) {
      close(fsrc);
      return(-1);
   }

   while (1) {
      cnt = read(fsrc, (void *) buf, sizeof(buf));

      if (cnt < 0) {
	 close(fsrc);
	 close(fdst);
	 return(-1);
      }

      if (cnt == 0)
	 break;

      total += cnt;

      if (memcmp(buf, zeros, cnt) == 0) {
	 write_last = 1;
	 if (lseek(fdst, cnt, SEEK_CUR) < 0) {
	    close(fsrc);
	    close(fdst);
	    return(-1);
	 }
      } else {
	 int wptr = 0;

	 while (cnt > 0) {
	    write_last = 0;
	    if ((wptr = write(fdst, (void *) (buf+wptr), cnt)) < 0) {
	       close(fsrc);
	       close(fdst);
	       return(-1);
	    }

	    cnt -= wptr;
	 }
      }
   }

   if (write_last) {
      /* Need to write into the last location, at least on Solaris */
      if (lseek(fdst, -1, SEEK_CUR) < 0
          || write(fdst, zeros, 1) != 1) {
         log_error("copy_file", strerror(errno));
         close(fsrc);
         close(fdst);
         return(-1);
      }
   }

   close(fsrc);
   close(fdst);

   return(total);
}

/* this can only be called after kd_open_1() */
int kd_backup_1()
{
   char buf[1024];
   char keydbname[20], bkeydbname[30];
   int i;
   
   if ((mkdir("backup", 0755) < 0) && (errno != EEXIST)) {
      kd_sync();
      sprintf(buf, "failed creating backup/ dir: errno = %d", errno);
      log_error("kd_backup_1", buf);
      return(0);
   }

   if ((unlink("backup/num_keydb") < 0) && (errno != ENOENT)) {
      kd_sync();
      sprintf(buf, "failed removing old backup/num_keydb: errno = %d", errno);
      log_error("kd_backup_1", buf);
      return(0);
   }
		
   for (i=0; i<num_keydb; i++) {
      sprintf(bkeydbname, "backup/keydb%03d", i);

      if ((unlink(bkeydbname) < 0) && (errno != ENOENT)) {
	 kd_sync();
	 sprintf(buf, "failed removing old %s: errno = %d", bkeydbname, errno);
	 log_error("kd_backup_1", buf);
	 return(0);
      }
   }
		
   if ((unlink("backup/worddb") < 0) && (errno != ENOENT)) {
      kd_sync();
      sprintf(buf, "failed removing old backup/worddb: errno = %d", errno);
      log_error("kd_backup_1", buf);
      return(0);
   }
		
   if ((unlink("backup/timedb") < 0) && (errno != ENOENT)) {
      kd_sync();
      sprintf(buf, "failed removing old backup/timedb: errno = %d", errno);
      log_error("kd_backup_1", buf);
      return(0);
   }
		
   kd_sync();

   if (copy_file("num_keydb", "backup/num_keydb") < 0) {
      kd_sync();
      sprintf(buf, "failed copying worddb to backup/worddb: errno = %d",
	      errno);
      log_error("kd_backup_1", buf);
      return(0);
   }
      
   for (i=0; i<num_keydb; i++) {
      sprintf(keydbname, "backup/keydb%03d", i);
      sprintf(bkeydbname, "keydb%03d", i);

      if (copy_file(keydbname, bkeydbname) < 0) {
	 kd_sync();
	 sprintf(buf, "failed copying %s to %s: errno = %d", keydbname,
		 bkeydbname, errno);
	 log_error("kd_backup_1", buf);
	 return(0);
      }
   }
      
   if (copy_file("worddb", "backup/worddb") < 0) {
      kd_sync();
      sprintf(buf, "failed copying worddb to backup/worddb: errno = %d",
	      errno);
      log_error("kd_backup_1", buf);
      return(0);
   }
      
   if (copy_file("timedb", "backup/timedb") < 0) {
      kd_sync();
      sprintf(buf, "failed copying timedb to backup/timedb: errno = %d",
	      errno);
      log_error("kd_backup_1", buf);
      return(0);
   }

   return(1);
}

void kd_sync_1()
{
   int i;

   (*(timedb->sync))(timedb, 0);
   (*(worddb->sync))(worddb, 0);
   for (i=0; i<num_keydb; i++)
      (*(keydb_files[i]->sync))(keydb_files[i], 0);
}

void kd_close_1()
{
   int count;
   int i;
   int ret = 0;
   char buf[MAXPATHLEN+100];
   char **loglist, **logfileptr;

   if (timedb)
      (*(timedb->close))(timedb, 0);
   if (worddb)
      (*(worddb->close))(worddb, 0);
   for (i=0; i<num_keydb; i++)
      if (keydb_files[i])
	 (*(keydb_files[i]->close))(keydb_files[i], 0);

   if (dbenv.tx_info) {
      /* I don't know why I need to do this twice, but if I don't,
	 log_archive() returns no files */

      for (count=0; count<10; count++) {
	 if ((ret = txn_checkpoint(dbenv.tx_info, 0, 0)) == DB_INCOMPLETE) {
	    sleep(1);
	    continue;
	 }

	 break;
      }

      if (ret) {
	 sprintf(buf, "failed db checkpointing: errno = %d", ret);
	 log_error("kd_close_1", buf);
	 return;
      }

      for (count=0; count<10; count++) {
	 if ((ret = txn_checkpoint(dbenv.tx_info, 0, 0)) == DB_INCOMPLETE) {
	    sleep(1);
	    continue;
	 }

	 break;
      }

      if (ret) {
	 sprintf(buf, "failed db checkpointing: errno = %d", ret);
	 log_error("kd_close_1", buf);
	 return;
      }

      if ((ret = log_archive(dbenv.lg_info, &loglist, DB_ARCH_ABS, NULL))) {
	 sprintf(buf, "failed listing unneeded log files: errno = %d", ret);
	 log_error("kd_close_1", buf);
	 return;
      }


      if (loglist) {
	 for (logfileptr = loglist; *logfileptr; logfileptr++) {
	    if ((ret = unlink(*logfileptr))) {
	       sprintf(buf, "failed removing log file %s: errno = %d",
		       *logfileptr, ret);
	       log_error("kd_close_1", buf);
	       return;
	    }
	 }

	 free(loglist);
      }
   }

   if ((ret = db_appexit(&dbenv))) {
       sprintf(buf, "failed closing db subsystems: errno = %d", ret);
       log_error("kd_close_1", buf);
   }
}

int kd_create(char *dbdir, int num_files, char **ret)
{
   error err;

   err.str = err.buf;

   kd_log_start("kd_create", NULL, 0, 0);

   if (kd_open_1(dbdir, num_files, 0, &err)) {
      kd_log_finish("kd_create", 1);

      return(1);
   } else if (!err.fatal) {
      if (!(*ret = my_strdup(err.str))) {
	 err.fatal = 1;
	 err.str = "Failed allocating space for error string";
	 fail();

	 /* fall through to fatal error handler */
      } else {
	 kd_log_finish("kd_create", 0);

	 return(0);
      }
   }

   /* fatal errors */

   if (err.fatal) {
      log_fatal("kd_open", err.str);
      /* never returns */
   }

   /* keep the compiler quiet */

   return(0);
}

int kd_open(char *dbdir, int flags, char **ret)
{
   error err;

   err.str = err.buf;

   if (kd_open_1(dbdir, 0, flags, &err)) {
      kd_log_finish("kd_open", 1);

      return(1);
   } else if (!err.fatal) {
      if (!(*ret = my_strdup(err.str))) {
	 err.fatal = 1;
	 err.str = "Failed allocating space for error string";
	 fail();

	 /* fall through to fatal error handler */
      } else {
	 kd_log_finish("kd_open", 0);

	 return(0);
      }
   }

   /* fatal errors */

   if (err.fatal) {
      log_fatal("kd_open", err.str);
      /* never returns */
   }

   /* keep the compiler quiet */

   return(0);
}

int kd_backup()
{
   int ret;

   kd_log_start("kd_backup", NULL, 0, 0);

   ret = kd_backup_1();

   kd_log_finish("kd_backup", ret);

   return(ret);
}

int kd_sync()
{
   kd_sync_1();

   kd_log_finish("kd_sync", 1);

   return(1);
}

int kd_close()
{
   kd_close_1();

   kd_log_finish("kd_close", 1);

   return(1);
}
