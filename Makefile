# Generated automatically from Makefile.in by configure.
#
# $Id: Makefile.in,v 1.17 2003/02/07 01:01:17 rlaager Exp $
# 
# Copyright (c) 1996, 1997, 1998, 1999, Marc Horowitz.  All rights reserved.
# See the LICENSE file in the release for redistribution information.

all::

SHELL = /bin/sh

## this does recursion for db2, if it's in the tree

SUBDIRS = db2-sleepycat/dist

depend all install check clean distclean maintainer-clean::
	for i in ${SUBDIRS}; do (test -d $$i && cd $$i && ${MAKE} DESTDIR=${DESTDIR} RPM_BUILD_DIR=${DESTDIR} $@) || exit 1; done

## this builds the keyserver

ALL = pksclient pksdctl pgpsplit
ALL_SUPERUSER = pksd
ALL_PURE = pksclient.pure pksd.pure
ALL_SH = pks-mail.sh pks-queue-run.sh

SYSCONF = pksd.conf
DATA = mail_intro $(addprefix pks_help., cz de dk en es fi fr hr ja kr no pl pt se tw)
MAN5 = pksd.conf.5
MAN8 = pks-intro.8 pksclient.8 pksd.8 pksdctl.8

UTILS = pksmailreq wwwtest pgpdump kvcv kxa pkscheck pksdump

all:: $(ALL) $(ALL_SUPERUSER) $(SYSCONF)
all-pure:: $(ALL_PURE)
all-utils:: $(UTILS)

DBDIR = db2-sleepycat/dist

CC = gcc
INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 0644
INSTALL_SCRIPT = $(INSTALL)
SOCKLIBS = 

srcdir = .
prefix = /usr/local
sbindir = ${exec_prefix}/sbin
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
localstatedir = ${prefix}/var
man5dir = ${prefix}/man/man5
man8dir = ${prefix}/man/man8

MKDEP = makedepend
PURIFY = purify

INCLUDES = -I$(DBDIR)
DBG = -DDEBUG
DEFINES = $(DBG)  -DHAVE_SYS_SELECT_H=1 -DHAVE_MMAP=1 -DHAVE_MADVISE=1 -DHAVE_SOCKLEN_T=1 
CFLAGS = -Wall -pedantic -g -O $(INCLUDES) $(DEFINES)

LIBDB = $(DBDIR)/libdb.a

CLEAN = rm -f

PKSOBJS = pks_www.o pks_socket.o
WWWOBJS = www.o
MAILOBJS = mail_req.o mail_send.o
INCROBJS = pks_incr.o
DBOBJS = kd_add.o kd_delete.o kd_disable.o kd_generic.o kd_get.o kd_index.o \
	kd_search.o kd_since.o kd_types.o
PGPOBJS = pgputil.o md5c.o armor.o pgpcrc.o shs.o
MPOBJS = kd_signal.o multiplex.o mp_signal.o
MISCOBJS = parse.o llist.o globals.o logging.o
UTILOBJS = util.o

# portable make doesn't do $^.  So I get to use a new variable
# for each program.  sigh.

O1 = pksclient.o $(DBOBJS) $(PGPOBJS) $(MISCOBJS) $(UTILOBJS)
pksclient: $(O1)
	$(CC) -o $@ $(O1) $(LDFLAGS) $(LIBDB)

pksclient.pure: $(O1) 
	$(PURIFY) $(CC) -o $@ $(O1) $(LDFLAGS) $(LIBDB)

O3 = pksd.o pks_config.o $(PKSOBJS) $(WWWOBJS) $(MAILOBJS) \
	$(INCROBJS) $(DBOBJS) $(PGPOBJS) $(MPOBJS) $(MISCOBJS) $(UTILOBJS)
pksd: $(O3)
	$(CC) -o $@ $(O3) $(LDFLAGS) $(SOCKLIBS) $(LIBDB)

pksd.pure: $(O3)
	$(PURIFY) $(CC) -o $@ $(O3) $(LDFLAGS) $(SOCKLIBS) $(LIBDB)

O5 = pksdctl.o
pksdctl: $(O5)
	$(CC) -o $@ $(O5) $(LDFLAGS) $(SOCKLIBS)


O6 = pksmailreq.o $(MAILOBJS) $(INCROBJS) \
	$(DBOBJS) $(PGPOBJS) $(MPOBJS) $(MISCOBJS) $(UTILOBJS)
pksmailreq: $(O6)
	$(CC) -o $@ $(O6) $(LDFLAGS) $(LIBDB)

O7 = pkscheck.o $(DBOBJS) $(PGPOBJS) $(UTILOBJS) $(MISCOBJS)
pkscheck: $(O7)
	$(CC) -o $@ $(O7) $(LDFLAGS) $(LIBDB)

O8 = pksdump.o $(DBOBJS) $(PGPOBJS) $(UTILOBJS) $(MISCOBJS)
pksdump: $(O8)
	$(CC) -o $@ $(O8) $(LDFLAGS) $(LIBDB)

O9 = wwwtest.o $(WWWOBJS) $(MPOBJS) $(MISCOBJS) $(UTILOBJS)
wwwtest: $(O9)
	$(CC) -o $@ $(O9) $(LDFLAGS) $(SOCKLIBS) $(LIBDB)

O10 = pgpdump.o pgpfile.o $(PGPOBJS) $(UTILOBJS)
pgpdump: $(O10)
	$(CC) -o $@ $(O10) $(LDFLAGS)

O11 = pgpsplit.o $(PGPOBJS) $(UTILOBJS)
pgpsplit: $(O11)
	$(CC) -o $@ $(O11) $(LDFLAGS)

O12 = kvcv.o pgpfile.o logging.o $(PGPOBJS) $(UTILOBJS)
kvcv: $(O12)
	$(CC) -o $@ $(O12) $(LDFLAGS)

O13 = kxa.o pgpfile.o $(PGPOBJS) $(UTILOBJS)
kxa: $(O13)
	$(CC) -o $@ $(O13) $(LDFLAGS)

pksd.conf: mkpksdconf
	sh mkpksdconf > pksd.conf

depend::
	$(MKDEP) -- $(CFLAGS) -- *.c

check::

installdirs::
	-mkdir -p $(DESTDIR)$(bindir) $(DESTDIR)$(sbindir) $(DESTDIR)$(datadir) $(DESTDIR)$(sysconfdir) $(DESTDIR)$(man5dir) $(DESTDIR)$(man8dir)
	-mkdir -p $(DESTDIR)$(localstatedir)/db $(DESTDIR)$(localstatedir)/incoming

install:: all installdirs
	for f in $(ALL); do $(INSTALL_PROGRAM) $$f $(DESTDIR)$(bindir); done
	for f in $(ALL_SUPERUSER); do $(INSTALL_PROGRAM) $$f $(DESTDIR)$(sbindir); done
	for f in $(SYSCONF); do [ -f $(DESTDIR)$(sysconfdir)/$$f ] || $(INSTALL_DATA) $$f $(DESTDIR)$(sysconfdir); done
	for f in $(ALL_SH); do $(INSTALL_SCRIPT) $(srcdir)/$$f $(DESTDIR)$(bindir); done
	for f in $(DATA); do $(INSTALL_DATA) $(srcdir)/$$f $(DESTDIR)$(datadir); done
	for f in $(MAN5); do $(INSTALL_DATA) $(srcdir)/$$f $(DESTDIR)$(man5dir); done
	for f in $(MAN8); do $(INSTALL_DATA) $(srcdir)/$$f $(DESTDIR)$(man8dir); done
	$(INSTALL_DATA) $(srcdir)/pks-commands.html $(DESTDIR)$(localstatedir)/index.html

install-utils:: all-utils installdirs
	for f in $(UTILS); do $(INSTALL_PROGRAM) $$f $(DESTDIR)$(bindir); done

clean::
	$(CLEAN) $(ALL) $(ALL_SUPERUSER) $(SYSCONF) $(ALL_PURE) $(UTILS) *.o *~

distclean:: 
	rm -rf config.status config.log config.cache Makefile mkpksdconf

maintainer-clean:: distclean
	rm -rf configure


# Below is a makedepend(1)-generated dependency list without
# system (/usr/include/) include files.

# DO NOT DELETE THIS LINE -- make depend depends on it.

armor.o: globals.h
armor.o: pgputil.h
armor.o: pgpcrc.h
armor.o: armor.h
armor.o: util.h
kd_add.o: armor.h
kd_add.o: pgputil.h
kd_add.o: database.h
kd_add.o: globals.h
kd_add.o: llist.h
kd_add.o: util.h
kd_add.o: kd_types.h
kd_add.o: kd_internal.h
kd_add.o: kd_search.h
kd_delete.o: database.h
kd_delete.o: globals.h
kd_delete.o: llist.h
kd_delete.o: util.h
kd_delete.o: kd_types.h
kd_delete.o: pgputil.h
kd_delete.o: kd_internal.h
kd_delete.o: kd_search.h
kd_disable.o: database.h
kd_disable.o: globals.h
kd_disable.o: llist.h
kd_disable.o: util.h
kd_disable.o: kd_types.h
kd_disable.o: pgputil.h
kd_disable.o: kd_internal.h
kd_disable.o: kd_search.h
kd_generic.o: database.h
kd_generic.o: globals.h
kd_generic.o: llist.h
kd_generic.o: util.h
kd_generic.o: kd_types.h
kd_generic.o: pgputil.h
kd_generic.o: kd_internal.h
kd_get.o: pgputil.h
kd_get.o: armor.h
kd_get.o: database.h
kd_get.o: globals.h
kd_get.o: llist.h
kd_get.o: util.h
kd_get.o: kd_types.h
kd_get.o: kd_internal.h
kd_get.o: kd_search.h
kd_index.o: database.h
kd_index.o: globals.h
kd_index.o: llist.h
kd_index.o: util.h
kd_index.o: md5.h
kd_index.o: kd_types.h
kd_index.o: pgputil.h
kd_index.o: kd_internal.h
kd_index.o: kd_search.h
kd_index.o: shs.h
kd_search.o: pgputil.h
kd_search.o: database.h
kd_search.o: globals.h
kd_search.o: llist.h
kd_search.o: util.h
kd_search.o: kd_types.h
kd_search.o: kd_internal.h
kd_search.o: kd_search.h
kd_signal.o: globals.h
kd_signal.o: database.h
kd_signal.o: multiplex.h
kd_since.o: pgputil.h
kd_since.o: armor.h
kd_since.o: database.h
kd_since.o: globals.h
kd_since.o: kd_search.h
kd_since.o: llist.h
kd_since.o: util.h
kd_since.o: kd_internal.h
kd_since.o: kd_types.h
kd_types.o: database.h
kd_types.o: llist.h
kd_types.o: util.h
kd_types.o: kd_types.h
kd_types.o: pgputil.h
kvcv.o: pgputil.h
kvcv.o: md5.h
kvcv.o: pgpfile.h
kvcv.o: shs.h
kxa.o: pgputil.h
kxa.o: pgpfile.h
kxa.o: util.h
kxa.o: armor.h
llist.o: llist.h
llist.o: util.h
llist.o: globals.h
logging.o: globals.h
logging.o: database.h
mail_req.o: parse.h
mail_req.o: globals.h
mail_req.o: util.h
mail_req.o: database.h
mail_req.o: mail_send.h
mail_req.o: mail_req.h
mail_req.o: pks_incr.h
mail_req.o: llist.h
mail_send.o: parse.h
mail_send.o: multiplex.h
mail_send.o: globals.h
mail_send.o: util.h
mail_send.o: mail_send.h
md5c.o: md5.h
mp_signal.o: multiplex.h
multiplex.o: util.h
multiplex.o: multiplex.h
parse.o: util.h
parse.o: parse.h
pgpcrc.o: pgpcrc.h
pgpcrc.o: pgputil.h
pgpdump.o: pgputil.h
pgpdump.o: md5.h
pgpdump.o: util.h
pgpdump.o: pgpfile.h
pgpfile.o: util.h
pgpfile.o: pgputil.h
pgpfile.o: pgpfile.h
pgpsplit.o: util.h
pgpsplit.o: pgputil.h
pgpsplit.o: pgpfile.h
pgputil.o: globals.h
pgputil.o: pgputil.h
pgputil.o: armor.h
pgputil.o: shs.h
pks_config.o: parse.h
pks_config.o: pks_config.h
pks_config.o: llist.h
pks_config.o: util.h
pks_config.o: globals.h
pks_incr.o: pks_incr.h
pks_incr.o: mail_send.h
pks_incr.o: llist.h
pks_incr.o: util.h
pks_incr.o: globals.h
pks_socket.o: pks_socket.h
pks_socket.o: mail_req.h
pks_socket.o: mail_send.h
pks_socket.o: pks_incr.h
pks_socket.o: llist.h
pks_socket.o: util.h
pks_socket.o: multiplex.h
pks_socket.o: parse.h
pks_socket.o: globals.h
pks_socket.o: database.h
pks_www.o: pks_www.h
pks_www.o: pks_incr.h
pks_www.o: mail_send.h
pks_www.o: llist.h
pks_www.o: util.h
pks_www.o: database.h
pks_www.o: www.h
pks_www.o: globals.h
pks_www.o: multiplex.h
pks_www.o: parse.h
pkscheck.o: database.h
pkscheck.o: globals.h
pkscheck.o: kd_internal.h
pkscheck.o: llist.h
pkscheck.o: util.h
pksclient.o: database.h
pksclient.o: globals.h
pksclient.o: util.h
pksd.o: pks_config.h
pksd.o: llist.h
pksd.o: util.h
pksd.o: pks_socket.h
pksd.o: mail_req.h
pksd.o: mail_send.h
pksd.o: pks_incr.h
pksd.o: pks_www.h
pksd.o: database.h
pksd.o: multiplex.h
pksd.o: globals.h
pksdump.o: database.h
pksdump.o: globals.h
pksdump.o: kd_internal.h
pksdump.o: llist.h
pksdump.o: util.h
pksmailreq.o: util.h
pksmailreq.o: llist.h
pksmailreq.o: mail_req.h
pksmailreq.o: mail_send.h
pksmailreq.o: pks_incr.h
pksmailreq.o: multiplex.h
pksmailreq.o: globals.h
pksmailreq.o: database.h
shs.o: shs.h
util.o: util.h
www.o: multiplex.h
www.o: util.h
www.o: www.h
www.o: globals.h
www.o: parse.h
www.o: pks_www.h
www.o: pks_incr.h
www.o: mail_send.h
www.o: llist.h
wwwtest.o: www.h
wwwtest.o: util.h
wwwtest.o: globals.h
wwwtest.o: multiplex.h
