Summary: OpenPGP Public Key Server
Summary(es): Servidor Publico de Claves OpenPGP
Name: pks
Version: 0.9.6
Release: 1
License: BSD-like (with advertising clause)
Group: Utilities/System
Source: %{name}-%{version}.tar.gz
Requires: %{name}-db = %{version}
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
%description
This is a OpenPGP Public Key Server. It allows users to store and lookup 
OpenPGP public keys from the server's database. Additionally, it can
synchronize with other servers to make a distributed, replicated
database of public keys.
 
This package provides only the server side. The client side is usually
an OpenPGP application (like PGP or GPG), although a simple HTML form
is provided to allow queries from a web page.

%package utils
Summary: OpenPGP Public Key Server Utilities
Group: Utilities/System
Requires: %{name} = %{version}
%description utils
This package contains optional utilities for use with the
OpenPGP Public Key Server.

%package db
Summary: OpenPGP Public Key Server Database Engine
Group: Utilities/System
Requires: %{name} = %{version}
%description db
This package contains the database utilities for use with the
OpenPGP Public Key Server.

%package db-devel
Summary: OpenPGP Public Key Server Database Libraries
Group: Development/Library
Requires: %{name} = %{version}
%description db-devel
This package contains the database headers and libraries for use with the
OpenPGP Public Key Server.

%prep
%setup

%build
%configure  \
            --prefix=/usr \
            --sysconfdir=/etc \
            --datadir=/usr/share/pks \
            --sharedstatedir=/var/lib/%{name} \
            --localstatedir=/var/lib/%{name} \
            --mandir=/usr/share/man \
            --with-libwrap
make 
make all-utils

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
make DESTDIR="$RPM_BUILD_ROOT" install
make DESTDIR="$RPM_BUILD_ROOT" install-utils
install -d "$RPM_BUILD_ROOT"/etc/init.d 
install -m 0755 pks.init "$RPM_BUILD_ROOT"/etc/init.d/pks
cp db2-sleepycat/LICENSE db2-sleepycat-LICENSE
cp db2-sleepycat/README db2-sleepycat-README
mkdir -p $RPM_BUILD_ROOT/var/lib/%{name}/db
mkdir -p $RPM_BUILD_ROOT/var/lib/%{name}/incoming

%post 
(/usr/sbin/useradd %{name} 2>&1 | grep -v "^useradd: user %{name} exists$" 1>&2) || true

%post db
if ! [ -f /var/lib/%{name}/db/num_keydb ] ; then
    echo "Creating an empty database..."
    /usr/bin/pksclient /var/lib/%{name}/db create
fi
chown -R %{name} /var/lib/%{name}
chgrp -R %{name} /var/lib/%{name}
echo "You may want to add some keys to the server, please read the README file."
echo "If you plan using the mail server component, see the README for instructions."

%files
%defattr(644,root,root,755)
%doc README NEWS LICENSE db2-sleepycat-LICENSE db2-sleepycat-README
%doc mail_intro
%doc pks_help.de pks_help.dk pks_help.en pks_help.es pks_help.fi pks_help.fr pks_help.no
%doc MRHKP

%verify(not md5 size mtime) %config /etc/pksd.conf
%attr(755,root,root) /etc/init.d/pks
/usr/share/pks
%attr(755,root,root) /usr/bin/pksclient
%attr(755,root,root) /usr/sbin/pksd
%attr(755,root,root) /usr/bin/pksdctl
%attr(755,root,root) /usr/bin/pgpsplit
%attr(755,root,root) /usr/bin/pks-mail.sh
%attr(755,root,root) /usr/bin/pks-queue-run.sh
/usr/share/man/man5/pksd.conf.5.gz
/usr/share/man/man8/pks-intro.8.gz
/usr/share/man/man8/pksclient.8.gz
/usr/share/man/man8/pksd.8.gz
/usr/share/man/man8/pksdctl.8.gz
%attr(755,pks,pks) /var/lib/%{name}/index.html
%attr(755,pks,pks) /var/lib/%{name}/db
%attr(777,pks,pks) /var/lib/%{name}/incoming


%files utils
%attr(755,root,root) /usr/bin/pksmailreq
%attr(755,root,root) /usr/bin/wwwtest
%attr(755,root,root) /usr/bin/pgpdump
%attr(755,root,root) /usr/bin/kvcv
%attr(755,root,root) /usr/bin/kxa
%attr(755,root,root) /usr/bin/pkscheck
%attr(755,root,root) /usr/bin/pksdump

%files db
%attr(755,root,root) /usr/bin/db_archive
%attr(755,root,root) /usr/bin/db_checkpoint
%attr(755,root,root) /usr/bin/db_deadlock
%attr(755,root,root) /usr/bin/db_dump
%attr(755,root,root) /usr/bin/db_load
%attr(755,root,root) /usr/bin/db_printlog
%attr(755,root,root) /usr/bin/db_recover
%attr(755,root,root) /usr/bin/db_stat

%files db-devel
/usr/include/db2/db.h
/usr/include/db2/db_185.h
/usr/include/db2/db_cxx.h
/usr/lib/db2/libdb.a

%changelog
* Thu Feb 06 2003 Richard Laager <rlaager@bigfoot.com> 0.9.6-1
- Updating version number for the upcoming release.
* Thu Jan 30 2003 Richard Laager <rlaager@bigfoot.com> 0.9.5-4
- Changed "PGP" to "OpenPGP" throughout this spec file.
* Sun Jan 19 2003 Richard Laager <rlaager@bigfoot.com> 0.9.5-3
- Added MRHKP as a documention file.
* Sun Sep 29 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5-2
- Added a revised description. (I made some modifications to the description provided by Inaki Arenaza <iarenaza@escomposlinux.org>.)
* Sun Sep 29 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5-1
- pks-commands.html is now installed in /var/lib/pks as index.html
* Sat Sep 28 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5-0
- Updated for the 0.9.5 release that should be coming shortly.
- Changed RPM_BUILD_DIR to DESTDIR.
* Fri Sep 27 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5rc1-5
- a few minor fixes to make things work smoothly
* Wed Sep 25 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5rc1-4
- Updating to reflect the change that pksd is now placed in /usr/sbin by the Makefile
* Fri Sep 13 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5rc1-3
- Applied a patch by Marcel Waldvogel <marcel@wanda.ch> to fix some documentation issues.
* Tue Sep 10 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5rc1-2
- Changed /var/lib/pks/db to /var/lib/pks. Bug fix suggested by Jan Dreyer <dreyerja@math.uni-paderborn.de>
- Added --mandir=/usr/share/man to the ./configure options. Bug fix suggested by Jan Dreyer.
* Sun Sep 08 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5rc1-1
- Changed /home/keyserver to /var/lib/%{name} to comply with FHS
- Removed logrotate stuff
- Renamed pks.iris to pks.init and moved it into the main distribution.
- Corrected License: line.
- Removed the use of Marc Horowitz's name to comply with the license.
- Tweaked the names and descriptions. (My apologies to anyone trying to use the Spanish description. I changed it to reflect the changes in the English version. Since I don't know Spanish, my changes may not be correct.)
- Changed Source: line to NOT point to Marc's website.
- Corrected the name of the init script. (From /etc/init.d/pks.init to /etc/init.d/pks)

* Sat Sep 07 2002 Richard Laager <rlaager@bigfoot.com> 0.9.5rc1-0
- Updated for 0.9.5rc1 that should be released shortly.

* Tue Sep 03 2002 Richard Laager <rlaager@bigfoot.com> 0.9.4-9
- Removed extra junk (xxxxxx.c~ was a common file to patch!) from pks-JHpatch1.rediris.patch
- Added patch_pf20020615
- Added flood.patch
- Added pks-teun-www.c-20020821.patch
- Added pks-multiple-20020807.patch

* Tue May 28 2002 Francisco Monserrat <francisco.monserrat@rediris.es>
- Add the pks.JHpatch1 (some fixed diferent source for the pks server ?)
- Fixed some problems with the tcpdwrapper patch
- Modified buffer overflow patch (kdd_add and kdd_delete also )

* Mon May 27 2002 Francisco Monserrat <francisco.monserrat@rediris.es>
- Patch against buffer overflow in keysubmission

* Tue Jan 17 2002 Francisco Monserrat <francisco.monserrat@rediris.es>
- Added a logrotate job  
* Tue Dec 04 2001 Francisco Monserrat <francisco.monserrat@rediris.es>
- version  0.9.4 Release: 3_imnx
- Added Immunix/RH 7 compatible init script
- Change server to /usr/sbin/pksd

* Fri Aug 23 2001  Francisco Monserrat <francisco.monserrat@rediris.es>
- Added patch to use libwrap control in the pks server

* Wed Aug 01 2001  Francisco Monserrat <francisco.monserrat@rediris.es>
- recompiled with StackGuard (Immunix 7)
- Add x509 patch from Christoph.Martin@uni-mainz.de
  from a email in pgp-keyserver-folk@flame.org 2001/07/20

* Wed Feb 07 2001  Francisco Monserrat <francisco.monserrat@rediris.es>
- recompiled with StackGuard

* Sat Nov 25 2000 Francisco J Monserrat Coll <francisco.monserrat@rediris.es>
 [0.9-4-2 ]
  Cambiadas las rutas de ls binarios a /usr/local y el home de la
 base de datos a /home/keyserver/db
* Sun Jun 13 1999 Robert Maron <robmar@mimuw.edu.pl>
  [0.9.4-1]
- rewrite for private use
TODO: test it
