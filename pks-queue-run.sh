#!/bin/sh

#
# $Id: pks-queue-run.sh,v 1.3 2003/01/31 01:17:29 rlaager Exp $
#
# Copyright (c) 1996, Marc Horowitz.  All rights reserved.
# See the LICENSE file in the release for redistribution information.

conf="$1"

case "X$conf" in
	X)
		echo "usage: $0 conf_file" 1>&2
		exit 1
		;;
esac

if [ ! -r $conf ]; then 
	echo "conf_file $conf is not readable" 1>&2
	exit 1
fi

dir=`awk '/mail_dir/ { print $2 }' < $conf`
socket=`awk '/socket_name/ { print $2 }' < $conf`
bindir=`awk '/pks_bin_dir/ { print $2 }' < $conf`

delay="$2"

if [ "${delay}" = "" ]; then
	delay=3
fi

while true ; do 
	for file in $dir/pks-mail.*; do
		# Handle all readable files.
		if [ -r "$file" ]; then
			$bindir/pksdctl $socket "mail $file"
		fi

		# Sleep to avoid swamping the server.
		sleep "${delay}"
	done

	# Sleep to avoid swamping the CPU or disks.
	sleep "${delay}"
done

