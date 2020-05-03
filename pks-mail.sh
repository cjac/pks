#!/bin/sh

#
# $Id: pks-mail.sh,v 1.3 2003/01/31 01:17:29 rlaager Exp $
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
file=$dir/pks-mail.`date +%Y.%m.%d.%H.%M.%S`.$$

cat > $file || {
	echo "Error writing mail file" 1>&2
	exit 1
}

