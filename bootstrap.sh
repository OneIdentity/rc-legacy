#!/bin/sh

set -ex

#-- Builds the automadness
rm -rf autom4te.cache install-sh missing Makefile.in configure \
       aclocal.m4 config.h.in
autoreconf --install

#-- Fetches polypkg
if test ! -x pp; then
    if test -x /data/rc/pub/rc/polypkg/pp; then
	#-- /data/rc/pub is an NFS share within Quest
	ln -s /data/rc/pub/rc/polypkg/pp pp
    else
	wget http://rc.quest.com/pub/rc/polypkg/pp
	chmod +x pp
    fi
    ./pp --version
fi
