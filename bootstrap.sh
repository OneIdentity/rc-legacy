#! /bin/sh
# $Id$
# 

clean () {
    (set -x; cd "$1"
     rm -rf autom4te.cache install-sh missing Makefile.in \
	    configure aclocal.m4 config.h.in \
	    config.guess config.sub ltmain.sh \
	    Makefile config.h config.log config.status \
	    stamp-h1 libtool depcomp .deps
    )
}

bootstrap () { 
    $clean_only && return
    (set -x; cd "$1"
     autoreconf --install
    )
}

clean_only=false

while test $# -gt 0; do
 case "$1" in
    --clean-only)
	clean_only=true
	;;
    --) shift; break;;
    -*) echo "unknown option $1";;
    *) break;;
 esac
 shift
done

clean .
bootstrap .
