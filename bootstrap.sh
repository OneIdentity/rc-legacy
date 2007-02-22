#! /bin/sh
# $Id$
# 

bootstrap () { 
    (set -x; cd "$1"
     rm -rf autom4te.cache install-sh missing Makefile.in \
	    configure aclocal.m4 config.h.in \
	    config.guess config.sub ltmain.sh
     autoreconf --install
    )
}

bootstrap .
