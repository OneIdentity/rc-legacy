#! /bin/sh
# Bootstrap sources from a fresh checkout, or when configure.ac has changed

bootstrap () { 
    (set -x; cd "$1"
     rm -rf autom4te.cache install-sh missing Makefile.in \
            configure aclocal.m4 config.h.in
     autoreconf --install
    )
}

bootstrap .
