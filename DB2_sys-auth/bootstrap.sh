#! /bin/sh
# Bootstrap sources from a fresh checkout, or when configure.ac has changed

bootstrap () { 
    ( cd "$1"
     rm -rf autom4te.cache install-sh missing \
            configure aclocal.m4 config.h.in
     autoreconf --install
     rm -rf autom4te.cache
    )
}

bootstrap .
