#!/bin/sh

set -ex
rm -rf autom4te.cache install-sh missing Makefile.in configure \
       aclocal.m4 config.h.in
autoreconf --install
