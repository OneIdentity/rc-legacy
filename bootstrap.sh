#!/bin/sh

set -ex

#-- Builds the automadness
rm -rf autom4te.cache install-sh missing Makefile.in configure \
       aclocal.m4 config.h.in
autoreconf --install

#-- Fetches polypkg
test -x pp ||
    { wget http://rc.vintela.com/pub/rc/polypkg/pp && 
      chmod +x pp &&
      ./pp --version; }
