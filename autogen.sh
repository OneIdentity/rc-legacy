#!/bin/sh
set -ex
rm -rf autom4te.cache configure Makefile.in depcomp config.h.in missing \
       aclocal.m4 install-sh
#svn up .
svnversion .
autoreconf -i
