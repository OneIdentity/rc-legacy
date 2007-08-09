#!/bin/sh
set -ex

rm -rf config.h stamp-h1 config.status config.cache config.log \
       configure.lineno configure.status.lineno autom4te.cache .deps \
       Makefile

autoreconf --install
