#!/bin/sh

# Builds coolkey RPMs
set -ex

#-- This package is required. NB: pcsc-lite-devel is not shipped by Red Hat 
#   for RHEL4; I had to find the pcsc-lite.src.rpm and build the 
#   pcsc-lite-devel package manually.
rpm -q pcsc-lite-devel

cd coolkey 
configure --disable-dependency-tracking 

#-- Extract the version from the makefile
VERSION=`sed -n -e '/^VERSION =/{s/.*= //;p;q;}' Makefile`
test -n "$VERSION"
make dist

# Build the RPMs
rpmbuild -ta coolkey-$VERSION.tar.gz

