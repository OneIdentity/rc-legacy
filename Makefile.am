# (c) Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS=       foreign

AM_LDFLAGS = $(shell vas-config --libs)
AM_CFLAGS = $(shell vas-config --cflags)

sbin_PROGRAMS=		vasidmapd
bin_PROGRAMS=		vasidmap
dist_bin_SCRIPTS=	vaspass vasmapcron

EXTRA_DIST=	vasidmapd-rh.init vasidmapd-suse.init

