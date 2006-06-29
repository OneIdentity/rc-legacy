# (c) Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS=       foreign

AM_LDFLAGS = $(VAS_LIBS)
AM_CFLAGS =  $(VAS_CFLAGS)

sbin_PROGRAMS=		vasidmapd
bin_PROGRAMS=		vasidmap
dist_bin_SCRIPTS=	vaspass vasmapcron

vasidmap_LDADD  =   $(LIBOBJS)
vasidmapd_LDADD =   $(LIBOBJS)

EXTRA_DIST=	vasidmapd-rh.init vasidmapd-suse.init

