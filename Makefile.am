# (c) Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS=       foreign

AM_LDFLAGS = $(VAS_LIBS)
AM_CFLAGS =  $(VAS_CFLAGS)

sbin_PROGRAMS=		vasidmapd
bin_PROGRAMS=		vasidmap
dist_bin_SCRIPTS=	vasidmap-preload vasidmap-config
noinst_PROGRAMS=	vasidmapc

vasidmap_LDADD  =   $(LIBOBJS)
vasidmapd_LDADD =   $(LIBOBJS)
vasidmapc_LDADD =   $(LIBOBJS)

EXTRA_DIST=	vasidmap.pp LICENCE 

dist-hook:
	cp /data/rc/pub/rc/polypkg/pp $(distdir)/pp
package: pp vasidmap.pp
	test -n "$(DESTDIR)"
	$(srcdir)/pp --destdir=$(DESTDIR) \
	    $(srcdir)/vasidmap.pp \
	    version="$(VERSION)"
