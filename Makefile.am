# (c) Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS=       foreign

AM_LDFLAGS = $(VAS_LIBS)
AM_CFLAGS =  $(VAS_CFLAGS)

sbin_PROGRAMS=		vasidmapd
bin_PROGRAMS=		vasidmap
dist_bin_SCRIPTS=	vasidmap-config vas-samba-config vas-set-samba-password
man_MANS =              vasidmapd.8

vasidmap_LDADD  =   $(LIBOBJS)
vasidmapd_LDADD =   $(LIBOBJS)

TESTS=			rc.test
TESTS_ENVIRONMENT=	$(SHELL)

EXTRA_DIST=	vasidmap.pp LICENCE rc.test $(man_MANS) pp

package: pp vasidmap.pp
	test -n "$(DESTDIR)"
	$(srcdir)/pp --destdir=$(DESTDIR) \
	    --install-script=install-vasidmap \
	    $(srcdir)/vasidmap.pp \
	    version="$(VERSION)" \
	    bindir=$(bindir) \
	    sbindir=$(sbindir) \
	    mandir=$(mandir)
