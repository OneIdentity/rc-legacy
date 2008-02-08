# (c) Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS=       foreign

AM_LDFLAGS = $(VAS_LIBS)
AM_CFLAGS =  $(VAS_CFLAGS)

sbin_PROGRAMS=		vasidmapd
bin_PROGRAMS=		vasidmap
dist_bin_SCRIPTS=	vasidmap-config vas-samba-config
dist_sbin_SCRIPTS=	vas-set-samba-password
man_MANS =              vasidmapd.8 vasidmap.1

subst = $(SED) -e 's,[@]VERSION[@],$(VERSION),g' \
	       -e 's,[@]bindir[@],$(bindir),g' \
	       -e 's,[@]sbindir[@],$(sbindir),g'

vas-samba-config: vas-samba-config.in
	$(subst) <$^ >$@
	chmod +x $@

vasidmap_LDADD  =   $(LIBOBJS)
vasidmapd_LDADD =   $(LIBOBJS)

TESTS=			rc.test
TESTS_ENVIRONMENT=	$(SHELL)

EXTRA_DIST=	vasidmap.pp LICENCE rc.test $(man_MANS) pp
EXTRA_DIST+=	vas-samba-config.in
EXTRA_DIST+=	README

package: pp vasidmap.pp
	DESTDIR="$${TMPDIR-/tmp}/vasidmap.root"; \
	rm -rf "$$DESTDIR"; \
	$(MAKE) install DESTDIR="$$DESTDIR" && \
	$(srcdir)/pp --destdir="$$DESTDIR" \
	    --install-script=install-vasidmap \
	    $(srcdir)/vasidmap.pp \
	    version="$(VERSION)" \
	    bindir=$(bindir) \
	    sbindir=$(sbindir) \
	    mandir=$(mandir)
