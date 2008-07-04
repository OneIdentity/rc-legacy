# (c) 2008, Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS =	foreign

AM_LDFLAGS =		$(VAS_LIBS)
AM_CFLAGS =		$(VAS_CFLAGS)

sbin_PROGRAMS =		vasidmapd
vasidmapd_LDADD =	$(LIBOBJS)
man_MANS =		vasidmapd.8

bin_PROGRAMS =		vasidmap
vasidmap_LDADD =	$(LIBOBJS)
man_MANS +=		vasidmap.1

sbin_SCRIPTS =		vas-samba-config
man_MANS +=		vas-samba-config.1

sbin_SCRIPTS +=		vas-krb5-config 
man_MANS +=		vas-krb5-config.1

libexec_SCRIPTS =	vas-set-samba-password
man_MANS +=		vas-set-samba-password.8

dist_pkgdata_DATA =	vasidmap-common.sh

TESTS=			rc.test t-vasidmap-common
TESTS_ENVIRONMENT=	srcdir=$(srcdir) $(SHELL)

EXTRA_DIST =		LICENCE README 
EXTRA_DIST +=		pp vasidmap.pp 
EXTRA_DIST +=		$(man_MANS)
EXTRA_DIST +=		vas-samba-config.in 
EXTRA_DIST +=		vas-krb5-config.in
EXTRA_DIST +=		vas-set-samba-password.in
EXTRA_DIST +=		$(TESTS)

CLEANFILES = vas-krb5-config vas-set-samba-password vas-samba-config


# Rules for generating the shell scripts
SUFFIXES = .in
subst = $(SED) -e 's,[@]VERSION[@],$(VERSION),g' \
	       -e 's,[@]bindir[@],$(bindir),g' \
	       -e 's,[@]libdir[@],$(libdir),g' \
	       -e 's,[@]libexecdir[@],$(libexecdir),g' \
	       -e 's,[@]mandir[@],$(mandir),g' \
	       -e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
	       -e 's,[@]sbindir[@],$(sbindir),g' \
	       -e 's,[@]sysconfdir[@],$(sysconfdir),g' 
.in:
	$(subst) <$< >$@
	chmod +x $@

# Rule for building a package
package: pp vasidmap.pp
	DESTDIR="$${TMPDIR-/tmp}/vasidmap.root"; \
	rm -rf "$$DESTDIR"; \
	$(MAKE) install DESTDIR="$$DESTDIR" && \
	$(srcdir)/pp --destdir="$$DESTDIR" \
	    --install-script="inst.sh" \
	    $(srcdir)/vasidmap.pp \
	    version="$(VERSION)" \
	    bindir=$(bindir) \
	    libdir=$(bindir) \
	    libexecdir=$(libexecdir) \
	    mandir=$(mandir) \
	    pkgdatadir=$(pkgdatadir) \
	    sbindir=$(sbindir) \
	    sysconfdir=$(sysconfdir)
