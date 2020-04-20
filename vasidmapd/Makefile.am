# (c) 2017, Quest Software, Inc. All rights reserved.

POLYPKGFILE=/data/rc/pub/rc/polypkg/pp
POLYPKGURI=http://rc.quest.com/pub/rc/polypkg/pp

AUTOMAKE_OPTIONS =	foreign

AM_CFLAGS =		$(VAS_CFLAGS)

sbin_PROGRAMS =		vasidmapd
vasidmapd_LDADD =	$(LIBOBJS) $(VAS_LIBS)
man_MANS =		vasidmapd.8

bin_PROGRAMS =		vasidmap
vasidmap_LDADD =	$(LIBOBJS) $(VAS_LIBS)
man_MANS +=		vasidmap.1

sbin_SCRIPTS =		vas-samba-config
man_MANS +=		vas-samba-config.1

sbin_SCRIPTS +=		vas-krb5-config 
man_MANS +=		vas-krb5-config.1

libexec_SCRIPTS =	vas-set-samba-password
man_MANS +=		vas-set-samba-password.8

libexec_SCRIPTS +=	vasidmap-status

dist_pkgdata_DATA =	vasidmap-common.sh

TESTS=			rc.test t-vasidmap-common
TESTS_ENVIRONMENT=	srcdir=$(srcdir) $(SHELL)

EXTRA_DIST =		LICENCE README Changelog
EXTRA_DIST +=		pp vasidmap.pp 
EXTRA_DIST +=       pp vas-samba-config.pp
EXTRA_DIST +=		$(man_MANS)
EXTRA_DIST +=		vas-samba-config.in 
EXTRA_DIST +=		vas-krb5-config.in
EXTRA_DIST +=		vas-set-samba-password.in
EXTRA_DIST +=		vasidmap-status.in
EXTRA_DIST +=		$(TESTS)
EXTRA_DIST +=		err.h inet_pton.h

CLEANFILES = vas-krb5-config vas-set-samba-password vas-samba-config vasidmap-status


# Rules for generating the shell scripts
SUFFIXES = .in
SED = sed
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

PP_DESTDIR=$${TMPDIR-/tmp}/vasidmap.root.`echo $$$$`


pp:
	if [ -r "$(POLYPKGFILE)" ]; then \
	ln -s $(POLYPKGFILE) $@; \
	elif which wget >/dev/null 2>&1; then \
	wget -O $@ "$(POLYPKGURI)"; \
	elif which curl >/dev/null 2>&1; then \
	curl -o $@ "$(POLYPKGURI)"; \
	else \
	echo "Cannot figure out how to get polypkg"; \
	exit 1; \
	fi
	chmod +x $@

# Rule for building a package
package: pp vasidmap.pp
	DESTDIR="$(PP_DESTDIR)"; \
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
	    sysconfdir=$(sysconfdir) \
	&& rm -rf "$$DESTDIR"

config: pp vas-samba-config.pp
	DESTDIR="$${TMPDIR-/tmp}/vas-samba-config.root.`echo $$$$`"; \
	rm -rf "$$DESTDIR"; \
	$(MAKE) install DESTDIR="$$DESTDIR" && \
	$(srcdir)/pp --destdir="$$DESTDIR" \
	--install-script="inst.sh" \
	$(srcdir)/vas-samba-config.pp \
	version="$(VERSION)" \
	bindir=$(bindir) \
	libdir=$(bindir) \
	libexecdir=$(libexecdir) \
	mandir=$(mandir) \
	pkgdatadir=$(pkgdatadir) \
	sbindir=$(sbindir) \
	sysconfdir=$(sysconfdir) \
	&& rm -rf "$$DESTDIR"
