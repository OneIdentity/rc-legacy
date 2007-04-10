# (c) 2007, Quest Software, Inc. All rights reserved.

AUTOMAKE_OPTIONS=	foreign

SUBST=			sed -e 's,[@]prefix[@],$(prefix),g' \
			    -e 's,[@]bindir[@],$(bindir),g' \
			    -e 's,[@]libdir[@],$(libdir),g' \
			    -e 's,[@]includedir[@],$(includedir),g' \
			    -e 's,[@]VERSION[@],$(VERSION),g'

include_HEADERS=	gssapi.h \
			pgssapi.h

lib_LTLIBRARIES=	libpgss.la
libpgss_la_SOURCES=	pgss-common.h \
			pgss-config.c \
			pgss-config.h \
			pgss-dispatch.h \
			pgss-dlprov.c \
			pgss-getprogname.c \
			pgss-basename.c \
			pgss-gss2.c \
			pgss-gss2.h \
			pgss-oidstr.c \
			pgss-oidstr.h \
			pgss-unavail.c

pkgconfigdir=		$(libdir)/pkgconfig
pkgconfig_DATA=		libpgss.pc
libpgss.pc: libpgss.pc.in
	$(SUBST) < $^ > $@

noinst_PROGRAMS=	test
test_SOURCES=		test.c
test_LDADD=		libpgss.la
test_DEPENDENCIES=	libpgss.la

CLEANFILES= 		design.html design.unpg tmp.xml libpgss.pc
EXTRA_DIST=		design.xml test.conf libpgss.pc.in README LICENSE

XML2HTML=		xml2html
XML2UNPG=		xml2unpg
design.html: design.xml
	cp $(srcdir)/design.xml ./tmp.xml
	$(XML2HTML) tmp.xml
	mv tmp.html $@

design.unpg: design.xml
	cp $(srcdir)/design.xml ./tmp.xml
	$(XML2UNPG) tmp.xml
	mv tmp.unpg $@
