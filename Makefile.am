
AUTOMAKE_OPTIONS=	foreign

include_HEADERS=	gssapi.h \
			pgssapi.h

lib_LTLIBRARIES=	libpgss.la
libpgssapi_la_SOURCES=	pgss-common.h \
			pgss-config.c \
			pgss-config.h \
			pgss-dispatch.h \
			pgss-dlprov.c \
			pgss-getprogname.c \
			pgss-basename.c \
			pgss-gss2.c \
			pgss-gss2.h \
			pgss-oidstr.c

noinst_bin_PROGRAMS=	test
test_SOURCES=		test.c
test_LDADD=		libpgss.la
test_DEPENDENCIES=	libpgss.la

CLEANFILES= 		design.html design.unpg tmp.xml
EXTRA_DISTFILES=	design.xml
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
