SUBDIRS=include

DEFS = @DEFS@ \
        -DPREFIX=\"@prefix@\" \
        -DSYSCONFDIR=\"@sysconfdir@\" \
        -DDATADIR=\"@datadir@\" \
        -DLIBDIR=\"@libdir@\" \
        -DPKCS11_PLUGIN_CONFIG_FILE=\"@sysconfdir@/pkcs11.conf\" 

INCLUDES = \
	-I$(srcdir)/.					\
	-I$(srcdir)/include				\
	-I$(top_srcdir)/src/include

libpromptpkcs11_la_SOURCES = \
	pkcs11_defs.h					\
	gdm_prompt_pkcs11.c

libpromptpkcs11_la_LDFLAGS =        			\
	-module -avoid-version 				\
	-ldl -lpthread					\
	-L$(top_builddir)/src/libs -lpromptconfig


pluginsdir=$(libdir)/gdm/plugins

plugins_LTLIBRARIES =            \
	libpromptpkcs11.la 

EXTRA_DIST=pkcs11.conf.in
