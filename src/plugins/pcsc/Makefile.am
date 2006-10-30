DEFS = @DEFS@ \
        -DPREFIX=\"@prefix@\" \
        -DSYSCONFDIR=\"@sysconfdir@\" \
        -DDATADIR=\"@datadir@\" \
        -DLIBDIR=\"@libdir@\" \
        -DPKCS11_PLUGIN_CONFIG_FILE=\"@sysconfdir@/pcsc.conf\" 

INCLUDES = \
	-I$(srcdir)/.					\
	-I$(srcdir)/include				\
	-I$(srcdir)/include/PCSC			\
	-I$(top_srcdir)/src/include

libpromptpcsc_la_SOURCES = \
	gdm_prompt_pcsc.c

libpromptpcsc_la_LDFLAGS =        			\
	-module -avoid-version 				\
	-ldl -lpthread					\
	-L$(top_builddir)/src/libs -lpromptconfig

pluginsdir=$(libdir)/gdm/plugins

plugins_LTLIBRARIES =            \
	libpromptpcsc.la 

EXTRA_DIST=include
