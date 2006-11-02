SUBDIRS=include

DEFS = @DEFS@ \
        -DPREFIX=\"@prefix@\" \
        -DSYSCONFDIR=\"@sysconfdir@\" \
        -DDATADIR=\"@datadir@\" \
        -DLIBDIR=\"@libdir@\" \
        -DPCSC_PLUGIN_CONFIG_FILE=\"@sysconfdir@/pcsc.conf\" 

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

pluginsconfdir=$(sysconfdir)/gdm/plugins

EXTRA_DIST=pcsc.conf.in

# Install pcsc.conf in ${pluginsconfdir}.
install-data-hook: pcsc.conf.in
	if test '!' -d $(DESTDIR)$(pluginsconfdir); then \
		$(mkinstalldirs) $(DESTDIR)$(pluginsconfdir); \
		chmod 755 $(DESTDIR)$(pluginsconfdir); \
	fi
	$(INSTALL_DATA) pcsc.conf.in $(DESTDIR)$(pluginsconfdir)/pcsc.conf
