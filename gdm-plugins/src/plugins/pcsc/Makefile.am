SUBDIRS=include

DEFS = @DEFS@ \
        -DPREFIX=\"@prefix@\" \
        -DSYSCONFDIR=\"@sysconfdir@\" \
        -DDATADIR=\"@datadir@\" \
        -DLIBDIR=\"@libdir@\" \
        -DPCSC_PLUGIN_CONFIG_FILE=\"@sysconfdir@/X11/gdm/plugins/pcsc.conf\" 

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

pluginsconfdir=$(sysconfdir)/X11/gdm/plugins

EXTRA_DIST=pcsc.conf.in

# Install pcsc.conf in ${pluginsconfdir}.
install-data-hook: pcsc.conf.in
	if test '!' -d $(DESTDIR)$(pluginsconfdir); then \
		$(mkinstalldirs) $(DESTDIR)$(pluginsconfdir); \
		chmod 755 $(DESTDIR)$(pluginsconfdir); \
	fi
	if test -f $(DESTDIR)$(pluginsconfdir)/pcsc.conf; then \
		cp -f $(DESTDIR)$(pluginsconfdir)/pcsc.conf $(DESTDIR)$(pluginsconfdir)/pcsc.conf.orig; \
	fi
	$(INSTALL_DATA) pcsc.conf.in $(DESTDIR)$(pluginsconfdir)/pcsc.conf
