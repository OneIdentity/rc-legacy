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

pluginsconfdir=$(sysconfdir)/gdm/plugins

EXTRA_DIST=pkcs11.conf.in

# Install pkcs11.conf in ${pluginsconfdir}. 
install-data-hook: pkcs11.conf.in
	if test '!' -d $(DESTDIR)$(pluginsconfdir); then \
		$(mkinstalldirs) $(DESTDIR)$(pluginsconfdir); \
		chmod 755 $(DESTDIR)$(pluginsconfdir); \
	fi 
	if test -f $(DESTDIR)$(pluginsconfdir)/pkcs11.conf; then \
		cp -f $(DESTDIR)$(pluginsconfdir)/pkcs11.conf $(DESTDIR)$(pluginsconfdir)/pkcs11.conf.orig; \
        fi
	$(INSTALL_DATA) pkcs11.conf.in $(DESTDIR)$(pluginsconfdir)/pkcs11.conf
