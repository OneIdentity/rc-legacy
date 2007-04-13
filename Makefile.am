
abs_srcdir		= $(shell cd $(srcdir) && pwd)
EXTRA_INSTALL_HOOKS 	=
EXTRA_UNINSTALL_HOOKS 	=
EXTRA_CLEAN_HOOKS 	=

# The directories that we install into
scriptdir 		= $(datadir)/php
docdir			= $(datadir)/doc

# installed PHP scripts, also used as documentation source
dist_script_DATA	= scripts/vasapi.php \
			  scripts/vas_gss.php \
			  scripts/vas_ldap.php

# the vas.so module is simply put in the datadir
data_DATA 		= extension/vas.so
#-- note: don't use a _SOURCES var here because its only intended for 
#   PROGRAMS, LIBRARIES and LT_LIBRARIES.
vas_so_sources		= extension/vasapi.c \
			  extension/php_vas.h 

#-- Some explicit rules to build the vas.so extension using phpize
extension/configure: extension/config.m4
	if test ! -d extension; then \
		mkdir -p extension; \
		touch extension/.linked; \
		ln -s $(abs_srcdir)/extension/config.m4 extension/config.m4; \
		ln -s $(abs_srcdir)/extension/vasapi.c extension/vasapi.c; \
	fi
	cd extension && $(PHPIZE)
extension/Makefile: extension/configure
	cd extension && ./configure CPPFLAGS=-I$(abs_srcdir)/extension
extension/vas.so: extension/Makefile $(vas_so_sources)
	cd extension && $(MAKE)
	cp extension/modules/vas.so $@

clean-vas_so:
	-cd extension && $(MAKE) clean
	-cd extension && $(PHPIZE) --clean
	-rm -rf extension/vas.so extension/autom4te.cache
	-if [ -f extension/.linked ]; then \
	    rm extension/config.m4 extension/vasapi.c extension/.linked; \
	    rmdir extension; \
	 fi

EXTRA_DIST		= $(vas_so_sources) \
			  extension/config.m4 \
			  AUTHORS COPYING INSTALL LICENCE NEWS NOTES README \
			  doxvas.in

if HAVE_DOXYGEN
#------------------------------------------------------------------------------
# Create the documentation, html and man pages, in the doc subdirectory.
#------------------------------------------------------------------------------

doc/html/index.html: $(script_DATA) doxvas
	$(DOXYGEN) doxvas
doxvas: doxvas.in
	sed -e 's,[@]srcdir[@],$(srcdir),g' < $(srcdir)/doxvas.in > $@
install-doc: doc/html/index.html
	$(install_sh) -d $(DESTDIR)$(docdir)
	cp -r doc/* $(DESTDIR)$(docdir)/
uninstall-doc:
	rm -rf $(DESTDIR)$(docdir)
clean-doc:
	-rm -rf doc doxvas

EXTRA_INSTALL_HOOKS +=	 install-doc
EXTRA_UNINSTALL_HOOKS += uninstall-doc
EXTRA_CLEAN_HOOKS +=	 clean-doc
endif

uninstall-local: $(EXTRA_UNINSTALL_HOOKS)
install-data-local: $(EXTRA_INSTALL_HOOKS)
clean-local: clean-vas_so $(EXTRA_CLEAN_HOOKS)

#------------------------------------------------------------------------------
# This is for Polypkg...
#------------------------------------------------------------------------------
package:
	$(MAKE) install DESTDIR=$$PWD/pkgroot
	$(srcdir)/pp --destdir=$$PWD/pkgroot $(srcdir)/php_vas.pp \
		version=$(PKG_VERSION) \
		scriptdir=$(scriptdir) \
		extensiondir=$(extensiondir) \
		docdir=$(docdir)

EXTRA_DIST += pp php-vas.pp
