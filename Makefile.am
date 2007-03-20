INCLUDES = $(PHP_INC_PATHS) $(VAS_INC_PATH)

EXTRA_DIST			= doxvas

noinst_LIBRARIES	= libphp_vas.a

#------------------------------------------------------------------------------
# vasapi.c contains our bindings along with php_vas.h. This get built into
# libphp_vas.a.
#------------------------------------------------------------------------------
libphp_vas_a_SOURCES= php_vas.h vasapi.c
libphp_vas_a_CFLAGS	= -fno-strict-aliasing -Wall -Wno-missing-prototypes -Wno-unused -Werror $(PHP_DEBUG_CFLAGS)

phpincludedir = $(includedir)/php

#------------------------------------------------------------------------------
# Rules to build a shared library from libphp_vas.a, which is just a temporary
# library on the way to a shared object.
#
# We calculate the version suffix of our PHP bindings library, i.e.:
# libphp_vas.so.M.m.r, based on the version of VAS installed since that aligns
# what we're interfacing. (This stuff is out of VAS' Makefile.am.shared-lib.)
#
# The PHP library, libphp[4|5].so, etc. is not needed for linking against since
# we're consuming it as a shared library. Only libvas.so.M.m.r is needed.
#------------------------------------------------------------------------------
if AIX
FILENAME       = $(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERSION)
FILENAME64     = $(BINDINGS)64.$(SO_SUFFIX).$(BINDINGS_VERSION)
MAJORSYMLINK   = $(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR)
MAJORSYMLINK64 = $(BINDINGS)64.$(BINDINGS_VERS_MAJOR).$(SO_SUFFIX)
LIBSYMLINK     = $(BINDINGS).$(SO_SUFFIX)
LIBSYMLINK64   = $(BINDINGS)64.$(SO_SUFFIX)
TMPLIBDIR      = .1				# (due to AIX command-line length limit)
else

if MACOSX
# Darwin has the suffix last, and the version info before that...
FILENAME       = $(BINDINGS).$(BINDINGS_VERSION).$(CSHAREDLIBSUFFIX)
FILENAME64     = $(FILENAME)
MAJORSYMLINK   = $(BINDINGS).$(BINDINGS_VERS_MAJOR).$(CSHAREDLIBSUFFIX)
MAJORSYMLINK64 = $(MAJORSYMLINK)
LIBSYMLINK     = $(BINDINGS).$(CSHAREDLIBSUFFIX)
LIBSYMLINK64   = $(LIBSYMLINK)
TMPLIBDIR      = .$(BINDINGS).libs

else
# Everything else has the version after the suffix...
FILENAME       = $(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERSION)
FILENAME64     = $(FILENAME)
MAJORSYMLINK   = $(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR)
MAJORSYMLINK64 = $(MAJORSYMLINK)
LIBSYMLINK     = $(BINDINGS).$(SO_SUFFIX)
LIBSYMLINK64   = $(LIBSYMLINK)
TMPLIBDIR      = .$(BINDINGS).libs
endif
endif

BINDINGS_SO_NAME	= libphp_vas

# phony targets that don't have dependencies...
.PHONY : build-$(BINDINGS) install-$(BINDINGS) clean-$(BINDINGS)

$(FILENAME): $(BINDINGS).a
	@echo
	@echo Delete the library-build directory...
	rm -rf $(TMPLIBDIR)
	mkdir $(TMPLIBDIR)
	@echo
	@echo Building $(FILENAME)...
	cd $(TMPLIBDIR) && ar x ../$< && cd ..
	cd $(TMPLIBDIR) && $(CLINK) \
		$(SO_LFLAGS) $(CFLAGS) \
		-o ../$(FILENAME) *.o \
		$(VAS_INSTALL_RPATH) ;
	chmod +x $(FILENAME)
	@echo
	@echo Chain-link the PHP shared objects just as is done for libvas.so...
	rm -rf $(LIBSYMLINK) $(MAJORSYMLINK) $(TMPLIBDIR)
	ln -sf $(FILENAME) $(MAJORSYMLINK)
	ln -sf $(MAJORSYMLINK) $(LIBSYMLINK)
	ls -lgo $(BINDINGS_SO_NAME).$(SO_SUFFIX)*

build-$(BINDINGS): $(FILENAME)

#------------------------------------------------------------------------------
# Miscellaneous utility targets for forcing the build, installation, cleaning
# up, etc.
#------------------------------------------------------------------------------
clean-$(BINDINGS):
	rm -rf $(TMPLIBDIR)
	rm -f $(FILENAME) $(MAJORSYMLINK) $(LIBSYMLINK)

phpinclude_SCRIPTS	=	vasapi.php vas_gss.php vas_ldap.php

all-local :		build-$(BINDINGS)
clean-local :	clean-$(BINDINGS)


#------------------------------------------------------------------------------
# Create the documentation, html and man pages, in the doc subdirectory.
#------------------------------------------------------------------------------
dox: vasapi.php vas_gss.php vas_ldap.php doxvas
	doxygen doxvas

#------------------------------------------------------------------------------
# This is for Polypkg...
#------------------------------------------------------------------------------
package:
	$(MAKE) install DESTDIR=$$PWD/pkgroot
	$(srcdir)/pp --destdir=$$PWD/pkgroot $(srcdir)/php_vas.pp \
		version=$(PKG_VERSION) \
		extensiondir=$(extensiondir) \
		phpincludedir=$(phpincludedir)
