PHP_INC=$(PHP_HEADERS)
VAS_INC=$(VAS_HEADERS)
INCLUDES = -I$(PHP_INC) -I$(PHP_INC)/Zend -I$(PHP_INC)/TSRM -I$(PHP_INC)/main -I$(VAS_INC)

EXTRA_DIST			= doxvas

noinst_LIBRARIES	= libphp_vas.a

#------------------------------------------------------------------------------
# vasapi.c contains our bindings along with php_vas.h. This get built into
# libphp_vas.a.
#------------------------------------------------------------------------------
libphp_vas_a_SOURCES= php_vas.h vasapi.c
libphp_vas_a_CFLAGS	= -fno-strict-aliasing -Wall -Wno-missing-prototypes -Wno-unused -Werror

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
FILENAME       = $(PHP_BINDINGS).$(PHP_SO_SUFFIX).$(PHP_BINDINGS_VERSION)
FILENAME64     = $(PHP_BINDINGS)64.$(PHP_SO_SUFFIX).$(PHP_BINDINGS_VERSION)
MAJORSYMLINK   = $(PHP_BINDINGS).$(PHP_SO_SUFFIX).$(PHP_BIND_VERS_MAJOR)
MAJORSYMLINK64 = $(PHP_BINDINGS)64.$(PHP_BIND_VERS_MAJOR).$(PHP_SO_SUFFIX)
LIBSYMLINK     = $(PHP_BINDINGS).$(PHP_SO_SUFFIX)
LIBSYMLINK64   = $(PHP_BINDINGS)64.$(PHP_SO_SUFFIX)
TMPLIBDIR      = .1				# (due to AIX command-line length limit)
else

if MACOSX
# Darwin has the suffix last, and the version info before that...
FILENAME       = $(PHP_BINDINGS).$(PHP_BIND_VERSION).$(CSHAREDLIBSUFFIX)
FILENAME64     = $(FILENAME)
MAJORSYMLINK   = $(PHP_BINDINGS).$(PHP_BIND_VERS_MAJOR).$(CSHAREDLIBSUFFIX)
MAJORSYMLINK64 = $(MAJORSYMLINK)
LIBSYMLINK     = $(PHP_BINDINGS).$(CSHAREDLIBSUFFIX)
LIBSYMLINK64   = $(LIBSYMLINK)
TMPLIBDIR      = .$(PHP_BINDINGS).libs

else
# Everything else has the version after the suffix...
FILENAME       = $(PHP_BINDINGS).$(PHP_SO_SUFFIX).$(PHP_BINDINGS_VERSION)
FILENAME64     = $(FILENAME)
MAJORSYMLINK   = $(PHP_BINDINGS).$(PHP_SO_SUFFIX).$(PHP_BIND_VERS_MAJOR)
MAJORSYMLINK64 = $(MAJORSYMLINK)
LIBSYMLINK     = $(PHP_BINDINGS).$(PHP_SO_SUFFIX)
LIBSYMLINK64   = $(LIBSYMLINK)
TMPLIBDIR      = .$(PHP_BINDINGS).libs
endif
endif

PHP_SO			= libphp_vas

# We link with VAS' API library...
VAS_SO_ADD		= -L$(VAS_LIBRARY_PATH) -l$(VAS_LIBRARY_NAME)
VAS_SO_RPATH	= $(VAS_INSTALL_RPATH)

# phony targets that don't have dependencies...
.PHONY : build-$(PHP_BINDINGS) install-$(PHP_BINDINGS) clean-$(PHP_BINDINGS)

$(FILENAME): $(PHP_BINDINGS).a
	@echo
	@echo Delete the library-build directory...
	rm -rf $(TMPLIBDIR)
	mkdir $(TMPLIBDIR)
	@echo
	@echo Building $(FILENAME)...
	cd $(TMPLIBDIR) && ar x ../$< && cd ..
	cd $(TMPLIBDIR) && $(CLINK) \
		$(PHP_SO_LFLAGS) $(CFLAGS) \
		-o ../$(FILENAME) *.o \
		$(patsubst -L../%,-L../../%,$(VAS_SO_ADD)) \
		$(VAS_SO_RPATH) ;
	chmod +x $(FILENAME)
	@echo
	@echo Chain-link the PHP shared objects just as is done for libvas.so...
	rm -rf $(LIBSYMLINK) $(MAJORSYMLINK) $(TMPLIBDIR)
	ln -sf $(FILENAME) $(MAJORSYMLINK)
	ln -sf $(MAJORSYMLINK) $(LIBSYMLINK)
	ls -lgo $(PHP_SO).$(PHP_SO_SUFFIX)*

build-$(PHP_BINDINGS): $(FILENAME)

#------------------------------------------------------------------------------
# Miscellaneous utility targets for forcing the build, installation, cleaning
# up, etc.
#------------------------------------------------------------------------------
clean-$(PHP_BINDINGS):
	rm -rf $(TMPLIBDIR)
	rm -f $(FILENAME) $(MAJORSYMLINK) $(LIBSYMLINK)

phpinclude_SCRIPTS=	vasapi.php vas_gss.php vas_ldap.php

all-local :		build-$(PHP_BINDINGS)
clean-local :	clean-$(PHP_BINDINGS)


#------------------------------------------------------------------------------
# Create the documentation, html and man pages, in the doc subdirectory.
#------------------------------------------------------------------------------
dox: vasapi.php vas_gss.php vas_ldap.php doxvas
	doxygen doxvas
