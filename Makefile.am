PHP_INC=$(PHP_HEADERS)
VAS_INC=$(VAS_HEADERS)
INCLUDES = -I$(PHP_INC) -I$(PHP_INC)/Zend -I$(PHP_INC)/TSRM -I$(PHP_INC)/main -I$(VAS_INC)

EXTRA_DIST			= vasapi.php vas_gss.php vas_ldap.php doxvas

noinst_LIBRARIES	= libphp_vas.a

#------------------------------------------------------------------------------
# vasapi.c contains our bindings along with php_vas.h. This get built into
# libphp_vas.a.
#------------------------------------------------------------------------------
libphp_vas_a_SOURCES= php_vas.h vasapi.c
libphp_vas_a_CFLAGS	= -fno-strict-aliasing -Wall -Wno-missing-prototypes -Wno-unused -Werror

QUESTPHPINCLUDEDIR = $(DESTDIR)$(includedir)/php

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
FILENAME       = $(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BINDINGS_VERSION)
FILENAME64     = $(PHP_BINDINGS)64.$(CSHAREDLIBSUFFIX).$(PHP_BINDINGS_VERSION)
MAJORSYMLINK   = $(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR)
MAJORSYMLINK64 = $(PHP_BINDINGS)64.$(PHP_BIND_VERS_MAJOR).$(CSHAREDLIBSUFFIX)
LIBSYMLINK     = $(PHP_BINDINGS).$(CSHAREDLIBSUFFIX)
LIBSYMLINK64   = $(PHP_BINDINGS)64.$(CSHAREDLIBSUFFIX)
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
FILENAME       = $(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BINDINGS_VERSION)
FILENAME64     = $(FILENAME)
MAJORSYMLINK   = $(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR)
MAJORSYMLINK64 = $(MAJORSYMLINK)
LIBSYMLINK     = $(PHP_BINDINGS).$(CSHAREDLIBSUFFIX)
LIBSYMLINK64   = $(LIBSYMLINK)
TMPLIBDIR      = .$(PHP_BINDINGS).libs
endif
endif

VAS_LIBRARY_ADD   =-L$(VAS_LIBRARY_PATH) -l$(VAS_LIBRARY_NAME)
VAS_LIBRARY_RPATH =-Wl,-rpath -Wl,$(VAS_LIBRARY_PATH)

# phony targets that don't have dependencies...
.PHONY : build-$(PHP_BINDINGS) install-$(PHP_BINDINGS) clean-$(PHP_BINDINGS)

$(FILENAME): $(PHP_BINDINGS).a
	@echo
	@echo Building $(FILENAME)...
	rm -rf $(TMPLIBDIR)
	mkdir $(TMPLIBDIR)
	cd $(TMPLIBDIR) && ar x ../$< && cd ..
	cd $(TMPLIBDIR) && \
	$(CLINK) $(CSHAREDLIBLINKFLAGS) $(CFLAGS) \
		-o ../$(FILENAME) *.o $(patsubst -L../%,-L../../%,$(VAS_LIBRARY_ADD))
	chmod +x $(FILENAME)
	@echo
	rm -rf $(LIBSYMLINK) $(MAJORSYMLINK) $(TMPLIBDIR)
	ln -sf $(FILENAME) $(MAJORSYMLINK)
	ln -sf $(MAJORSYMLINK) $(LIBSYMLINK)

build-$(PHP_BINDINGS): $(FILENAME)

#------------------------------------------------------------------------------
# Miscellaneous utility targets for forcing the build, installation, cleaning
# up, etc.
#------------------------------------------------------------------------------
clean-$(PHP_BINDINGS):
	rm -rf $(TMPLIBDIR)
	rm -f $(FILENAME) $(MAJORSYMLINK) $(LIBSYMLINK)

install-data-local:
	$(mkinstalldirs) $(QUESTPHPINCLUDEDIR)
	$(INSTALL_DATA)  $(QUESTPHPINCLUDEDIR)/
	$(INSTALL_DATA)  vasapi.php $(QUESTPHPINCLUDEDIR)/
	$(INSTALL_DATA)  vas_gss.php $(QUESTPHPINCLUDEDIR)/
	$(INSTALL_DATA)  vas_ldap.php $(QUESTPHPINCLUDEDIR)/

all-local :		build-$(PHP_BINDINGS)
clean-local :	clean-$(PHP_BINDINGS)


#------------------------------------------------------------------------------
# Create the documentation, html and man pages, in the doc subdirectory.
#------------------------------------------------------------------------------
dox: vasapi.php vas_gss.php vas_ldap.php doxvas
	doxygen doxvas
