# This file is fodder to aclocal, but use ./bootstrap.sh to prepare configure.
# Afterward, do the following:
#
#       ./configure [--with-php-include-dir=./php-4.4.6]
#       make
#       make install
#
# The invocation of configure demonstrates the possibility of consuming a PHP
# down-load other than the one that is probably installed on the build host.
#
AC_INIT(vasapi.c)
AM_INIT_AUTOMAKE(libphp_vas.so.4.3.0, 4.3.0)
AC_REVISION


# -----------------------------------------------------------------------------
# Ascertain VAS' libvas.so version. We do this in a subshell because we have to
# use brackets and brackets don't work in configure.ac because of m4.
#
VAS_LIBRARY_NAME="vas"

library_info=`./libvas-info.sh`
echo "checking for VAS library..."
VAS_LIBRARY_PATH=`echo    $library_info | awk '{ print $1; }'`
PHP_BIND_VERS_MAJOR=`echo $library_info | awk '{ print $2; }'`
PHP_BIND_VERS_MINOR=`echo $library_info | awk '{ print $3; }'`
PHP_BIND_VERS_MICRO=`echo $library_info | awk '{ print $4; }'`

PHP_BINDINGS=libphp_vas
PHP_BINDINGS_VERSION=$PHP_BIND_VERS_MAJOR.$PHP_BIND_VERS_MINOR.$PHP_BIND_VERS_MICRO


# -----------------------------------------------------------------------------
# Options: determine VAS and PHP include, binary paths...
#
ENABLE_DEBUG=
AC_ARG_ENABLE(debug,
[  --enable-debug              enable debugging mode],
[  if test "x$enable_debug" = "xyes"; then
     ENABLE_DEBUG=1
     PHP_DEBUG_CFLAGS="-g3 -DDEBUG"
   else
     ENABLE_DEBUG=0
     PHP_DEBUG_CFLAGS="-DNDEBUG"
   fi
]
)
AM_CONDITIONAL(ENABLE_DEBUG, test "x$enable_debug" = "xyes")


# -----------------------------------------------------------------------------
# Look for PHP headers: these can be specified or left to default from the
# usual places. This way, a new PHP down-load can be employed (say, to this
# directory) without having to refit the build host.
#
VAS_HEADERS=/opt/quest/include
PHP_HEADERS=
AC_ARG_WITH(php-include-dir,
[  --with-php-include-dir=DIR  path to the PHP include directory, e.g.: \
        --with-php-include-dir=/usr/include/php],
[ case "$withval" in
    yes|no)
      # in case specified without argument...
      AC_MSG_ERROR([--with-php-include-dir specified without argument])
      ;;
    * )
      PHP_HEADERS="$withval"
      ;;
    esac],
[
  # Attempt to locate PHP headers in a couple of places. We try in this
  # order:
  # /usr/include/php
  # /usr/local/include/php
  #
  # To test that we've found them, we'll verify the existence of main/php.h as
  # representative of the headers (even though the PHP include paths are a
  # complex lot). If we cannot find these headers, then we will have to fail.
  if test -d "/usr/include/php" ; then
      PHP_HEADERS="/usr/include/php"
  elif test -d "/usr/local/include/php" ; then
      PHP_HEADERS="/usr/local/include/php"
  else
      PHP_HEADERS=
  fi
])
AC_CHECK_FILES( $PHP_HEADERS/main/php.h, ,
[
AC_MSG_WARN([Invalid PHP include directory. Could not find main/php.h. The
VAS-PHP bindings will not be built.])
PHP_HEADERS=
])


# -----------------------------------------------------------------------------
# Platform-variable stuff. This is crucial to building the bindings on the
# various platforms on which VAS is supported.
#
AC_CANONICAL_HOST
CANONICAL_HOST=$host

AH_TEMPLATE([AIX],     [Define if the operating system is AIX])
AH_TEMPLATE([LINUX],   [Define if the operating system is LINUX])
AH_TEMPLATE([IRIX],    [Define if the operating system is IRIX])
AH_TEMPLATE([SOLARIS], [Define if the operating system is SOLARIS])
AH_TEMPLATE([HPUX],    [Define if the operating system is HPUX])
AH_TEMPLATE([MACOSX],  [Define if the operating system is Macintosh OSX])
AH_TEMPLATE([FREEBSD], [Define if the operating system is FREEBSD])
AH_TEMPLATE([TRU64],   [Define if the operating system is TRU64])

echo ""
case $host in
  *-*-aix*)
    echo "  Platform is identified as AIX * * * * * * * * * * * * *"
    ostype="AIX"
    AC_DEFINE(AIX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS="$CSHAREDLIBLINKFLAGS -shared -Wl,-G -static-libgcc -Wl,-brtl"
    PHP_BIND_INST_RPATH='-Wl,-bnolibpath -Wl,-blibpath:$(libdir):/usr/lib:/lib'
    PHP_BIND64_INST_RPATH='-Wl,-bnolibpath -Wl,-blibpath:$(lib64dir):/usr/lib:/lib'
    PHP_BIND_SUPLIB_RPATH='-Wl,-bnolibpath -Wl,-blibpath:$(supportlibdir):$(libdir):/usr/lib:/lib'

    ;;
  x86_64-*-linux*)
    echo "  Platform is identified as Linux x86 64 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fpic -Wl,-soname,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR) -static-libgcc'
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    PHP_BIND64_INST_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  s390x-*-linux*)
    echo "  Platform is identified as Linux S390x * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fPIC -Wl,-soname,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR) -static-libgcc'
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    PHP_BIND64_INST_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  s390-*-linux*)
    echo "  Platform is identified as Linux S390 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fPIC -Wl,-soname,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR) -static-libgcc'
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    LIBVAS_BUILD_RPATH='-Wl,-rpath -Wl,$(abs_top_builddir)/src/libs/vasapi'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  ia64-*-linux*)
    echo "  Platform is identified as Linux IA64 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fpic -Wl,-soname,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR) -static-libgcc'
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    PHP_BIND64_INST_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  powerpc64-*-linux*)
    echo "  Platform is identified as Linux PowerPC * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fpic -Wl,-soname,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR) -static-libgcc'
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    PHP_BIND64_INST_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-*-linux*)
    echo "  Platform is identified as Linux x86 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS="-shared -fpic -Wl,-soname,$PHP_BINDINGS.$CSHAREDLIBSUFFIX.$PHP_BIND_VERS_MAJOR -static-libgcc"
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-sgi-iri*)
    echo "  Platform is identified as Irix * * * * * * * * * * * * *"
    ostype="IRIX"
    AC_DEFINE(IRIX,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fpic -Wl,-soname,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR) -static-libgcc'
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  i386-*-solaris*)
    echo "  Platform is identified as Solaris i386 * * * * * * * * * * * * *"
    ostype="SOLARIS"
    AC_DEFINE(SOLARIS,1)
    CSHAREDLIBSUFFIX="so"
    if test -d /usr/lib/64; then
      CSHAREDLIBLINKFLAGS='-specs=$(abs_top_builddir)/cf/gccspecs-sol10-rpath-fixes -shared -fPIC -static-libgcc -Wl,-h -Wl,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR)'
    else
      CSHAREDLIBLINKFLAGS='-shared -fPIC -static-libgcc -Wl,-h -Wl,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR)'
    fi
    PHP_BIND_INST_RPATH='-Wl,-R -Wl,$(libdir)'
    PHP_BIND64_INST_RPATH='-Wl,-R -Wl,$(lib64dir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-R -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-*-solaris*)
    echo "  Platform is identified as Solaris * * * * * * * * * * * * *"
    ostype="SOLARIS"
    AC_DEFINE(SOLARIS,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fPIC -static-libgcc -Wl,-h -Wl,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR)'
    PHP_BIND_INST_RPATH='-Wl,-R -Wl,$(libdir)'
    PHP_BIND64_INST_RPATH='-Wl,-R -Wl,$(lib64dir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-R -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-*-hpux11*)
    echo "  Platform is identified as HP-UX * * * * * * * * * * * * *"
    ostype="HPUX"
    AC_DEFINE(HPUX,1)
    hparch=`uname -m`
    if test "x$hpuxarch" = "xia64"; then
      CSHAREDLIBSUFFIX="so"
      PHP_BIND_INST_RPATH='-Wl,+b -Wl,$(libdir)'
      PHP_BIND64_INST_RPATH='-Wl,+b -Wl,$(lib64dir)'
      PHP_BIND_SUPLIB_RPATH='-Wl,+b -Wl,$(supportlibdir):$(libdir)'
    else
      CSHAREDLIBSUFFIX="sl"
      PHP_BIND_INST_RPATH='-Wl,+b -Wl,$(libdir)'
      PHP_BIND64_INST_RPATH='-Wl,+b -Wl,$(lib64dir)'
      PHP_BIND_SUPLIB_RPATH='-Wl,+b -Wl,$(supportlibdir):$(libdir)'
    fi
    CSHAREDLIBLINKFLAGS='-shared -fPIC -static-libgcc -Wl,+h,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR)'
    ;;
  *-*-darwin*)
    echo "  Platform is identified as Macintosh OS X * * * * * * * * * * * * *"
    ostype="MACOSX"
    AC_DEFINE(MACOSX,1)
    CSHAREDLIBSUFFIX="dylib"
    CSHAREDLIBLINKFLAGS='-dynamiclib -dynamic -install_name ${libdir}/$(PHP_BINDINGS).$(PHP_BIND_VERS_MAJOR).$(CSHAREDLIBSUFFIX) -compatibility_version $(PHP_BIND_VERS_MAJOR) -current_version $(PHP_BINDINGS_VERSION)'" $UNIVERSAL_LINK_FLAGS"
    PHP_BIND_INST_RPATH=''
    ;;
  *-*-freebsd*)
    echo "  Platform is identified as FreeBSD * * * * * * * * * * * * *"
    ostype="FREEBSD"
    AC_DEFINE(FREEBSD,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fPIC -Wl,-soname -Wl,$(PHP_BINDINGS).$(CSHAREDLIBSUFFIX).$(PHP_BIND_VERS_MAJOR)'
    PHP_BIND_INST_RPATH="-Wl,--rpath -Wl,$(libdir)"
    PHP_BIND_SUPLIB_RPATH="-Wl,--rpath -Wl,$(supportlibdir):$(libdir)"
    ;;
  alphaev68-*-osf*)
    echo "  Platform is identified as Tru64 * * * * * * * * * * * * *"
    ostype="TRU64"
    AC_DEFINE(TRU64,1)
    CSHAREDLIBSUFFIX="so"
    CSHAREDLIBLINKFLAGS='-shared -fPIC -static-libgcc -Wl,-set_version -Wl,$(PHP_BINDINGS_VERSION):$(PHP_BIND_VERS_MAJOR):0 -Wl,-msym'
    PHP_BIND_INST_RPATH='-Wl,-rpath -Wl,$(libdir)'
    PHP_BIND_SUPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  *)
    echo "Unknown CANONICAL_HOST $host"
    exit
    ;;
esac

AM_CONDITIONAL(AIX,    test "x$ostype" = "xaix")
AM_CONDITIONAL(LINUX,  test "x$ostype" = "xlinux")
AM_CONDITIONAL(SOLARIS,test "x$ostype" = "xsolaris_x86" || test "x$ostype" = "xsolaris_sparc" || test "x$ostype" = "xsolaris_x64" )
AM_CONDITIONAL(HPUX,   test "x$ostype" = "xhpux-pa" || test "x$ostype" = "xhpux-ia64")
AM_CONDITIONAL(MACOSX, test "x$ostype" = "xmacosx")
AM_CONDITIONAL(FREEBSD,test "x$ostype" = "xfreebsd")
AM_CONDITIONAL(TRU64,  test "x$ostype" = "xtru64")


# -----------------------------------------------------------------------------
# Process these variables in the Makefiles: we explicitly cause our current
# values to get substituted here.
#
echo "  Using PHP headers from $PHP_HEADERS!"
echo "  Variables exported to make:"

AC_SUBST(PHP_BINDINGS)
echo "    PHP_BINDINGS as $PHP_BINDINGS"

AC_SUBST(VAS_LIBRARY_PATH)
echo "    VAS_LIBRARY_PATH as $VAS_LIBRARY_PATH"
AC_SUBST(VAS_LIBRARY_NAME)
echo "    VAS_LIBRARY_NAME as $VAS_LIBRARY_NAME"

AC_SUBST(PHP_BIND_VERS_MAJOR)
echo "    PHP_BIND_VERS_MAJOR as $PHP_BIND_VERS_MAJOR"
AC_SUBST(PHP_BIND_VERS_MINOR)
echo "    PHP_BIND_VERS_MINOR as $PHP_BIND_VERS_MINOR"
AC_SUBST(PHP_BIND_VERS_MICRO)
echo "    PHP_BIND_VERS_MICRO as $PHP_BIND_VERS_MICRO"
AC_SUBST(PHP_BINDINGS_VERSION)
echo "    PHP_BINDINGS_VERSION as $PHP_BINDINGS_VERSION"

AC_SUBST(VAS_HEADERS)
echo "    VAS_HEADERS as $VAS_HEADERS"
AC_SUBST(PHP_HEADERS)
echo "    PHP_HEADERS as $PHP_HEADERS"

AC_SUBST(CANONICAL_HOST)
echo "    CANONICAL_HOST as $CANONICAL_HOST"

AC_SUBST(CSHAREDLIBSUFFIX)
echo "    CSHAREDLIBSUFFIX as $CSHAREDLIBSUFFIX"
AC_SUBST(CSHAREDLIBLINKFLAGS)
echo "    CSHAREDLIBLINKFLAGS as $CSHAREDLIBLINKFLAGS"
AC_SUBST(PHP_BIND_INST_RPATH)
echo "    PHP_BIND_INST_RPATH as $PHP_BIND_INST_RPATH"
AC_SUBST(PHP_BIND64_INST_RPATH)
echo "    PHP_BIND64_INST_RPATH as $PHP_BIND64_INST_RPATH"
AC_SUBST(PHP_BIND_SUPLIB_RPATH)
echo "    PHP_BIND_SUPLIB_RPATH as $PHP_BIND_SUPLIB_RPATH"

AC_SUBST(ENABLE_DEBUG)
echo "    ENABLE_DEBUG as $ENABLE_DEBUG"
AC_SUBST(PHP_DEBUG_CFLAGS)
echo "    PHP_DEBUG_CFLAGS as $PHP_DEBUG_CFLAGS"

if test -z "$CLINK" ; then
  CLINK='$(CC)'
fi
AC_SUBST(CLINK)
echo "    CLINK as $CLINK"
echo "  * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"
echo ""

AC_PROG_CC
AC_PROG_RANLIB
AC_HEADER_STDC
AC_OUTPUT(Makefile)
