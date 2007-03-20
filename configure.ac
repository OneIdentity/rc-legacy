# This file is fodder to aclocal, but use ./bootstrap.sh to prepare configure.
# Afterward, do the following:
#
#       ./configure [--with-php-include-dir=./php-4.4.6]
#                     - or -
#       ./configure [--with-php-include-dir=./php-5.2.1 --enable-php-5]
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
# Look for VAS headers and libraries installed in the usual places. If VAS isn't
# installed, we just won't be able to do anything of this.
#
# Ascertain VAS' libvas.so version. We don't get much help doing this because
# vas-config only gives us the path to the VAS installation. We have to hack
# around to figure out the library version (never identical to vas-config
# --version).
#
VAS_INC_PATH=`/opt/quest/bin/vas-config --cflags`
VAS_INSTALL_RPATH=`/opt/quest/bin/vas-config --libs`
if test -z "$VAS_INC_PATH" ; then
  AC_MSG_WARN([VAS isn't installed. The VAS-PHP bindings cannot be built.])
fi
if test -z "$VAS_INSTALL_RPATH" ; then
  AC_MSG_WARN([VAS isn't installed. The VAS-PHP bindings cannot be built.])
fi

VAS_LIBRARY_NAME="vas"
VAS_HEADERS=/opt/quest/include

  echo "checking for VAS library..."
  vas_prefix=`/opt/quest/bin/vas-config --prefix`
  dnl echo "vas_prefix=$vas_prefix"
  libdir="$vas_prefix/lib"
  dnl echo "libdir=$libdir"
  libs=`ls $libdir/libvas.so*`
  dnl echo $libs
  liblist=`echo $libs | sed "s^$libdir/^^g"`
  dnl echo "liblist=$liblist"
  # big assumption: there are 3 libraries here!
  actual=`echo $liblist | awk '{ print $3 }'`
  dnl echo "(3) actual=$actual"
  if test -z "$actual" ; then
    actual=`echo $liblist | awk '{ print $2 }'`
    dnl echo "(2) actual=$actual"
    if test -z "$actual" ; then
      actual=`echo $liblist | awk '{ print $1 }'`
      dnl echo "(1) actual=$actual"
    fi
  fi
  # big assumption: there are 3 version digits!
  versions=`echo $actual | sed 's/\./ /g' | awk '{ print $3,$4,$5 }'`
  dnl echo "versions=$versions"
  lib64dir=$libdir
  supportlibdir=$libdir


VAS_LIBRARY_PATH=$libdir
dnl echo "VAS library version is $versions"
BINDINGS_VERS_MAJOR=`echo $versions | awk '{ print $1 }'`
BINDINGS_VERS_MINOR=`echo $versions | awk '{ print $2 }'`
BINDINGS_VERS_MICRO=`echo $versions | awk '{ print $3 }'`

BINDINGS=libphp_vas
BINDINGS_VERSION=$BINDINGS_VERS_MAJOR.$BINDINGS_VERS_MINOR.$BINDINGS_VERS_MICRO


# -----------------------------------------------------------------------------
# Options: determine VAS and PHP include, whether to dump from preprocessed
# output (useful for debugging bindings the zend macros are from hell)...
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

ENABLE_CPPDUMP=
AC_ARG_ENABLE(cppdump,
[  --enable-cppdump              enable debugging mode],
[  if test "x$enable_cppdump" = "xyes"; then
     ENABLE_CPPDUMP=1
     PHP_DEBUG_CFLAGS="$PHP_DEBUG_CFLAGS -E"
   else
     ENABLE_CPPDUMP=0
   fi
]
)
AM_CONDITIONAL(ENABLE_CPPDUMP, test "x$enable_cppdump" = "xyes")


# -----------------------------------------------------------------------------
# Look for PHP version and headers: these can be specified or left to default
# from the usual places. This way, a new PHP down-load can be employed (say, to
# this directory) without having to refit the build host and changing its
# version.
#
# Default PHP version we support. To get PHP-5, configure with --enable-php-5.
#
PHP_VERSION=4
PHP_VERSION_5=0
AC_ARG_ENABLE(php-5,
[  --enable-php-5              enable build for PHP-5],
[  if test "x$enable_php_5" = "xyes"; then
     PHP_VERSION=5
     PHP_VERSION_5=1
     CFLAGS="$CFLAGS -D__PHP_5__"
   else
     version=`/usr/local/bin/php-config --version`
     if test -n "$version" ; then
       vers=`echo $version | sed 's/\./ /g' | awk '{ print $1 }'`
       case "$vers" in
         5)
           PHP_VERSION=5
           PHP_VERSION_5=1
           CFLAGS="$CFLAGS -D__PHP_5__"
           ;;
         *)
           CFLAGS="$CFLAGS -D__PHP_4__"
           ;;
       esac
     else
       CFLAGS="$CFLAGS -D__PHP_4__"
     fi
   fi
]
)
AM_CONDITIONAL(PHP_VERSION_5, test "x$enable_php_5" = "xyes")


PHP_INC_PATHS=
AC_ARG_WITH(php-include-dir,
[  --with-php-include-dir=DIR  path to the PHP include directory, e.g.: \
        --with-php-include-dir=/usr/include/php],
[ case "$withval" in
    yes|no)
      # in case specified without argument...
      AC_MSG_ERROR([--with-php-include-dir specified without argument])
      ;;
    *)
      inc_root="$withval"
      PHP_INC_PATHS="-I$withval -I$withval/Zend -I$withval/TSRM -I$withval/main"
      ;;
    esac],
[
  # Typical: In the absence of --with-php-include-dir=<directory>, attempt to
  # locate PHP headers using php-config:
  where=`/usr/local/bin/php-config --includes`
  if test -n where ; then
    PHP_INC_PATHS=$where
  else
    AC_MSG_WARN([Invalid PHP include directory. Try specifying using
 --with-php-include-dir=<directory>. The VAS-PHP bindings will not be built.])
      PHP_INC_PATHS=
  fi
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
    SO_SUFFIX="so"
    SO_LFLAGS="$SO_LFLAGS -shared -Wl,-G -static-libgcc -Wl,-brtl"
    VAS64_INSTALL_RPATH='-Wl,-bnolibpath -Wl,-blibpath:$(lib64dir):/usr/lib:/lib'
    VAS_SUPPLIB_RPATH='-Wl,-bnolibpath -Wl,-blibpath:$(supportlibdir):$(libdir):/usr/lib:/lib'

    ;;
  x86_64-*-linux*)
    echo "  Platform is identified as Linux x86 64 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fpic -Wl,-soname,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR) -static-libgcc'
    VAS64_INSTALL_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  s390x-*-linux*)
    echo "  Platform is identified as Linux S390x * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fPIC -Wl,-soname,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR) -static-libgcc'
    VAS64_INSTALL_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  s390-*-linux*)
    echo "  Platform is identified as Linux S390 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fPIC -Wl,-soname,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR) -static-libgcc'
    LIBVAS_BUILD_RPATH='-Wl,-rpath -Wl,$(abs_top_builddir)/src/libs/vasapi'
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  ia64-*-linux*)
    echo "  Platform is identified as Linux IA64 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fpic -Wl,-soname,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR) -static-libgcc'
    VAS64_INSTALL_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  powerpc64-*-linux*)
    echo "  Platform is identified as Linux PowerPC * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fpic -Wl,-soname,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR) -static-libgcc'
    VAS64_INSTALL_RPATH='-Wl,-rpath -Wl,$(lib64dir)'
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-*-linux*)
    echo "  Platform is identified as Linux x86 * * * * * * * * * * * * *"
    ostype="LINUX"
    AC_DEFINE(LINUX,1)
    SO_SUFFIX="so"
    SO_LFLAGS="-shared -fpic -Wl,-soname,$BINDINGS.$SO_SUFFIX.$BINDINGS_VERS_MAJOR -static-libgcc"
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-sgi-iri*)
    echo "  Platform is identified as Irix * * * * * * * * * * * * *"
    ostype="IRIX"
    AC_DEFINE(IRIX,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fpic -Wl,-soname,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR) -static-libgcc'
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
    ;;
  i386-*-solaris*)
    echo "  Platform is identified as Solaris i386 * * * * * * * * * * * * *"
    ostype="SOLARIS"
    AC_DEFINE(SOLARIS,1)
    SO_SUFFIX="so"
    if test -d /usr/lib/64; then
      SO_LFLAGS='-specs=$(abs_top_builddir)/cf/gccspecs-sol10-rpath-fixes -shared -fPIC -static-libgcc -Wl,-h -Wl,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR)'
    else
      SO_LFLAGS='-shared -fPIC -static-libgcc -Wl,-h -Wl,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR)'
    fi
    VAS64_INSTALL_RPATH='-Wl,-R -Wl,$(lib64dir)'
    VAS_SUPPLIB_RPATH='-Wl,-R -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-*-solaris*)
    echo "  Platform is identified as Solaris * * * * * * * * * * * * *"
    ostype="SOLARIS"
    AC_DEFINE(SOLARIS,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fPIC -static-libgcc -Wl,-h -Wl,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR)'
    VAS64_INSTALL_RPATH='-Wl,-R -Wl,$(lib64dir)'
    VAS_SUPPLIB_RPATH='-Wl,-R -Wl,$(supportlibdir):$(libdir)'
    ;;
  *-*-hpux11*)
    echo "  Platform is identified as HP-UX * * * * * * * * * * * * *"
    ostype="HPUX"
    AC_DEFINE(HPUX,1)
    hparch=`uname -m`
    if test "x$hpuxarch" = "xia64"; then
      SO_SUFFIX="so"
      VAS64_INSTALL_RPATH='-Wl,+b -Wl,$(lib64dir)'
      VAS_SUPPLIB_RPATH='-Wl,+b -Wl,$(supportlibdir):$(libdir)'
    else
      SO_SUFFIX="sl"
      VAS64_INSTALL_RPATH='-Wl,+b -Wl,$(lib64dir)'
      VAS_SUPPLIB_RPATH='-Wl,+b -Wl,$(supportlibdir):$(libdir)'
    fi
    SO_LFLAGS='-shared -fPIC -static-libgcc -Wl,+h,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR)'
    ;;
  *-*-darwin*)
    echo "  Platform is identified as Macintosh OS X * * * * * * * * * * * * *"
    ostype="MACOSX"
    AC_DEFINE(MACOSX,1)
    SO_SUFFIX="dylib"
    SO_LFLAGS='-dynamiclib -dynamic -install_name ${libdir}/$(BINDINGS).$(BINDINGS_VERS_MAJOR).$(SO_SUFFIX) -compatibility_version $(BINDINGS_VERS_MAJOR) -current_version $(BINDINGS_VERSION)'" $UNIVERSAL_LINK_FLAGS"
    ;;
  *-*-freebsd*)
    echo "  Platform is identified as FreeBSD * * * * * * * * * * * * *"
    ostype="FREEBSD"
    AC_DEFINE(FREEBSD,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fPIC -Wl,-soname -Wl,$(BINDINGS).$(SO_SUFFIX).$(BINDINGS_VERS_MAJOR)'
    VAS_SUPPLIB_RPATH="-Wl,--rpath -Wl,$(supportlibdir):$(libdir)"
    ;;
  alphaev68-*-osf*)
    echo "  Platform is identified as Tru64 * * * * * * * * * * * * *"
    ostype="TRU64"
    AC_DEFINE(TRU64,1)
    SO_SUFFIX="so"
    SO_LFLAGS='-shared -fPIC -static-libgcc -Wl,-set_version -Wl,$(BINDINGS_VERSION):$(BINDINGS_VERS_MAJOR):0 -Wl,-msym'
    VAS_SUPPLIB_RPATH='-Wl,-rpath -Wl,$(supportlibdir):$(libdir)'
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
echo "  Using PHP headers from `echo $PHP_INC_PATHS | awk '{ print $1 }'`!"
echo "  Configure variables:"
echo "    libdir=$libdir"
echo "    lib64dir=$lib64dir"
echo "    supportlibdir=$supportlibdir"
echo "  Variables exported to make:"

AC_SUBST(BINDINGS)
echo "    BINDINGS as $BINDINGS"
AC_SUBST(PHP_VERSION)
echo "    PHP_VERSION as $PHP_VERSION"
AC_SUBST(PHP_VERSION_5)
echo "    PHP_VERSION_5 as $PHP_VERSION_5"

AC_SUBST(VAS_LIBRARY_PATH)
echo "    VAS_LIBRARY_PATH as $VAS_LIBRARY_PATH"
AC_SUBST(VAS_LIBRARY_NAME)
echo "    VAS_LIBRARY_NAME as $VAS_LIBRARY_NAME"

AC_SUBST(BINDINGS_VERS_MAJOR)
echo "    BINDINGS_VERS_MAJOR as $BINDINGS_VERS_MAJOR"
AC_SUBST(BINDINGS_VERS_MINOR)
echo "    BINDINGS_VERS_MINOR as $BINDINGS_VERS_MINOR"
AC_SUBST(BINDINGS_VERS_MICRO)
echo "    BINDINGS_VERS_MICRO as $BINDINGS_VERS_MICRO"
AC_SUBST(BINDINGS_VERSION)
echo "    BINDINGS_VERSION as $BINDINGS_VERSION"

AC_SUBST(VAS_INC_PATH)
echo "    VAS_INC_PATH as $VAS_INC_PATH"
AC_SUBST(PHP_INC_PATHS)
echo "    PHP_INC_PATHS as $PHP_INC_PATHS"

AC_SUBST(CANONICAL_HOST)
echo "    CANONICAL_HOST as $CANONICAL_HOST"

AC_SUBST(SO_SUFFIX)
echo "    SO_SUFFIX as .$SO_SUFFIX"
AC_SUBST(SO_LFLAGS)
echo "    SO_LFLAGS as $SO_LFLAGS"
AC_SUBST(VAS_INSTALL_RPATH)
echo "    VAS_INSTALL_RPATH as $VAS_INSTALL_RPATH"
# What is in $VAS_INSTALL_RPATH might in fact suffice for $VAS64_INSTALL_RPATH.
AC_SUBST(VAS64_INSTALL_RPATH)
echo "    VAS64_INSTALL_RPATH as $VAS64_INSTALL_RPATH"
AC_SUBST(VAS_SUPPLIB_RPATH)
echo "    VAS_SUPPLIB_RPATH as $VAS_SUPPLIB_RPATH"

AC_SUBST(ENABLE_DEBUG)
echo "    ENABLE_DEBUG as $ENABLE_DEBUG"
AC_SUBST(ENABLE_CPPDUMP)
echo "    ENABLE_CPPDUMP as $ENABLE_CPPDUMP"
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
