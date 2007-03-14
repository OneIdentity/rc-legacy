#!/bin/sh

DEBUG=0

# -----------------------------------------------------------------------------
# Because we can't make use of brackets inside configure.ac (as m4 coopts
# them), we analyze the VAS library (libvas.so.M.m.r) in here and just report
# back. First, here are our defaults...
# -----------------------------------------------------------------------------
PHP_BIND_VERS_MAJOR=4
PHP_BIND_VERS_MINOR=3
PHP_BIND_VERS_MICRO=0

VAS_LIBRARY_PATH="/opt/quest/lib"

DebugScript()
{
  msg=$1

  # Don't turn on debugging from configure.ac which simply cannot work because
  # of the extra console debug output. Do invoke ./libvas-info.sh -d directly
  # to test its ability to locate the VAS library by hand. This will ensure
  # that it will work when configure.ac calls it. Some light console debug
  # information will come out at the end of invoking this script even without
  # turning on debug explicitly: coming after what configure.ac is looking for,
  # it's simply ignored by it.
  if [ $DEBUG -gt 0 ]; then
    echo "  $msg"
  fi
}

# Check to see if we're supposed to execute in debug mode which we cannot do
# and still be useful to configure.ac.
set -- `getopt d $*`

while [ $1 != -- ]; do
  case $1 in
    -d)             DEBUG=1 ;;
    --debug)        DEBUG=1 ;;
    --enable-debug) DEBUG=1 ;;
  esac
  shift
done

if [ $DEBUG -gt 0 ]; then
  echo "
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
  libvas-info.sh running in debug: unsuitable for calling from configure.ac!
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
  "
fi

# Meat and potatoes here. We use 4 3 0 because that was the version of
# libvas.so when this script was written. It won't always stay that way.
if [ -d "$VAS_LIBRARY_PATH" ]; then           # Basically: is VAS installed?
  CWD=`pwd`
  DebugScript "Starting in $CWD..."
  cd $VAS_LIBRARY_PATH
  DebugScript "Switching to $VAS_LIBRARY_PATH..."
  libvas_so_4_3_0=`ls libvas.so.?.?.?`

  if [ -n "$libvas_so_4_3_0" ]; then          # Does our library exist?
    DebugScript "Successfully found libvas.so.?.?.?..."
    intermediate=`echo $libvas_so_4_3_0 | sed 's/[.]/ /g'`
    version=`echo $intermediate | awk '{ print $3,$4,$5 }'`

    if [ -n "$version" ]; then                # Did we get a version sequence?
      DebugScript "Successfully isolated potential, discrete versions..."
      PHP_BIND_VERS_MAJOR=`echo $version | awk '{ print $1 }'`
      PHP_BIND_VERS_MINOR=`echo $version | awk '{ print $2 }'`
      PHP_BIND_VERS_MICRO=`echo $version | awk '{ print $3 }'`
    fi
  fi

  DebugScript "Returning to $CWD..."
  cd $CWD
fi

echo "$VAS_LIBRARY_PATH"
echo "$PHP_BIND_VERS_MAJOR"
echo "$PHP_BIND_VERS_MINOR"
echo "$PHP_BIND_VERS_MICRO"

# And, for very light debugging, this stuff goes out, but from configure.ac, we
# just ignore it:
echo "$libvas_so_4_3_0"
echo "$intermediate"
echo "$version"
# vim: set tabstop=2 shiftwidth=2 expandtab:
