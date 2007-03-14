#!/bin/sh

# The intended invocation order is:
#
#       aclocal
#       autoconf
#       automake
#       automake -a
VERBOSE_OPT=1
ACLOCAL_OPTS=
AUTOMAKE_OPTS="--add-missing --copy"
AUTOCONF_VERSION="2.5."
AUTOMAKE_VERSION="1.6"
ACLOCAL_VERSION="$AUTOMAKE_VERSION"

AUTOCONF=${AUTOCONF:-"autoconf"}
AUTOMAKE=${AUTOMAKE:-"automake"}
ACLOCAL=${ACLOCAL:-`echo $AUTOMAKE | sed s,automake,aclocal,`}


usage()
{
  echo "bootstrap.sh  Runs the autotools to create the configure scripts"
  echo "Usage: ./bootstrap.sh"
}

process_command_line()
{
  set -- `getopt dq $*`

  while [ $1 != -- ]; do
    case $1 in
      -h)     usage && exit 1 ;;
      -q)     VERBOSE_OPT=0   ;;
      \?)     usage && exit 1 ;;
      --help) usage && exit 1 ;;
      *)      echo "Ignoring unrecognized argument $1..." ;;
    esac
    shift
  done
}

output()
{
  if [ $VERBOSE_OPT -eq 1 ]; then
    echo $1
  fi
}

check_version()
{
  # Matches minimum versions
  # separate the version numbers out so they can be sorted...
  tool="$1"
  minv1=`echo "$2" | cut -f 1 -d .`
  minv2=`echo "$2" | cut -f 2 -d .`
  v=`$tool --version | sed -n '1s/.*) //p'`
  v1=`echo "$v" | cut -f 1 -d .`
  v2=`echo "$v" | cut -f 2 -d .`

  # do second test because sort doesn't sort versions as it should...
  if test "$minv1" = `(echo "$v1"; echo "$minv1") | sort -n | head -1`; then
    if test "$minv2" != `(echo "$v2"; echo "$minv2") | sort -n | head -1`; then
       error <<EOF
$tool version is $v; expected minimum version $minv1.$minv2

Set environment variables AUTOMAKE and/or AUTOCONF to point to the correct
versions. ACLOCAL may also be set, otherwise it will be derived from the
AUTOMAKE and AUTOCONF versions.

e.g AUTOMAKE=automake-1.6 AUTOCONF=2.53 sh bootstrap
EOF
    fi
  fi
}

check_for_autotools()
{
  output "checking versions of bootstrap tools"
  check_version "$AUTOCONF"   "$AUTOCONF_VERSION"
  check_version "$AUTOMAKE"   "$AUTOMAKE_VERSION"
  check_version "$ACLOCAL"    "$ACLOCAL_VERSION"
}

clean_up_old_files()
{
  output "cleaning old generated files..."

  find . -name Makefile -exec rm {} \;
  find . -name Makefile.in -exec rm {} \;
  rm -rf autom4te-*.cache
}

process_command_line $*
check_for_autotools
clean_up_old_files

echo "bootstrapping the PHP bindings build..."
echo "running aclocal..."   && $ACLOCAL $ACLOCAL_OPTS
echo "running autoconf..."  && $AUTOCONF
echo "running automake..."  && $AUTOMAKE $AUTOMAKE_OPTS
echo "running automake..."  && $AUTOMAKE -a

echo "You may now proceed to configure; see configure.ac."


# vim: set tabstop=2 shiftwidth=2 expandtab:
