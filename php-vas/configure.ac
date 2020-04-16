AC_INIT([php-vas],
	[1.0.0.]esyscmd((svnversion . /trunk||echo 0)|tr : _|tr -d \\012),
	[support@quest.com])
AM_INIT_AUTOMAKE()
AC_PREFIX_DEFAULT([/opt/quest])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_SRCDIR([extension/vasapi.c])

AC_PATH_PROG([PHPIZE], [phpize], [no])
if test x"$PHPIZE" = x"no"; then
    AC_MSG_ERROR([phpize not found; please install the PHP SDK])
fi

AC_PATH_PROG([PHPCONFIG], [php-config], [no])
if test x"$PHPCONFIG" = x"no"; then
    AC_MSG_ERROR([php-config not found; please install the PHP SDK])
fi

#
# When --enable-doc=auto, we search for doxygen
#
AC_ARG_ENABLE([doc],
	      [AS_HELP_STRING([--enable-doc],
			      [enable documentation (default=auto)])],,
	      [enable_doc=auto])
if test x"$enable_doc" != x"no"; then
    AC_PATH_PROG([DOXYGEN], [doxygen], [no])
    case "$enable_doc:$DOXYGEN" in
	yes:no)	 AC_MSG_ERROR([doxygen is required by --enable-doc]);;
	auto:no) enable_doc=no;;
	*)	 enable_doc=yes;;
    esac
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test x"$enable_doc" = x"yes"])

AC_SUBST([PHPIZE])
AC_SUBST([PHPCONFIG])
AC_OUTPUT
