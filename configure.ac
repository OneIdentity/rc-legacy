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

AC_PATH_PROG([DOXYGEN], [doxygen], [no])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x"$DOXYGEN" != x"no"])

AC_SUBST([PHPIZE])
AC_SUBST([PHPCONFIG])
AC_OUTPUT
