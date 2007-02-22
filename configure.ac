# (c) 2007 Quest Software, Inc. All rights reserved.

AC_INIT([pgssapi],
	[0.0.0.]esyscmd({ svnversion -n . /trunk || echo 0; }|tr -d '\012'),
	[support@quest.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([pgssapi.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/opt/quest])

AC_PROG_CC
AC_PROG_RANLIB
dnl AC_C_CONST
dnl AC_HEADER_STDC
AC_CHECK_HEADERS([libgen.h])

# CHECK_SYMBOL(sym,[if-true],[if-false]) - tries linking to resolve sym
AC_DEFUN([CHECK_SYMBOL],
[
 AS_VAR_PUSHDEF([my_var], [ac_cv_var_$1])dnl
 AC_CACHE_CHECK([for $1], my_var,
    [AC_LINK_IFELSE(
     [AC_LANG_PROGRAM([extern char $1;],
		      [if ($1) return 1;])],
     [AS_VAR_SET(my_var, yes)],
     [AS_VAR_SET(my_var, no)])
    ])
 AS_IF(test AS_VAR_GET(my_var) = yes,[$2],[$3])
 AS_VAR_POPDEF([my_var])dnl
])

# Various ways of determining the current executable's name
ok=no
CHECK_SYMBOL([__progname], [ok=yes;AC_DEFINE([HAVE___PROGNAME],1,[__progname])])
CHECK_SYMBOL([p_xargv],    [ok=yes;AC_DEFINE([HAVE_P_XARGV],   1,[p_xargv])])
CHECK_SYMBOL([\$ARGV],     [ok=yes;AC_DEFINE([HAVE__ARGV],     1,[$ARGV])])
AC_CHECK_FUNCS([getprogname getexecname],[ok=yes])
if test ok = no; then
    AC_MSG_ERROR([No way known to get progname from crt0 on this system])
fi

AC_CHECK_FUNCS([basename])
AC_CHECK_FUNCS([getenv])

AC_OUTPUT
