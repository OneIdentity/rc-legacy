#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_REVISION([$Vintela: configure.ac,v 1.3 2005/05/19 10:51:08 davidl Exp $])
AC_COPYRIGHT([Copyright (c) 2005, Vintela, Inc. All rights reserved.])
AC_INIT([ktedit], [1.1], [support@vintela.com])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([splitline.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PATH_PROG([KRB5CONFIG], [krb5-config], [:], [/opt/vintela/vas/bin:$PATH])

# Add in kerberos paths
LIBS="$LIBS `$KRB5CONFIG --libs krb5`"
CFLAGS="$CFLAGS `$KRB5CONFIG --cflags krb5`"
CPPFLAGS="$CPPFLAGS `$KRB5CONFIG --cflags krb5`"

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h unistd.h krb5.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM

# Checks for library functions.
AC_CHECK_FUNCS([strftime vprintf strchr krb5_init_context],,
		[missing="$missing $ac_func"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
