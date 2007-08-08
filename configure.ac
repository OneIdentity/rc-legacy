#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_REVISION([$Vintela: configure.ac,v 1.7 2007/08/08 06:48:12 dleonard Exp $])
AC_COPYRIGHT([(c) 2005, Quest Software, Inc. All rights reserved.])
AC_INIT([ktedit], [1.2], [support@vintela.com])
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
AC_CHECK_HEADERS([stdlib.h string.h unistd.h krb5.h getopt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM

cat >>confdefs.h <<.
#include <vas_symbols/krb5_sym.h>
.

# Checks for library functions.
AC_CHECK_FUNCS([strftime vprintf strchr krb5_init_context],,
		[missing="$missing $ac_func"])

# These determine if we have the MIT or Heimdal API
AC_CHECK_FUNCS([krb5_c_string_to_key krb5_keytype_to_string krb5_xfree])
AC_CHECK_FUNCS([krb5_get_err_text krb5_string_to_keytype krb5_principal_match krb5_keytype_to_string])
AC_CHECK_FUNCS([error_message])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
