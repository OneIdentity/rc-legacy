# (c) 2006 Quest Software, Inc. All rights reserved.

AC_INIT([authtest],
	[1.0.0.]esyscmd((svnversion . /trunk || echo 0)|tr : _|tr -d \\012),
	[general@rc.vintela.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([authtest.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/opt/quest])

AC_PROG_CC
AC_C_CONST
AC_HEADER_STDC
AC_PROG_RANLIB

AC_PATH_PROG([KRB5CONFIG], [krb5-config], [no], [/opt/quest/bin:$PATH])
if test x"$KRB5CONFIG" = x"no"; then
    AC_MSG_ERROR([krb5-config was not found; is the VAS SDK installed?])
fi
KRB5_CFLAGS=`$KRB5CONFIG --cflags`; AC_SUBST(KRB5_CFLAGS)
KRB5_LIBS=`$KRB5CONFIG --libs`;     AC_SUBST(KRB5_LIBS) 

GSS_CFLAGS=`$KRB5CONFIG --cflags gssapi`; AC_SUBST(GSS_CFLAGS)
GSS_LIBS=`$KRB5CONFIG --libs gssapi`;     AC_SUBST(GSS_LIBS) 

AC_SEARCH_LIBS([pam_start], [pam])

AC_CHECK_FUNC([authenticate], [have_lam=true], [have_lam=false])
AM_CONDITIONAL(HAVE_LAM, test x$have_lam = xtrue)


AC_OUTPUT
