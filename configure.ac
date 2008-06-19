# (c) 2006 Quest Software, Inc. All rights reserved.

AC_INIT([quest-vasidmap],
	[1.0.0.]esyscmd((svnversion . /trunk||echo 0)|tr : _|tr -d \\012),
	[support@quest.com])
AM_INIT_AUTOMAKE()
AC_CONFIG_SRCDIR([vasidmap.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/opt/quest])

AC_PROG_CC
AC_PROG_SED
AC_C_CONST
AC_HEADER_STDC
AC_CHECK_HEADERS([grp.h unistd.h pwd.h sys/socket.h sys/un.h errno.h netinet/in.h err.h])

AC_PATH_PROG([VASCONFIG], [vas-config], [no], [/opt/quest/bin:$PATH])
if test x"$VASCONFIG" = x"no"; then
    AC_MSG_ERROR([vas-config was not found; is the VAS SDK installed?])
fi
AC_SUBST([VASCONFIG])

VAS_CFLAGS=`$VASCONFIG --cflags`
AC_SUBST([VAS_CFLAGS])
VAS_LIBS=`$VASCONFIG --libs`
AC_SUBST([VAS_LIBS])

AC_CHECK_FUNC([getopt], [], [AC_LIBOBJ([getopt])])
AC_CHECK_FUNC([errx], [], [AC_LIBOBJ([err])])
AC_CHECK_FUNC([inet_pton], [], [AC_LIBOBJ([inet_pton])])
AC_CHECK_FUNCS([syslog])

AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([setsockopt], [xnet])
AC_SEARCH_LIBS([inet_addr], [xnet])

AC_CHECK_TYPE([socklen_t],[AC_DEFINE([HAVE_SOCKLEN_T],[1],[socklen_t])],,[
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])

AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(uid_t,, [#include <sys/types.h>])
AC_CHECK_SIZEOF(gid_t,, [#include <sys/types.h>])
AC_CHECK_SIZEOF(pid_t,, [#include <sys/types.h>])

AC_OUTPUT
