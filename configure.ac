# (c) 2006 Quest Software, Inc. All rights reserved.

AC_INIT([vasidmap],
	[0.6]esyscmd((svnversion . /trunk||echo 0)|tr : _|tr -d \\012),
	[samba@rc.vintela.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([vasidmap.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/opt/quest])

AC_PROG_CC
AC_C_CONST
AC_HEADER_STDC
AC_CHECK_HEADERS([grp.h unistd.h pwd.h sys/socket.h sys/un.h errno.h netinet/in.h err.h])

AC_PATH_PROG([VASCONFIG], [vas-config], [no], [/opt/quest/bin:$PATH])
if test x"$VASCONFIG" = x"no"; then
    AC_MSG_ERROR([vas-config was not found; is the VAS SDK installed?])
fi
AC_SUBST([VASCONFIG])

AC_CHECK_FUNC([getopt], [], [AC_LIBOBJ([getopt])])
AC_CHECK_FUNC([errx])

AC_SEARCH_LIBS([socket], [socket])

AC_CHECK_TYPE([socklen_t],[AC_DEFINE([HAVE_SOCKLEN_T],[1],[socklen_t])],,[
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])

AC_OUTPUT
