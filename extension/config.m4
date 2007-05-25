PHP_ARG_ENABLE([vas], [whether to enable VAS],
[ --enable-vas   Enable VAS support], [yes])

AC_PATH_PROG([VASCONFIG], [vas-config], [no], [/opt/quest/bin:$PATH])
if test x"$VASCONFIG" = x"no"; then
    AC_MSG_ERROR([vas-config was not found; please install the VAS SDK])
fi
AC_SUBST([VASCONFIG])

if test "$PHP_VAS" = "yes"; then

  VAS_CFLAGS=`$VASCONFIG --cflags`
  VAS_LIBS=`$VASCONFIG --libs`

  AC_DEFINE([HAVE_VAS], [1], [Whether you have VAS])
  PHP_NEW_EXTENSION([vas], [vasapi.c], $ext_shared,,[$VAS_CFLAGS])

  dnl VAS_API_VERSION was not reliable before 4.3.0
  save_CFLAGS="$CFLAGS"
  save_LIBS="$LIBS"
  LIBS="$LIBS $VAS_LIBS"
  CFLAGS="$CFLAGS $VAS_CFLAGS"
  AC_CHECK_DECLS([VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND,VAS_ID_FLAG_DERIVE_FILE_CCACHE_FROM_ID,VAS_ERR_NOT_IMPLEMENTED,VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT,vas_name_compare],[#include <vas.h>])
  CFLAGS="$save_CFLAGS"
  LIBS="$save_LIBS"

  dnl PHP_EVAL_LIBLINE([$VAS_LIBS])
  VAS_SHARED_LIBADD="$VAS_LIBS"
  PHP_SUBST([VAS_SHARED_LIBADD])
fi

