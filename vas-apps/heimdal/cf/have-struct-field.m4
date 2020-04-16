dnl $Id: have-struct-field.m4,v 1.9 2004/08/26 12:35:42 joda Exp $
dnl
dnl check for fields in a structure
dnl
dnl AC_HAVE_STRUCT_FIELD(struct, field, headers)

AC_DEFUN([AC_HAVE_STRUCT_FIELD], [
define(cache_val, translit(ac_cv_type_$1_$2, [A-Z ], [a-z_]))
AC_CACHE_CHECK([for $2 in $1], cache_val,[
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[$3]],[[$1 x; x.$2]])],
[cache_val=yes],
[cache_val=no])])
if test "$cache_val" = yes; then
	define(foo, translit(HAVE_$1_$2, [a-z ], [A-Z_]))
	AC_DEFINE(foo, 1, [Define if $1 has field $2.])
	undefine([foo])
fi
undefine([cache_val])
])
