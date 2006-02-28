dnl $Id$
dnl
dnl
dnl 
dnl Enable a with-krb5 option to pull in an external krb5 library for building
dnl apps

AC_DEFUN([AC_WITH_KRB5],
[
# Check whether user wants Kerberos 5 support
DEFAULT_WITH_KRB5=$1
WITH_KRB5=
AC_ARG_WITH(krb5,
	[ --with-krb5=PATH   Enable Kerberos 5 support],
	[ WITH_KRB5=${withval} ],
        [ WITH_KRB5=$DEFAULT_WITH_KRB5 ])


KRB5_MSG="no"
if test "x${WITH_KRB5}" != "xno" ; then
	if test "x$WITH_KRB5" = "xyes" ; then
		KRB5ROOT="/opt/vas"
	else
		KRB5ROOT=${WITH_KRB5}
	fi

	AC_DEFINE(KRB5)
	KRB5_MSG="yes"

	AC_MSG_CHECKING(for krb5-config)
	if test -x  $KRB5ROOT/bin/krb5-config ; then
		KRB5CONF=$KRB5ROOT/bin/krb5-config
		AC_MSG_RESULT($KRB5CONF)

		AC_MSG_CHECKING(for gssapi support)
		if $KRB5CONF | grep gssapi >/dev/null ; then
			AC_MSG_RESULT(yes)
			AC_DEFINE(GSSAPI)
			k5confopts=gssapi
		else
			AC_MSG_RESULT(no)
			k5confopts=""
		fi
		K5CFLAGS="`$KRB5CONF --cflags $k5confopts`"
		K5LIBS="`$KRB5CONF --libs $k5confopts`"
		CPPFLAGS="$CPPFLAGS $K5CFLAGS"
		AC_MSG_CHECKING(whether we are using Heimdal)
		AC_TRY_COMPILE([ #include <krb5.h> ],
			       [ char *tmp = heimdal_version; ],
			       [ AC_MSG_RESULT(yes)
				 AC_DEFINE(HEIMDAL) ],
			         AC_MSG_RESULT(no)
		)
	else
		AC_MSG_RESULT(no)
		CPPFLAGS="$CPPFLAGS -I${KRB5ROOT}/include"
		LDFLAGS="$LDFLAGS -L${KRB5ROOT}/lib"
		AC_MSG_CHECKING(whether we are using Heimdal)
		AC_TRY_COMPILE([ #include <krb5.h> ],
			       [ char *tmp = heimdal_version; ],
			       [ AC_MSG_RESULT(yes)
				 AC_DEFINE(HEIMDAL)
				 K5LIBS="-lkrb5 -ldes"
				 K5LIBS="$K5LIBS -lcom_err -lasn1"
				 AC_CHECK_LIB(roken, net_write, 
				   [K5LIBS="$K5LIBS -lroken"])
			       ],
			       [ AC_MSG_RESULT(no)
				 K5LIBS="-lkrb5 -lk5crypto -lcom_err"
			       ]
		)
		AC_SEARCH_LIBS(dn_expand, resolv)

		AC_CHECK_LIB(gssapi,gss_init_sec_context,
			[ AC_DEFINE(GSSAPI)
			  K5LIBS="-lgssapi $K5LIBS" ],
			[ AC_CHECK_LIB(gssapi_krb5,gss_init_sec_context,
				[ AC_DEFINE(GSSAPI)
				  K5LIBS="-lgssapi_krb5 $K5LIBS" ],
				AC_MSG_WARN([Cannot find any suitable gss-api library - build may fail]),
				$K5LIBS)
			],
			$K5LIBS)
		
		AC_CHECK_HEADER(gssapi.h, ,
			[ unset ac_cv_header_gssapi_h
			  CPPFLAGS="$CPPFLAGS -I${KRB5ROOT}/include/gssapi"
			  AC_CHECK_HEADERS(gssapi.h, ,
				AC_MSG_WARN([Cannot find any suitable gss-api header - build may fail])
			  )
			]
		)

		oldCPP="$CPPFLAGS"
		CPPFLAGS="$CPPFLAGS -I${KRB5ROOT}/include/gssapi"
		AC_CHECK_HEADER(gssapi_krb5.h, ,
				[ CPPFLAGS="$oldCPP" ])

	fi
	if test ! -z "$need_dash_r" ; then
		LDFLAGS="$LDFLAGS -R${KRB5ROOT}/lib"
	fi
	if test ! -z "$blibpath" ; then
		blibpath="$blibpath:${KRB5ROOT}/lib"
	fi
fi

AC_CHECK_HEADERS(gssapi.h gssapi/gssapi.h)
AC_CHECK_HEADERS(gssapi_krb5.h gssapi/gssapi_krb5.h)
AC_CHECK_HEADERS(gssapi_generic.h gssapi/gssapi_generic.h)

LIBS="$LIBS $K5LIBS"
AC_SEARCH_LIBS(k_hasafs, kafs, AC_DEFINE(USE_AFS))
AC_SEARCH_LIBS(krb5_init_ets, $K5LIBS, AC_DEFINE(KRB5_INIT_ETS))
]
)

])
