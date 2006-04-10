# It's recommended to declare the VARIABLE (1st arg) as precious, see Setting
# Output Variables::AC_ARG_VAR for details.

AC_DEFUN([LOGIN_PATH],
    [
	AC_PATH_PROG([LOGIN], [login], [not-found])

	if test "$LOGIN" = "not-found"; then
	    AC_MSG_ERROR([cannot find login])
	fi

	AC_DEFINE_UNQUOTED(_PATH_LOGIN, $LOGIN, Path to the login command)
    ]
)
