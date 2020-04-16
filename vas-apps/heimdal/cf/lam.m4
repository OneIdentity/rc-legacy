# Only expected to be found on AIX.
AC_DEFUN([AUTH_LAM],
    [
    AC_CHECK_FUNC(
	[loginrestrictions],
	[
	    AC_DEFINE([HAVE_LAM], 1, [AIX LAM authentication system])
	]
    )
    ]
)
