AC_DEFUN([LIB_PAM],
    [
    AC_CHECK_LIB(
	[pam],
	[pam_start],
	[
	    LIBS="-lpam ${LIBS}"
	    AC_DEFINE(HAVE_LIBPAM,[],"PAM libraries")
	],
	[
	    echo "PAM not found, quitting."
	    exit 1
	]
    )
    ]
)
