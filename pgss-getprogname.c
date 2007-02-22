/* (c) 2007 Quest Software, Inc. All rights reserved */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if HAVE_STDLIB_H	/* getexecname(), getprogname() */
# include <stdlib.h>
#endif

#include "pgss-common.h"

#if !HAVE_GETPROGNAME
/*
 * getprogname() returns the currently-running executable's program name.
 * The returned name is not trustworthy: it may be a relative path, or it 
 * may have been altered by the program itself. It may even have been set 
 * to NULL.
 */
const char *
getprogname() {
# if HAVE___PROGNAME		    /* Linux */
    extern char *__progname;
    return __progname;
# elif HAVE_GETEXECNAME		    /* Solaris */
    return getexecname(); 
# elif HAVE_P_XARGV		    /* AIX */
    extern char **p_xargv;
    return *p_xargv;
# elif HAVE__ARGV		    /* HPUX */
    /* #include <crt0.h> for _DLD_ARGV ? */
    extern char *$ARGV;
    return $ARGV;
# else
#  warning "Don't know how to get program name on this platform"
    return "unknown";
# endif
}
#endif /* !HAVE_GETPROGNAME */


#if TEST
#include <stdio.h>
int
main(int argc, char **argv)
{
    const char *name;

    printf("argv[0] = '%s'\n", argv[0]);
    name = getprogname();
    if (name)
	printf("getprogname = '%s'\n", name);
    else
	printf("getprogname = NULL\n");
    return 0;
}
#endif /* TEST */
