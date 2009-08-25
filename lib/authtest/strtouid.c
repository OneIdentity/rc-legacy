/* (c) 2006 Quest Software, Inc. All rights reserved. */
/*
 * Pam testing tool
 * David Leonard
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <pwd.h>
#include "authtest.h"

/* Convert a string containing a username or integer to a uid */
int
strtouid(const char *s)
{
    struct passwd *pw;

    if (*s >= '0' && *s <= '9')
	return atoi(s);
    pw = getpwnam(s);
    if (!pw) {
	fprintf(stderr, "bad username '%s'\n", s);
	exit(1);
    }
    return pw->pw_uid;
}

