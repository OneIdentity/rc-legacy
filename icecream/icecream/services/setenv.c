
#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "setenv.h"

#if !HAVE_SETENV && HAVE_PUTENV
/* It leaks! But I don't care! */
int
setenv(const char *name, const char *value, int overwrite)
{
    char *buffer, *old;

    if (!overwrite && getenv(name))
	return 0;   /* XXX */
    if (!buffer) {
	errno = ENOMEM;
	return -1;
    }
    strcpy(buffer, name);
    strcat(buffer, "=");
    strcat(buffer, value);
    return putenv(buffer);
}
#endif
