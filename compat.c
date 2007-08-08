/* $Vintela: compat.c,v 1.1 2005/04/21 02:29:26 davidl Exp $ */
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#if STDC_HEADERS
# include <stdlib.h>
# include <stdarg.h>
#endif

#include "ktedit.h"

#if !HAVE_ASPRINTF
/* Implementation of asprintf for platforms that don't have it */
int
asprintf(char **p, const char *fmt, ...)
{
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    *p = malloc(len + 1);

    va_start(ap, fmt);
    len = vsnprintf(*p, len + 1, fmt, ap);
    va_end(ap);

    return len;
}
#endif
