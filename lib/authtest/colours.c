/* (c) 2006 Quest Software, Inc. All rights reserved. */
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "authtest.h"

const char 
    *col_SO = "", 
    *col_SO_ERR = "",
    *col_SO_INP = "",
    *col_SE = "";

void 
authtest_init()
{
    const char *term = NULL;

    /* I'm too cheap to go hunting for termcap/terminfo */
#if HAVE_GETENV
    term = getenv("TERM");
#endif
    if (!term)
        term ="unknown";
    if (strncmp(term, "xterm", 5) == 0 ||
        strncmp(term, "vt", 2) == 0 ||
        strncmp(term, "putty", 5) == 0)
    {
        col_SO     = "\033[32m";
        col_SO_ERR = "\033[31m";
        col_SO_INP = "\033[34m";
        col_SE     = "\033[m";
    }
}

/* Prints a message surrounded by col_SO and col_SE \n to stderr */
void
debug(const char *fmt, ...)
{
    va_list ap;

    fflush(stdout);
    fprintf(stderr, "%s", col_SO);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", col_SE);
}

/* Prints a message surrounded by col_SO and col_SE to stderr */
void
debug_nonl(const char *fmt, ...)
{
    va_list ap;

    fflush(stdout);
    fprintf(stderr, "%s", col_SO);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s", col_SE);
}


/* Prints a message surrounded by col_SO_ERR and col_SE \n to stderr */
void
debug_err(const char *fmt, ...)
{
    va_list ap;

    fflush(stdout);
    fprintf(stderr, "%s", col_SO_ERR);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", col_SE);
}

