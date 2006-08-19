
#include <stdio.h>
#include <stdarg.h>

#include "authtest.h"

const char 
    *col_SO = "", 
    *col_SO_ERR = "",
    *col_SO_INP = "",
    *col_SE = "";

void 
authtest_colours()
{
    col_SO     = "\033[32m";
    col_SO_ERR = "\033[31m";
    col_SO_INP = "\033[34m";
    col_SE     = "\033[m";
}

/* Prints a message surrounded by col_SO and col_SE \n to stderr */
void
debug(fmt)
    const char *fmt;
{
    va_list ap;

    fprintf(stderr, "%s", col_SO);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", col_SE);
}


/* Prints a message surrounded by col_SO_ERR and col_SE \n to stderr */
void
debug_err(fmt)
    const char *fmt;
{
    va_list ap;

    fprintf(stderr, "%s", col_SO_ERR);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", col_SE);
}

