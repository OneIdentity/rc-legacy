/* $Vintela: error.c,v 1.3 2005/04/21 02:50:32 davidl Exp $ */
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#if STDC_HEADERS
# include <stdlib.h>
# include <stdarg.h>
#endif

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "ktedit.h"

int debug = 0;

/*
 * Error handling module
 *   - prints warnings and errors to stderr with the current
 *     command line context
 */

/* Current command source information for error messages */
const char *current_filename;
int current_lineno;

/* Helper function to print a warning message */
static void
vwarn(const char *type, const char *fmt, va_list ap)
{
    if (current_filename)
	fprintf(stderr, "%s:%d: ", current_filename, current_lineno);
    fprintf(stderr, "%s: ", type);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

/* Prints a warning message on standard error */
void
warning(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vwarn("Warning", fmt, ap);
    va_end(ap);
}

/* Prints an error message, and then exits */
void
die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vwarn("Error", fmt, ap);
    va_end(ap);
    exit(1);
}

