#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_VSYSLOG
#ifndef VSYSLOG_H
#define VSYSLOG_H
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>

/*
 * the theory behind this is that we might be trying to call vsyslog
 * when there's no memory left, and we should try to be as useful as
 * possible.  And the format string should say something about what's
 * failing.
 */

static void
simple_vsyslog(int pri, const char *fmt, va_list ap);

void 
vsyslog(int pri, const char *fmt, va_list ap);

#endif
#endif
