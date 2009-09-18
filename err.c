/* (c) 2009, Quest Software, Inc. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Quest Software, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Standard error handling functions for platforms that do not have them.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

#include "err.h"

#define ERR	1
#define WARN	0
#define X	2

static void _err(int exitcode, int flags, const char *fmt, va_list ap);

static void
_err(int exitcode, int flags, const char *fmt, va_list ap)
{
    fprintf(stderr, "%s: ",
	    (flags & ERR) ? "error" : "warning");
    vfprintf(stderr, fmt, ap);
    if ((flags & X) == 0)
	fprintf(stderr, ": %s", strerror(errno));
    fprintf(stderr, "\n");
    if (flags & ERR)
	exit(exitcode);
}

void
errx(int exitcode, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(exitcode, ERR|X, fmt, ap);
}

void
err(int exitcode, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(exitcode, ERR, fmt, ap);
}

void
warnx(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(0, WARN|X, fmt, ap);
    va_end(ap);
}

void
warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(0, WARN, fmt, ap);
    va_end(ap);
}
