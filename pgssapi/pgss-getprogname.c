/* 
 * (c) 2007 Quest Software, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *  a. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 
 *  b. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 
 *  c. Neither the name of Quest Software, Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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
