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
 * Simple getopt implementation, for platforms without it.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS
# include <stdio.h>
#endif

char *optarg;
int optind = 1, opterr = 1, optopt;
int optidx = 0;

int
getopt(int argc, char * const argv[], const char *optstring)
{
    const char *p;
    char ch;

    if (argv[optind] == NULL || *argv[optind] != '-')
	return -1;

    p = optstring;
    ch = argv[optind][optidx + 1];
    if (*p == ':')
	p++;
    while (*p) {
	if (*p == ch) 
	    break;
	p++;
	if (*p == ':')
	    p++;
    }

    if (!*p) {
	optopt = ch;
	if (*optstring != ':')
	    fprintf(stderr, "unknown option -%c\n", ch);
	if (argv[optind][optidx + 2] == '\0') {
	    optind++;
	    optidx = 0;
	} else 
	    optidx++;
	return '?';
    }

    if (p[1] == ':') {
	if (argv[optind][optidx + 2]) 
	    optarg = argv[optind] + optidx + 2;
	else {
	    optarg = argv[++optind];
	    if (!optarg) {
		if (*optstring != ':')
		    fprintf(stderr, "missing argument to -%c\n", *p);
		optopt = *p;
		return ':';
	    }
	}
	optind++;
	optidx = 0;
    } else if (argv[optind][2] == '\0') {
	optind++;
	optidx = 0;
    } else 
	optidx++;
    return *p;
}
