/* (c) 2006, Quest Software, Inc. All rights reserved. */
/* David Leonard, 2006 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS
# include <stdio.h>
#endif

/*
 * Simple getopt implementation, for platforms without it.
 */

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
