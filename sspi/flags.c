/* (c) 2009, Quest Software, Inc. All rights reserved. */

#include <windows.h>
#include <ntsecpkg.h>   /* Gah! */
#include <security.h>
#include <stdlib.h>
#include <stdio.h>
#include "flags.h"

static struct {
    const char *desc;
    ULONG flag;
} flagtab[] = {
    { "deleg",    ISC_REQ_DELEGATE },
    { "mutual",   ISC_REQ_MUTUAL_AUTH },
    { "replay",   ISC_REQ_REPLAY_DETECT },
    { "sequence", ISC_REQ_SEQUENCE_DETECT },
    { "conf",     ISC_REQ_CONFIDENTIALITY },
    { "integ",    ISC_REQ_INTEGRITY },
    /* no "anon" */
    { "exterr",   ISC_REQ_EXTENDED_ERROR },
    { "http",     ISC_REQ_HTTP },
    { "sessionkey", ISC_REQ_USE_SESSION_KEY },
    { "stream",   ISC_REQ_STREAM },
};
#define nflagtab (sizeof flagtab / sizeof flagtab[0])

/* Converts a single name into a flag value. Returns 0 on error. */
static ULONG
name2flag(const char *name)
{
    int i;

    for (i = 0; i < nflagtab; i++)
	if (strcmp(name, flagtab[i].desc) == 0)
	    return flagtab[i].flag;
    return 0;
}

/* Converts a comma-delimited list of names to ISC_REQ_* flags */
ULONG
names2flags(const char *names)
{
    ULONG flags, flag;
    char *s, *cp;

    flags = 0;
    cp = strdup(names);
    s = strtok(cp, ",");
    while (s) {
	flag = name2flag(s);
	if (!flag) {
	    fprintf(stderr, "unknown flag '%s'\n", s);
	    exit(1);
	}
	flags |= flag;
	s = strtok(NULL, ",");
    }
    free(cp);
    return flags;
}

/* Converts ISC_REP_* bits to a string (in static storage) */
const char *
flags2str(ULONG flags)
{
    static char buf[4096];
    int i, pos = 0, desc_len;

    for (i = 0; i < nflagtab; i++)
	if ((flags & flagtab[i].flag) == flagtab[i].flag) {
	    if (pos)
		buf[pos++] = ',';
	    desc_len = strlen(flagtab[i].desc);
	    memcpy(buf + pos, flagtab[i].desc, desc_len);
	    pos += desc_len;
	}
    buf[pos] = '\0';
    return buf;
}

const char *
flags_all()
{
    ULONG all_flags = 0;
    int i;

    for (i = 0; i < nflagtab; i++)
	all_flags |= flagtab[i].flag;
    return flags2str(all_flags);
}

