/* (c) 2005 Quest Software, Inc. All rights reserved. */
/* David Leonard */

/*
 * Common code for the GSSAPI token tester
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <gssapi.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "gss-common.h"
#include "base64.h"
#include "authtest.h"

#include "gssapi_krb5.h"

int base64_whitespace = 1;

/* Terminates program with a GSS error message. */
void
gssdie(int exitcode, struct res *res, const char *message)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    debug_err("error: %s", message);
    if (res) {
	OM_uint32 ctx = 0;
	do {
	    major = gss_display_status(&minor, res->major,
		    GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &buf);
	    if (GSS_ERROR(major)) { exit(1); }
	    debug_err("\t%.*s", buf.length, (char *)buf.value);
	    (void) gss_release_buffer(&minor, &buf);
	} while (ctx);
	if (res->minor) do {
	    major = gss_display_status(&minor, res->minor,
		    GSS_C_MECH_CODE, GSS_C_NO_OID, &ctx, &buf);
	    if (GSS_ERROR(major)) { exit(1); }
	    debug_err("\t%.*s", buf.length, (char *)buf.value);
	    (void) gss_release_buffer(&minor, &buf);
	} while (ctx);
    }
    exit(exitcode);
}

static struct {
    const char *desc;
    OM_uint32 flag;
} flagtab[] = {
    { "deleg", GSS_C_DELEG_FLAG },
    { "mutual", GSS_C_MUTUAL_FLAG },
    { "replay", GSS_C_REPLAY_FLAG },
    { "sequence", GSS_C_SEQUENCE_FLAG },
    { "conf", GSS_C_CONF_FLAG },
    { "integ", GSS_C_INTEG_FLAG },
    { "anon", GSS_C_ANON_FLAG }
};
#define nflagtab (sizeof flagtab / sizeof flagtab[0])

/* Return GSS flags in the form "<flag,flag,...>" */
const char *
flags2str(OM_uint32 flags)
{
    static char buf[1024];
    char nc = '<';
    char *s;
    int i;

    s = buf;
    for (i = 0; i < nflagtab; i++)
	if (flagtab[i].flag & flags) {
            int len = strlen(flagtab[i].desc);
            *s++ = nc;
            memcpy(s, flagtab[i].desc, len); s+=len;
	    nc = ',';
	}
    if (nc == '<') 
        *s++ = '<';
    *s++ = '>';
    *s = 0;
    return buf;
}

/* Converts a flag name to a flag bitmask. Returns 0 if name unknown */
OM_uint32
name2flag(const char *name)
{
    int i;
    for (i = 0; i < nflagtab; i++)
	if (strcmp(name, flagtab[i].desc) == 0)
	    return flagtab[i].flag;
    return 0;
}

/* Converts a comma-separated list of flag names to a bitmask.
 * Dies if a flag name is not known */
OM_uint32
names2flags(const char *names)
{
    OM_uint32 flags, flag;
    char *s, *cp;
   
    flags = 0;
    cp = strdup(names);
    s = strtok(cp, ",");
    while (s) {
	flag = name2flag(s);
	if (!flag) { debug_err("unknown flag '%s'", s); exit(1); }
	flags |= flag;
	s = strtok(NULL, ",");
    }
    free(cp);
    return flags;
}

/*
 * Reads and decodes base64 from stdin into a GSS buffer. 
 * Caller must free buf->value.
 */
void
readb64(gss_buffer_t buf)
{
    char sbuf[65537], *dec;
    int bufpos, inlen, ch;

    if (isatty(0)) {
	fprintf(stderr, "\n%sinput:%s ", col_SO_INP, col_SE);
    	fflush(stdout);
    }
    bufpos = 0;
    while ((ch = fgetc(stdin)) != EOF) {
	if (ch == '.') 
	    break;
	if (!isspace(ch) && bufpos + 1 < sizeof sbuf)
	    sbuf[bufpos++] = ch;
    }
    sbuf[bufpos] = '\0';
    if (ch == EOF) {
	debug_err("fgetc: eof");
	exit(1);
    }
    dec = base64_string_decode(sbuf, &inlen);
    if (!dec) {
	debug_err("base64_string_decode: failed");
	exit(1);
    }
    printf("\n");
    buf->value = dec;
    buf->length = inlen;
}

/*
 * Writes the gss buffer as base64 to stdout, then releases and
 * zeros the buffer structure.
 */
void
writeb64_and_release(gss_buffer_t buf)
{
    char *enc;
    struct res res;
   
    enc = base64_string_encode(buf->value, buf->length);
    if (isatty(0))
	printf("output: ");
    if (!base64_whitespace)
        printf("%s.\n", enc);
    else {
        char *e = enc;
        int len;
        while ((len = strlen(e)) > 60) {
            printf(" %.60s\n", e);
            e += 60;
        }
        printf(" %s.\n", e);
    }
    free(enc);
    res.major = gss_release_buffer(&res.minor, buf);
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_release_buffer");
    buf->value = 0;
    buf->length = 0;
}

static int
oideq(const gss_OID oid1, const gss_OID oid2)
{
    if (oid1 == oid2) return 1;
    return oid1 && oid2 && oid1->length == oid2->length &&
	   memcmp(oid1->elements, oid2->elements, oid1->length) == 0;
}

const char *
oid2str(gss_OID oid)
{
    static char buf[1024];
    char numbuf[10];
    int i, len;
    unsigned long n;
    unsigned char *b;
    char *s;

#define T(n) if (oideq(n,oid)) { return #n; }
    T(GSS_C_NO_OID)
    T(GSS_C_NT_USER_NAME)
    T(GSS_C_NT_MACHINE_UID_NAME)
    T(GSS_C_NT_STRING_UID_NAME)
    T(GSS_C_NT_HOSTBASED_SERVICE_X)
    T(GSS_C_NT_HOSTBASED_SERVICE)
    T(GSS_C_NT_ANONYMOUS)
    T(GSS_C_NT_EXPORT_NAME)
    T(GSS_SPNEGO_MECHANISM)
    T(GSS_KRB5_NT_PRINCIPAL_NAME)
    T(GSS_KRB5_NT_USER_NAME)
    T(GSS_KRB5_NT_MACHINE_UID_NAME)
    T(GSS_KRB5_NT_STRING_UID_NAME)
    T(GSS_KRB5_MECHANISM)
#undef T

    if (oid->length < 3)
	return "<bad oid>";
    b = oid->elements;
    s = buf;

    *s++ = '{';
#define N(n) \
        snprintf(numbuf, sizeof numbuf, "%lu", n); \
        len = strlen(numbuf); \
        memcpy(s, numbuf, len); \
        s += len;
    N(b[0] / 40)
    *s++ = '.';
    N(b[0] % 40)
    n = 0;
    for (i = 1; i < oid->length; i++) {
	n = n << 7 | (b[i] & 0x7f);
	if ((b[i] & 0x80) == 0) {
            *s++ = '.';
            N(n)
	    n = 0;
	}
    }
    *s++ = '.';
    *s = 0;
    return buf;
}
