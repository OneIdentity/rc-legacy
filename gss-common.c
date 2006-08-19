/* (c) 2005 Quest Software, Inc. All rights reserved. */
/* David Leonard */

/*
 * Common code for the GSSAPI token tester
 */

#include <stdio.h>
#include <gssapi.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "gss-common.h"
#include "base64.h"

#include "gssapi_krb5.h"

/* Terminates program with a GSS error message written to stderr. */
void
gssdie(int exitcode, struct res *res, const char *message)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    fprintf(stderr, "error: %s", message);
    if (res) {
	OM_uint32 ctx = 0;
	do {
	    major = gss_display_status(&minor, res->major,
		    GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx, &buf);
	    if (GSS_ERROR(major)) { exit(1); }
	    fprintf(stderr, "; %.*s", buf.length, (char *)buf.value);
	    (void) gss_release_buffer(&minor, &buf);
	} while (ctx);
	if (res->minor) do {
	    major = gss_display_status(&minor, res->minor,
		    GSS_C_MECH_CODE, GSS_C_NO_OID, &ctx, &buf);
	    if (GSS_ERROR(major)) { exit(1); }
	    fprintf(stderr, "; %.*s", buf.length, (char *)buf.value);
	    (void) gss_release_buffer(&minor, &buf);
	} while (ctx);
    }
    fprintf(stderr, "\n");
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

/* Print GSS flags to stderr in the form "<flag,flag,...>" */
void
fprintflags(FILE *out, OM_uint32 flags)
{

    char nc = '<';
    int i;

    for (i = 0; i < nflagtab; i++)
	if (flagtab[i].flag & flags) {
	    fprintf(out, "%c%s", nc, flagtab[i].desc);
	    nc = ',';
	}
    fprintf(out, nc == '<' ? "<>" : ">");
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
	if (!flag) { fprintf(stderr, "unknown flag '%s'\n", s); exit(1); }
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
	fprintf(stderr, "\ninput: ");
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
	fprintf(stderr, "fgetc: eof\n");
	exit(1);
    }
    dec = base64_string_decode(sbuf, &inlen);
    if (!dec) {
	fprintf(stderr, "base64_string_decode: failed\n");
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
    printf("%s.\n", enc);
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

void
fprintoid(FILE *out, gss_OID oid)
{
    int i;
    unsigned long n;
    unsigned char *b;

#define T(n) if (oideq(n,oid)) { fprintf(out, "%s", #n); return; }
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

    if (oid->length < 3) {
	fprintf(out, "<bad oid>");
	return;
    }
    b = oid->elements;
    fprintf(out, "{%u.%u", b[0] / 40, b[0] % 40);
    n = 0;
    for (i = 1; i < oid->length; i++) {
	n = n << 7 | (b[i] & 0x7f);
	if ((b[i] & 0x80) == 0) {
	    fprintf(out, ".%lu", n);
	    n = 0;
	}
    }
    fprintf(out, "}");
}
