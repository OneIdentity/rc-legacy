
/*
 * Functions to convert strings to OIDs and back again:
 * 	gss_oid_to_str()
 * 	gss_str_to_oid()
 */

#include <assert.h>
#include <stdlib.h>
#include "gssapi.h"
#include "pgss-oidstr.h"

#define ISNUM(c) ((c) >= '0' && (c) <= '9')

/*
 * Decodes one element from a DER-encoded OID.
 * On success, returns the new position, and stores the result 
 * On failure, returns -1.
 */
static int
parse_der_int(base, pos, maxpos, result)
    const unsigned char *base;
    int pos;
    int maxpos;
    unsigned long *result;
{
    unsigned long n;
    unsigned char b;
    int nlen;

    if (pos >= maxpos)
	return -1;
    n = 0;
    nlen = 0;
    do {
	b = base[pos++];
	/* Check that we don't exceed the length of our machine int */
	nlen += 7; 
	if (nlen > 8 * sizeof n)
	    return -1;
	n = (n << 7) | (b & 0x7f);
    } while (pos < maxpos && (b & 0x80) != 0);
    *result = n;
    return pos;
}

/*
 * Decodes an ASCII integer
 * On success, returns the new position, and stores the result.
 * On failure, returns -1.
 */
static int
parse_ascii_int(base, pos, maxpos, result)
    const unsigned char *base;
    int pos;
    int maxpos;
    unsigned long *result;
{
    unsigned long n;
    unsigned long d;

    if (!ISNUM(base[pos]))
	return -1;

    n = 0;
    while (pos < maxpos && ISNUM(base[pos])) {
	d = base[pos] - '0';
	/* Check that we don't exceed the range of our machine int */
	if (n > (~0UL / 10) || (n == (~0UL/10) && d > (~0UL - 10 * (~0UL/10))))
	    return -1;
	n = n * 10 + d;
	pos++;
    }
    *result = n;
    return pos;
}

/*
 * Appends a DER-encoded OID element to an OID buffer.
 * If the buffer is NULL, no data is stored.
 * Returns the new offset into the buffer (even if the buffer was NULL)
 */
static int
append_der_int(buf, pos, num)
    char *buf;
    int pos;
    unsigned long num;
{
    int pos2;
    unsigned long num2;
    unsigned char b;

    num2 = num;

    do {
	num2 >>= 7;
	pos++;
    } while (num2);

    pos2 = pos;
    do {
	b = num & 0x7f;
	num >>= 7;
	if (pos2 != pos)
	    b |= 0x80;
	pos2--;
	if (buf)
	    buf[pos2] = b;
    } while (num);
    return pos;
}

/*
 * Append a base 10 number into the buffer at the pos.
 * If the buffer is NULL, no data is stored.
 * Returns the new position.
 */
static int
append_ascii_int(buf, pos, num)
    char *buf;
    int pos;
    unsigned long num;
{
    int pos2;
    unsigned long num2;

    /* The zero case */
    if (num == 0) {
	if (buf)
	    buf[pos] = '0';
	return pos + 1;
    }

    num2 = num;
    while (num2 > 0) {
	num2 /= 10;
	pos++;
    }
    pos2 = pos;
    while (num > 0) {
	pos2--;
	if (buf)
	    buf[pos2] = '0' + (num % 10);
	num /= 10;
    }
    return pos;
}

/* Converts a string to elements of a DER-encoded OBJECT IDENTIFIER sequence.
 * Returns 1 on success and fills in oidbuf, otherwise returns -1 
 * on no-memory or 0 if the input string was malformed.
 */
int
_pgss_str_to_oid(strbuf, oidbuf)
    gss_buffer_t strbuf, oidbuf;
{
    int pass;
    char *out = NULL;
    int outlen = -1;
    const char *str = (const char *)strbuf->value;
    const int strlen = strbuf->length;

    /*
     * This is a two-pass conversion. The first pass determines
     * how much storage is required in out[], and the second
     * pass fills in the out[] buffer.
     */
    for (pass = 1; pass <= 2; pass++) {
	int first, inpos, outpos;
	unsigned long n, n2;

	inpos = 0;
	outpos = 0;
	first = 1;
	while (inpos < strlen) {
	    /* skip all non-numbers; assume they are delimiters */
	    while (inpos < strlen && !ISNUM(str[inpos]))
		inpos++;
	    if (inpos < strlen) {
		inpos = parse_ascii_int(str, inpos, strlen, &n);
		if (inpos < 0)
		    return 0;	    /* malformed */
		if (first) {
		    /* The first arc is combined with the second to
		     * form the first element of the OID sequence */
		    while (inpos < strlen && !ISNUM(str[inpos]))
			inpos++;
		    inpos = parse_ascii_int(str, inpos, strlen, &n2);
		    if (inpos < 0 || n2 >= 40)
			return 0;	    /* malformed (bad 2nd number) */
		    n = (n * 40) + n2;
		    first = 0;
		}
		outpos = append_der_int(out, outpos, n);
	    }
	}
	if (first)
	    return 0;			    /* malformed (empty) */

	/* At the end of the first pass, we allocate storage for out[] */
	if (pass == 1) {
	    outlen = outpos;
	    out = malloc(outlen);
	    if (!out) 
		return -1;		    /* ENOMEM */
	} else if (pass == 2)
	    assert(outlen == outpos);
    }

    oidbuf->length = outlen;
    oidbuf->value = out;
    return 1;
}

/* Converts a gss_OID into a string of the form {a b c d}. Returns 1
 * on successful conversion, 0 if the gss_OID doesn't contain a properly
 * DER-encoded OID, or -1 if there was a memory allocation error.  */
int
_pgss_oid_to_str(oid, oid_str)
    gss_OID oid;
    gss_buffer_t oid_str;
{
    char *out = NULL;
    int pass, outlen = 0;

    assert(oid != NULL);

    /*
     * This is a two-pass conversion. The first pass calculates
     * the length of the buffer to allocate, and the second
     * allocates then fills in the buffer.
     */
    for (pass = 1; pass <= 2; pass++) {
	int inpos = 0, outpos = 0, first = 1;
	unsigned long n;
	const char *base = (const char *)oid->elements;
	const int inmax = oid->length;

	while (inpos < inmax) {
	    inpos = parse_der_int(base, inpos, inmax, &n);
	    if (inpos < 0) 
		return 0;
	    if (first) {
		if (out) out[outpos] = '{';
	       	outpos++;
		outpos = append_ascii_int(out, outpos, n / 40);
		n = n % 40;
		first = 0;
	    }
	    if (out) out[outpos] = ' ';
	    outpos++;
	    outpos = append_ascii_int(out, outpos, n);
	}
	if (first)
	    return 0;	/* malformed: empty OID sequence */
	if (out) out[outpos] = '}';
	outpos++;

	if (pass == 1) {
	    outlen = outpos;
	    out = malloc(outlen + 1);
	    if (!out)
		return -1;
	    out[outlen] = '\0';
	}
    }
    oid_str->value = out;
    oid_str->length = outlen;
    return 1;
}

/*------------------------------------------------------------
 * Test cases
 */

#if defined(TEST)
#include <stdio.h>

#define ASSERT_EQ(t,r) do { \
    typeof(t) _result; \
    printf("%-40s", #t); \
    fflush(stdout); \
    _result = (t); \
    printf("%s: %s\n", _result == (r) ? "PASS" : "FAIL", #r); \
    if (!_result) exitcode=1; \
 } while (0)

#define ASSERT_STREQ(t,r) do { \
    const char * _result; \
    int _eq; \
    printf("%-40s", #t); \
    fflush(stdout); \
    _result = (t); \
    _eq = _result == r || (_result && r && (strcmp(_result, r) == 0)); \
    printf("%s: <%s>\n", _eq ? "PASS" : "FAIL", _result ? _result : "NULL"); \
    if (!_eq) exitcode=1; \
 } while (0)

#define ASSERT_OIDEQ(t,r) do { \
    gss_OID _result; \
    int _eq; \
    printf("%-40s", #t); \
    fflush(stdout); \
    _result = (t); \
    _eq = _result->length == (r)->length && \
	  memcmp(_result->elements, (r)->elements, _result->length) == 0; \
    printf("%s\n", _eq ? "PASS" : "FAIL"); \
    if (!_eq) exitcode=1; \
 } while (0)

#define PRINTOID(o) do { \
    int _i; \
    if ((o)) { \
    const unsigned char *_p = (const unsigned char *)((o)->elements); \
    printf("  %-30s = [ ", #o); \
    for (_i = 0; _i < (o)->length; _i++) \
       printf("%02x ", _p[_i]); \
    printf("]\n"); \
    } else printf("  %-30s = NULL\n", #o); \
  } while (0)

#define PRINTBUF(b) do { \
    printf("  %-30s = \"%.*s\"\n", #b, (b)->length, (b)->value); \
  } while (0)


int main()
{
    gss_buffer_desc in, out;
    gss_OID_desc oidin;
    gss_OID oid;
    int exitcode = 0;
    OM_uint32 minor;
    gss_OID_desc
	    NT_USER_NAME =           /* 1.2.840.113554.1.2.1.1 */
	        {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"};
    char * NT_USER_NAME_OID = "{1 2 840 113554 1 2 1 1}";


    in.value = "{2 16 840 1 113687 1 2 1}";
    in.length = strlen(in.value);
    oid = NULL;
    PRINTBUF(&in);
    ASSERT_EQ(gss_str_to_oid(&minor, &in, &oid), GSS_S_COMPLETE);
    PRINTOID(oid);
    ASSERT_EQ(gss_oid_to_str(&minor, oid, &out), GSS_S_COMPLETE);
    PRINTBUF(&out);
    ASSERT_STREQ(out.value, in.value);

    ASSERT_EQ(gss_oid_to_str(&minor, &NT_USER_NAME, &out), GSS_S_COMPLETE);
    PRINTBUF(&out);
    ASSERT_STREQ(out.value, NT_USER_NAME_OID);

    in.value = NT_USER_NAME_OID;
    in.length = strlen(in.value);
    oid = NULL;
    PRINTBUF(&in);
    ASSERT_EQ(gss_str_to_oid(&minor, &in, &oid), GSS_S_COMPLETE);
    PRINTOID(oid);
    PRINTOID(&NT_USER_NAME);
    ASSERT_OIDEQ(oid, &NT_USER_NAME);

    in.value = "1.2.840.113554.1.2.1.1";
    in.length = strlen(in.value);
    oid = NULL;
    PRINTBUF(&in);
    ASSERT_EQ(gss_str_to_oid(&minor, &in, &oid), GSS_S_COMPLETE);
    PRINTOID(oid);
    ASSERT_OIDEQ(oid, &NT_USER_NAME);

    in.value = "1.2.840.113554.1.2.1.1..";
    in.length = strlen(in.value);
    oid = NULL;
    PRINTBUF(&in);
    ASSERT_EQ(gss_str_to_oid(&minor, &in, &oid), GSS_S_COMPLETE);
    PRINTOID(oid);
    ASSERT_OIDEQ(oid, &NT_USER_NAME);

    in.value = "..1.2.840.113554.1.2.1.1..";
    in.length = strlen(in.value);
    oid = NULL;
    PRINTBUF(&in);
    ASSERT_EQ(gss_str_to_oid(&minor, &in, &oid), GSS_S_COMPLETE);
    PRINTOID(oid);
    ASSERT_OIDEQ(oid, &NT_USER_NAME);

    return exitcode;
}
#endif
