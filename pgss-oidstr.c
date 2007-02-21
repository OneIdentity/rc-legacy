
/*
 * Functions to convert strings to OIDs and back again:
 * 	gss_oid_to_str()
 * 	gss_str_to_oid()
 */

#include <stdlib.h>
#include "gssapi.h"

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

    if (pos >= maxpos)
	return -1;
    n = 0;
    do {
	b = base[pos++];
	/* XXX: check for overflow in n */
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

    if (!ISNUM(base[pos]))
	return -1;

    n = 0;
    while (pos < maxpos && ISNUM(base[pos])) {
	/* XXX: check for overflow in n */
	n = n * 10 + (base[pos] - '0');
	pos++;
    }
    *result = n;
    return pos;
}

/*
 * Appends a DER-encoded OID element to an OID buffer.
 * If the buffer is NULL, no data is stored.
 * Returns the new position.
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


OM_uint32
gss_str_to_oid(minor_status, oid_str, oid)
    OM_uint32 *minor_status;
    gss_buffer_t oid_str;
    gss_OID *oid;
{
    int state;
    char *out = NULL;
    int outlen = 0;
    const char *in = (const char *)oid_str->value;
    const int inmax = oid_str->length;
    gss_OID o;

    for (state = 0; state < 2; state++) {
	int first, inpos, outpos;
	unsigned long n;

	inpos = 0;
	outpos = 0;
	first = 1;
	while (inpos < inmax) {
	    while (inpos < inmax && !ISNUM(in[inpos]))
		inpos++;
	    if (inpos < inmax) {
		inpos = parse_ascii_int(in, inpos, inmax, &n);
		if (first && inpos >= 0) {
		    unsigned long n2;
		    while (inpos < inmax && !ISNUM(in[inpos]))
			inpos++;
		    inpos = parse_ascii_int(in, inpos, inmax, &n2);
		    if (inpos < 0 || n2 >= 40) {
			*minor_status = 0; /* XXX malformed */
			return GSS_S_FAILURE;
		    }
		    n = (n * 40) + n2;
		    first = 0;
		}
		if (inpos < 0) {
		    *minor_status = 0; /* XXX malformed */
		    return GSS_S_FAILURE;
		}
		outpos = append_der_int(out, outpos, n);
	    }
	}

	if (state == 0) {
	    outlen = outpos;
	    out = malloc(outlen);
	    if (!out) {
		*minor_status = 0; /* XXX: ENOMEM */
		return GSS_S_FAILURE;
	    }
	}
    }

    o = (gss_OID)malloc(sizeof *o);
    if (!o) {
	free(out);
	*minor_status = 0; /* XXX: ENOMEM */
	return GSS_S_FAILURE;
    }

    o->length = outlen;
    o->elements = out;

    *oid = o;
    return GSS_S_COMPLETE;
}

OM_uint32
gss_oid_to_str(minor_status, oid, oid_str)
    OM_uint32 *minor_status;
    gss_OID oid;
    gss_buffer_t oid_str;
{
    char *out = NULL;
    int state, outlen;
    const char *base = (const char *)oid->elements;
    const int inmax = oid->length;

    oid_str->value = NULL;
    oid_str->length = 0;

    /*
     * This is a two-pass conversion. The first pass calculates
     * the length of the generated string, and the second
     * fills in the buffer
     */
    for (state = 0; state < 2; state++) {
	int inpos, outpos, first;
	unsigned long n;

	inpos = 0;
	outpos = 0;
	first = 1;
	while (inpos < inmax) {
	    inpos = parse_der_int(base, inpos, inmax, &n);
	    if (inpos < 0) {
		*minor_status = 0; /* XXX: "Malformed OID" */
		return GSS_S_FAILURE;
	    }
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
	if (out) out[outpos] = '}';
	outpos++;

	if (state == 0) {
	    outlen = outpos;
	    out = malloc(outlen + 1);
	    if (!out) {
		*minor_status = 0; /* XXX: ENOMEM */
		return GSS_S_FAILURE;
	    }
	    out[outlen] = '\0';
	}
    }
    oid_str->value = out;
    oid_str->length = outlen;
    return GSS_S_COMPLETE;
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
