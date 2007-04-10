/* (c) 2007 Quest Software Inc. All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "gssapi.h"
#include "pgssapi.h"
#include "pgss-dispatch.h"
#include "pgss-config.h"


/*------------------------------------------------------------
 * RFC2045 base64 encoding and decoding 
 */

static int base64_debug = 1;

/* State type for the base64 stream encoder functions. */
typedef struct base64_enc_state {
    char grp[3];
    int  inpos;
} base64_enc_state_t;

/* State type for the base64 stream decoder functions. */
typedef struct base64_dec_state {
    char grp[4];
    int inpos;
    int pad;
    int n;
} base64_dec_state_t;

/* Encoding table: value to digit */
static char enctab[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789+/";

/* Decoding table: digit to value */
static signed char dectab[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,   /* -1: invalid */
    -1,-2,-2,-2,-2,-2,-1,-1,   /* -2: whitespace */
    -1,-1,-1,-1,-1,-1,-1,-1,   /* 0..63: base64 digit */
    -1,-1,-1,-1,-1,-1,-1,-1,
    -2,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,
    60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,
     7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,
    23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,
    33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,
    49,50,51,-1,-1,-1,-1,-1
};

static void
base64_encode_init(state)
    base64_enc_state_t *state;
{
    state->inpos = 0;
}

static int
base64_encode_sub(state, inbuf, inbuflen, outbuf, outbuflen)
    base64_enc_state_t *state;
    const char *inbuf;
    int inbuflen;
    char *outbuf;
    int outbuflen;
{
    int inpos = 0;
    int outpos = 0;

    /* Encode as many whole input triples into 4 output chars as possible */
    while (inpos < inbuflen) {
	state->grp[(state->inpos + inpos) % 3] = inbuf[inpos]; inpos++;
	if ((state->inpos + inpos) % 3 == 0) {
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[(state->grp[0] & 0xfc) >> 2 & 0x3f];
	    outpos++;
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[((state->grp[0] & 0x03) << 4 |
				      (state->grp[1] & 0xf0) >> 4) & 0x3f];
	    outpos++;
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[((state->grp[1] & 0x0f) << 2 | 
				      (state->grp[2] & 0xc0) >> 6) & 0x3f];
	    outpos++;
	    if (outpos < outbuflen)
		outbuf[outpos] = enctab[state->grp[2] & 0x3f];
	    outpos++;
	}
    }
    state->inpos = state->inpos + inpos;
    return outpos;
}

static int
base64_encode_fini(state, outbuf, outbuflen)
    base64_enc_state_t *state;
    char *outbuf;
    int outbuflen;
{
    int outpos = 0, i;

    /* Handle remaining characters that don't fit into a triple */
    if (state->inpos % 3 != 0) {
	for (i = state->inpos % 3; i < 3; i++)
	    state->grp[i] = 0;
	if (outpos < outbuflen)
	    outbuf[outpos] = enctab[(state->grp[0] & 0xfc) >> 2 & 0x3f];
	outpos++;
	if (outpos < outbuflen)
	    outbuf[outpos] = enctab[((state->grp[0] & 0x03) << 4 |
				  (state->grp[1] & 0xf0) >> 4) & 0x3f];
	outpos++;
	if (outpos < outbuflen)
	    outbuf[outpos] = (state->inpos % 3 > 1) 
		? enctab[((state->grp[1] &0x0f) << 2) & 0x3f]
		: '=';
	outpos++;
	if (outpos < outbuflen)
	    outbuf[outpos] = '=';
	outpos++;
    }

    return outpos;
}

/* Prints base64 data to the given file, followed by a '.' */
static void
base64_print(file, buffer)
    FILE *file;
    gss_buffer_t buffer;
{
    const char *buf = (const char *)buffer->value;
    int buflen = buffer->length;;
    base64_enc_state_t state;
    char out[5];
    int outlen;

    /* Encode using triples of input */
    base64_encode_init(&state);
    while (buflen) {
	int bufstep = buflen > 3 ? 3 : buflen;
	outlen = base64_encode_sub(&state, buf, bufstep,
		out, sizeof out);
	assert(outlen < sizeof out);
	out[outlen] = '\0';
	fputs(out, file);
	buflen -= bufstep;
	buf += bufstep;
    }
    outlen = base64_encode_fini(&state, buf, sizeof buf);
    out[outlen] = '\0';
    fputs(out, file);

    fputs(".\n", file);
}

static void
base64_decode_init(state)
    base64_dec_state_t *state;
{
    state->pad = 0;
    state->inpos = 0;
    state->n = 0;
}

static int
base64_decode_sub(state, inbuf, inbuflen, outbuf, outbuflen)
    base64_dec_state_t *state;
    const char *inbuf;
    int inbuflen;
    char *outbuf;
    int outbuflen;
{
    int inpos = 0;
    int outpos = 0;

    if (state->n || !state->pad)
	while (inpos < inbuflen) {
	    unsigned char c = (unsigned char)inbuf[inpos++];

	    /* Classify input bytes as padding, ignorable or codes */
	    if (c == '=') {
		if (state->n < 2) {
		    if (base64_debug)
			fprintf(stderr, "spurious '=' at index %d\n", inpos-1);
		    return -1;
		}
		state->pad++;
		state->grp[state->n++] = 0;
	    } else if ((c & 0x80) || dectab[(unsigned int)c] == -1) {
		if (base64_debug)
		    fprintf(stderr, "INVALID CHARACTER '%c' #%x"
		       	" at index %d of %d\n", c, c, inpos - 1, inbuflen);
		return -1;
	    } else if (dectab[(unsigned int)c] == -2) 
		continue;
	    else {
		if (state->pad) {
		    if (base64_debug)
			fprintf(stderr, "bad char '%c' #%x after padding"
			       " at index %d\n", c, c, inpos - 1);
		    return -1;
		}
		state->grp[state->n++] = dectab[(unsigned int)c];
	    }

	    /* When a group of 4 has been filled, convert to 3 output bytes */
	    if (state->n == 4) {
		if (state->pad > 2) {
		    if (base64_debug)
		       	fprintf(stderr, "too many padding =s\n");
		    return -1;	
		}
		if (outpos < outbuflen)
		    outbuf[outpos] = state->grp[0] << 2 | state->grp[1] >> 4;
		outpos++;
		if (state->pad < 2) {
		  if (outpos < outbuflen)
		    outbuf[outpos] = (state->grp[1] << 4 | state->grp[2] >> 2) 
			& 0xff;
		  outpos++;
		}
		if (state->pad < 1) {
		  if (outpos < outbuflen)
		    outbuf[outpos] = (state->grp[2] << 6 | state->grp[3]) 
			& 0xff;
		  outpos++;
		}
		state->n = 0;
		if (state->pad)
		    break;
	    }
	}

    /* Return -1 if there is non-whitespace after any padding */
    while (state->pad && inpos < inbuflen) {
	char c = inbuf[inpos++];
	if (dectab[(unsigned int)c] != -2) {
	    if (base64_debug)
		fprintf(stderr, "EXTRA CHARACTER '%c' #%x at index %d of %d\n",
		    c, c, inpos - 1, inbuflen);
	    return -1;
	}
    }

    return outpos;
}

static int
base64_decode_fini(state)
    base64_dec_state_t *state;
{

    /* Return -1 if there are undecodable characters remaining */
    if (state->n != 0) {
	if (base64_debug)
	    fprintf(stderr, "%d leftover characters\n", state->n);
	return -1;
    }

    return 0;
}

static void
base64_scan(file, buffer)
    FILE *file;
    gss_buffer_t buffer;
{
    int buflen = 8192;
    int bufpos = 0;
    int outlen;
    char *buf = malloc(buflen);
    int ch;
    char inbuf[1];
    base64_dec_state_t state;

    base64_decode_init(&state);
    while ((ch = getc(file)) != EOF && ch != '.') {
	inbuf[0] = ch;
	outlen = base64_decode_sub(&state, inbuf, sizeof inbuf,
		buf + bufpos, buflen - bufpos);
	assert(outlen >= 0);
	assert(outlen + bufpos <= buflen);
	bufpos += outlen;
    }
    outlen = base64_decode_fini(&state);
    assert(outlen == 0);
    buffer->value = buf;
    buffer->length = bufpos;
}

/*------------------------------------------------------------
 * GSS error display
 */

static void
gsserr(const char *msg, OM_uint32 major, OM_uint32 minor, gss_OID mech)
{
    OM_uint32 context, maj, min;
    gss_buffer_desc buf;

#if ERROR_DEBUG
    printf("GSS error: %s\n", msg);
    printf(" Major 0x%x:\n", major);
#else
    printf("%s: ", msg);
#endif

    context = 0;
    do {
	maj = gss_display_status(&min, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
		&context, &buf);
	if (GSS_ERROR(maj)) {
	    printf("[error while displaying: 0x%x,0x%x]\n", maj, min);
	    exit(1);
	}
#if ERROR_DEBUG
	printf("  <%.*s>\n", buf.length, buf.value);
#else
	printf("%.*s", buf.length, buf.value);
	if (context) printf("; ");
#endif
	maj = gss_release_buffer(&min, &buf);
	if (GSS_ERROR(maj))
	    printf("[error while releasing buffer: 0x%x/0x%x]\n", maj, min);
    } while (context != 0);

    if (1) {
#if ERROR_DEBUG
	printf(" Minor 0x%x:\n", minor);
#endif
	do {
	    maj = gss_display_status(&min, minor, GSS_C_MECH_CODE, mech,
		    &context, &buf);
	    if (GSS_ERROR(maj)) {
		printf("[error while displaying: 0x%x/0x%x]\n", maj, min);
		exit(1);
	    }
#if ERROR_DEBUG
	    printf("  <%.*s>\n", buf.length, buf.value);
#else
	    printf("; %.*s", buf.length, buf.value);
#endif
	    maj = gss_release_buffer(&min, &buf);
	    if (GSS_ERROR(maj))
		printf("[error while releasing buffer: 0x%x/0x%x]\n", maj, min);
	} while (context != 0);
    }
#if ERROR_DEBUG
    printf(" (end of GSS error)\n");
#else
    printf("\n");
#endif

    exit(1);
}

/*------------------------------------------------------------
 * Functionality tests
 */

static void
load_conf(const char *conffile)
{
    printf("Loading config file %s...\n", conffile);

    if (_pgss_load_config_file(conffile)) {
	fprintf(stderr, "error: %s\n", _pgss_config_last_error());
	exit(1);
    }
}

/* Dumps the internal PGSS config tables */
static void
dump_conf()
{
    struct config *cfg;
    void *context;
    gss_OID oid;
    gss_buffer_desc buf;
    OM_uint32 major, minor;
    int i;

    context = NULL;
    while ((cfg = _pgss_config_next(&context, &oid)) != NULL) {
	if (oid == GSS_C_NO_OID)
	    printf("    mech: *\n");
	else {
	    major = gss_oid_to_str(&minor, oid, &buf);
	    if (GSS_ERROR(major))
		gsserr("gss_oid_to_str", major, minor, GSS_C_NO_OID);
	    printf("    mech: %.*s\n", buf.length, buf.value);
	    major = gss_release_buffer(&minor, &buf);
	    if (GSS_ERROR(major))
		gsserr("gss_release_buffer", major, minor, GSS_C_NO_OID);
	}

	printf("    name: '%s'\n", cfg->name);
	for (i = 0; i < cfg->nparams; i++)
	    printf("        %s\n", cfg->params[i]);
	printf("\n");
    }
}

/* Calls gss_indicate_mechs() and prints the results */
static void
enum_mechs()
{
    gss_OID_set set;
    OM_uint32 major, minor, i;
    gss_buffer_desc buf;

    printf("(config before enumerating:)\n");
    dump_conf();
    printf("\n");

    printf("Enumerating available mechanisms...\n");
    major = gss_indicate_mechs(&minor, &set);
    if (GSS_ERROR(major))
	gsserr("gss_indicate_mechs", major, minor, GSS_C_NO_OID);
    printf("\n");


    printf("found %u mechanism%s:\n", set->count, set->count == 1 ? "" : "s");
    for (i = 0; i < set->count; i++) {
	major = gss_oid_to_str(&minor, set->elements + i, &buf);
	if (GSS_ERROR(major))
	    gsserr("gss_oid_to_str", major, minor, GSS_C_NO_OID);

	printf(" %3d. %.*s\n", i, buf.length, buf.value);

	major = gss_release_buffer(&minor, &buf);
	if (GSS_ERROR(major))
	    gsserr("gss_release_buffer", major, minor, GSS_C_NO_OID);
    }

    major = gss_release_oid_set(&minor, &set);
    if (GSS_ERROR(major))
	gsserr("gss_release_oid_set", major, minor, GSS_C_NO_OID);
    printf("\n");


    printf("(config after enumerating:)\n");
    dump_conf();
    printf("\n");
}

static int
bufeq(gss_buffer_t buf, const char *str)
{
    return buf->length == strlen(str) &&
	   memcmp(buf->value, str, buf->length) == 0;
}

static struct {
    const char *abbr;
    gss_OID *oidp;
} oidabbr[] = {
    { "user", &GSS_C_NT_USER_NAME },
    { "uid", &GSS_C_NT_STRING_UID_NAME },
    { "hostbased", &GSS_C_NT_HOSTBASED_SERVICE },
    { "anon", &GSS_C_NT_ANONYMOUS },
    { "export", &GSS_C_NT_EXPORT_NAME },
    { "krb5", &GSS_KRB5_NT_PRINCIPAL_NAME },
    { 0, 0 }
};

/* Imports a string of the form [:nametype_oid:]name into a GSS name.
 * If no :oid: prefix is present, then uses GSS_C_NO_OID in the call
 * to gss_import_name(). On error, calls gsserr().
 */
static void
import_name(char *arg, gss_name_t *name)
{
    gss_OID oid = GSS_C_NO_OID;
    char *n;
    gss_buffer_desc buf;
    OM_uint32 major, minor, i;

    if (!arg) {
	*name = GSS_C_NO_NAME;
	return;
    }

    if (*arg == ':') {
	n = strchr(arg + 1, ':');
	if (n) {
	    buf.value = arg + 1;
	    buf.length = n - arg - 1;
	    n++;
	    printf("importing using nametype '%.*s'\n", buf.length, buf.value);

	    for (i = 0; oidabbr[i].abbr; i++)
		if (bufeq(&buf, oidabbr[i].abbr)) {
		    oid = *oidabbr[i].oidp;
		    break;
		}
	    if (!oid) {
		major = gss_str_to_oid(&minor, &buf, &oid);
		if (GSS_ERROR(major))
		    gsserr("gss_str_to_oid", major, minor, GSS_C_NO_OID);
	    }
	} else
	    n = arg;
    } else
	n = arg;


    buf.value = n;
    buf.length = strlen(n);

    printf("importing name '%.*s'...\n", buf.length, buf.value);

    major = gss_import_name(&minor, &buf, oid, name);
    if (GSS_ERROR(major))
	gsserr("gss_import_name", major, minor, GSS_C_NO_OID);
}

static void
test_init(char *target, char *client)
{
    OM_uint32 major, minor;
    gss_name_t target_name, client_name;
    gss_cred_id_t cred;
    gss_ctx_id_t ctx;
    gss_buffer_desc out;

    import_name(target, &target_name);
    import_name(client, &client_name);

    if (client_name) {
	printf("acquiring credentials...\n");
	major = gss_acquire_cred(&minor, client_name, GSS_C_INDEFINITE,
		GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred, NULL, NULL);
	if (GSS_ERROR(major))
	    gsserr("gss_acquire_cred", major, minor, GSS_C_NO_OID);
    } else
	cred = GSS_C_NO_CREDENTIAL;


    for (;;) {
	ctx = GSS_C_NO_CONTEXT;
	major = gss_init_sec_context(&minor, cred, &ctx, target_name, 
		GSS_C_NO_OID, 0, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
		GSS_C_NO_BUFFER, NULL, &out, NULL, NULL);

	if (out.length) {
	    printf("\noutput token: ");
	    base64_print(stdout, &out);
	    printf("\n");
	}
	if (GSS_ERROR(major) == GSS_S_COMPLETE)
	    break;
	if (GSS_ERROR(major) != GSS_S_CONTINUE_NEEDED)
	    gsserr("gss_init_sec_context", major, minor, GSS_C_NO_OID);
    }
    printf("init completed.\n");

    if (GSS_ERROR(major = gss_release_buffer(&minor, &out)))
	gsserr("gss_release_buffer", major, minor, GSS_C_NO_OID);
    if (GSS_ERROR(major = gss_release_cred(&minor, &cred)))
	gsserr("gss_release_cred", major, minor, GSS_C_NO_OID);
    if (GSS_ERROR(major = gss_delete_sec_context(&minor, &ctx, 0)))
	gsserr("gss_delete_sec_context", major, minor, GSS_C_NO_OID);
}

static void
test_accept(char *target)
{
    OM_uint32 major, minor;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t name = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    gss_buffer_desc input, output;
    OM_uint32 flags, time;
    gss_cred_id_t deleg = GSS_C_NO_CREDENTIAL;
    gss_name_t target_name;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;

    import_name(target, &target_name);

    if (target_name) {
	printf("acquiring credentials...\n");
	major = gss_acquire_cred(&minor, target_name, GSS_C_INDEFINITE,
		GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred, NULL, NULL);
	if (GSS_ERROR(major))
	    gsserr("gss_acquire_cred", major, minor, GSS_C_NO_OID);
    } else
	cred = GSS_C_NO_CREDENTIAL;

    for (;;) {
	printf("input token? "); fflush(stdout);
	base64_scan(stdin, &input);

	major = gss_accept_sec_context(&minor, &ctx, cred,
		&input, GSS_C_NO_CHANNEL_BINDINGS,
		&name, &mech, &output, &flags, &time, &deleg);

	if (output.length) {
	    printf("\noutput token: ");
	    base64_print(stdout, &output);
	    printf("\n");
	}
	if (GSS_ERROR(major) == GSS_S_COMPLETE)
	    break;
	if (GSS_ERROR(major) != GSS_S_CONTINUE_NEEDED)
	    gsserr("gss_accept_sec_context", major, minor, GSS_C_NO_OID);
    }
    printf("accept completed.\n");

    if (GSS_ERROR(major = gss_release_cred(&minor, &deleg)))
	gsserr("gss_release_cred(&deleg)", major, minor, GSS_C_NO_OID);
    if (GSS_ERROR(major = gss_release_cred(&minor, &cred)))
	gsserr("gss_release_cred(&cred)", major, minor, GSS_C_NO_OID);
    if (GSS_ERROR(major = gss_delete_sec_context(&minor, &ctx, 0)))
	gsserr("gss_delete_sec_context", major, minor, GSS_C_NO_OID);
}

/*------------------------------------------------------------
 * Driver
 */

static void
usage(const char *argv0)
{
    fprintf(stderr, 
	    "usage: %s [-f config] -l\n"
	    "       %s [-f config] -i [:nt:]target [[:nt:]cred]\n"
	    "       %s [-f config] -a [[:nt:]cred]\n",
	    argv0, argv0, argv0);
    exit(1);
}

int
main(int argc, char **argv)
{
    const char *argv0 = argv[0];
    int optind = 1;

    if (optind >= argc) usage(argv0);
    if (strcmp(argv[optind], "-f") == 0) {
	if (optind + 1 >= argc) usage(argv0); 
	load_conf(argv[optind + 1]);
	optind += 2;
    }

    if (strcmp(argv[optind], "-l") == 0) {
	/* -l: list the mechanisms loaded */
	enum_mechs();
	optind++;
    } else if (strcmp(argv[optind], "-i") == 0) {
	/* -i: initiator test */
	if (optind + 1 >= argc) usage(argv0);
	test_init(argv[optind + 1], optind + 2 < argc ? argv[optind+2] : NULL);
	optind += optind + 2 < argc ? 3 : 2;
    } else if (strcmp(argv[optind], "-a") == 0) {
	/* -a: acceptor test */
	if (optind >= argc) usage(argv0);
	test_accept(optind + 1 < argc ? argv[optind + 1] : NULL);
	optind += optind + 1 < argc ? 1 : 2;
    } else
	usage(argv0);

    if (optind != argc)
	usage(argv0);
    exit(0);
}
