#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "gssapi.h"
#include "pgssapi.h"
#include "pgss-dispatch.h"
#include "pgss-config.h"

/* print a gss error and exit */
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

    if (mech) {
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

static void
load_conf(const char *conffile)
{
    struct config *cfg;
    void *context;
    gss_OID oid;

    printf("Loading config file %s...\n", conffile);

    if (_pgss_load_config_file(conffile)) {
	fprintf(stderr, "error: %s\n", _pgss_config_last_error());
	exit(1);
    }

    context = NULL;
    while ((cfg = _pgss_config_next(&context, &oid)) != NULL) {
    	gss_buffer_desc buf;
	OM_uint32 major, minor;
	int i;

	if (oid == GSS_C_NO_OID)
	    printf("*\n");
	else {
	    major = gss_oid_to_str(&minor, oid, &buf);
	    if (GSS_ERROR(major))
		gsserr("gss_oid_to_str", major, minor, GSS_C_NO_OID);
	    printf("%.*s\n", buf.length, buf.value);
	}

	printf("    name: '%s'\n", cfg->name);
	for (i = 0; i < cfg->nparams; i++)
	    printf("        %s\n", cfg->params[i]);
	printf("\n");

	major = gss_release_buffer(&minor, &buf);
	if (GSS_ERROR(major))
	    gsserr("gss_release_buffer", major, minor, GSS_C_NO_OID);
    }
}

static void
enum_mechs()
{
    gss_OID_set set;
    OM_uint32 major, minor, i;
    gss_buffer_desc buf;

    printf("Enumerating available mechanisms...\n");

    major = gss_indicate_mechs(&minor, &set);
    if (GSS_ERROR(major))
	gsserr("gss_indicate_mechs", major, minor, GSS_C_NO_OID);

    printf("found %u mechanism%s\n", set->count, set->count == 1 ? "" : "s");

    for (i = 0; i < set->count; i++) {
	major = gss_oid_to_str(&minor, set->elements + i, &buf);
	if (GSS_ERROR(major))
	    gsserr("gss_oid_to_str", major, minor, GSS_C_NO_OID);

	printf("  <%.*s>\n", buf.length, buf.value);

	major = gss_release_buffer(&minor, &buf);
	if (GSS_ERROR(major))
	    gsserr("gss_release_buffer", major, minor, GSS_C_NO_OID);
    }

    major = gss_release_oid_set(&minor, &set);
    if (GSS_ERROR(major))
	gsserr("gss_release_oid_set", major, minor, GSS_C_NO_OID);
}

static void
print_binary(gss_buffer_t buf)
{
    OM_uint32 i;

    if (!buf) {
	printf("(null)\n");
	return;
    }

    putchar('"');
    for (i = 0; i < buf->length; i++) {
	unsigned char ch = ((unsigned char *)buf->value)[i];

	if (ch == '\\' || ch == '\"')
	    printf("\\%c", ch);
	else if (ch == '\0')
	    printf("\\0", ch);
	else if (ch == '\n')
	    printf("\\n", ch);
	else if (ch >= ' ' && ch <= '~')
	    putchar(ch);
	else
	    printf("\\x%02x", ch);
    }
    printf("\"\n");
}

static int
scan_hex(char *s, unsigned char *v)
{
    int i;
    unsigned char result = 0;
    char c;

    for (i = 0; i < 2; i++) {
	c = s[i];
	result <<= 4;
	if (c >= '0' && c <= '9')
	    result = result | (c - '0');
	else if (c >= 'a' && c <= 'f')
	    result = result | (c - 'a' + 10);
	else if (c >= 'A' && c <= 'F')
	    result = result | (c - 'A' + 10);
	else
	    return -1;
    }
    *v = result;
    return 0;
}


/* Reduces in-place a string to its binary form, and sets buffer to span it */
static int
scan_binary(char *s, gss_buffer_t buf)
{
    char *start, *t;

    while (*s && *s != '"')
	s++;
    if (*s != '"')
	return -1;
    s++;
    start = s;
    t = start;
    while (*s && *s != '"') {
	if (*s != '\\') {
	    *t++ = *s++;
	    continue;
	}
	s++;
	switch (*s) {
	case 'x':
	    if (scan_hex(s + 1, (unsigned char *)t) == -1)
		return -1;
	    s++;
	    break;
	case 'n': *t = '\n'; break;
	case '0': *t = '\0'; break;
	default:  *t = *s;
	}
	t++; s++;
    }
    buf->value = start;
    buf->length = t - start;
}

/* Imports a string of the form [:nametype_oid:]name into a GSS name */
static void
import_name(char *arg, gss_name_t *name)
{
    gss_OID oid = GSS_C_NO_OID;
    char *n;
    gss_buffer_desc buf;
    OM_uint32 major, minor;

    if (!arg) {
	*name = GSS_C_NO_NAME;
	return;
    }

    if (*arg == ':') {
	n = strchr(arg + 1, ':');
	if (n) {
	    arg = n + 1;
	    buf.value = arg + 1;
	    buf.length = n - arg - 1;
	    major = gss_str_to_oid(&minor, &buf, &oid);
	    if (GSS_ERROR(major))
		gsserr("gss_str_to_oid", major, minor, GSS_C_NO_OID);
	} else
	    n = arg;
    } else
	n = arg;

    printf("importing name '%s'...\n", n);

    buf.value = n;
    buf.length = strlen(n);

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


    ctx = GSS_C_NO_CONTEXT;
    major = gss_init_sec_context(&minor, cred, &ctx, target_name, 
	    GSS_C_NO_OID, 0, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
	    GSS_C_NO_BUFFER, NULL, &out, NULL, NULL);
    if (GSS_ERROR(major))
	gsserr("gss_init_sec_context", major, minor, GSS_C_NO_OID);

    printf("first token: ");
    print_binary(&out);
}

static void
test_accept(char *target)
{
    fprintf(stderr, "test_accept: TBD\n"); exit(1);
}

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
	if (optind + 1 >= argc) usage(argv0);
	test_accept(optind + 1 < argc ? argv[optind + 1] : NULL);
	optind += optind + 1 < argc ? 1 : 2;
    } else
	usage(argv0);

    if (optind != argc)
	usage(argv0);
    exit(0);
}
