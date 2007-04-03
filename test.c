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

    printf("GSS error: %s\n", msg);
    printf(" Major 0x%x:\n", major);
    context = 0;
    do {
	maj = gss_display_status(&min, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
		&context, &buf);
	if (GSS_ERROR(maj)) {
	    printf("[error while displaying: major=0x%x minor=0x%x]\n",
		    maj, min);
	    exit(1);
	}
	printf("  <%.*s>\n", buf.length, buf.value);
	maj = gss_release_buffer(&min, &buf);
	if (GSS_ERROR(maj))
	    printf("[error while releasing buffer: major=0x%x minor=0x%x]\n",
		    maj, min);
    } while (context != 0);

    printf(" Minor 0x%x:\n", minor);
    do {
	maj = gss_display_status(&min, minor, GSS_C_MECH_CODE, mech,
		&context, &buf);
	if (GSS_ERROR(maj)) {
	    printf("[error while displaying: major=0x%x minor=0x%x]\n",
		    maj, min);
	    exit(1);
	}
	printf("  <%.*s>\n", buf.length, buf.value);
	maj = gss_release_buffer(&min, &buf);
	if (GSS_ERROR(maj))
	    printf("[error while releasing buffer: major=0x%x minor=0x%x]\n",
		    maj, min);
    } while (context != 0);

    printf(" (end of GSS error)\n");

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

	major = gss_oid_to_str(&minor, oid, &buf);
	if (GSS_ERROR(major))
	    gsserr("gss_oid_to_str", major, minor, GSS_C_NO_OID);
	printf("%.*s\n\t%s\n", buf.length, buf.value, cfg->name);
	for (i = 0; i < cfg->nparams; i++)
	    printf("\t%s\n", cfg->params[i]);
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

int
main(int argc, char **argv)
{

    if (argc < 2) {
	fprintf(stderr, "usage: %s config\n", argv[0]);
	exit(1);
    }

    load_conf(argv[1]);
    enum_mechs();

    exit(0);
}
