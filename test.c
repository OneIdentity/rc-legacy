#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <gssapi.h>
#include <pgssapi.h>
#include "pgss-dispatch.h"
#include "pgss-config.h"

int
main(int argc, char **argv)
{
    struct config *cfg;
    void *context;
    gss_OID oid;

    if (_pgss_load_config_file(argv[1])) {
	fprintf(stderr, "%s\n", _pgss_config_last_error());
	exit(1);
    }

    context = NULL;
    while ((cfg = _pgss_config_iterate(&context, &oid)) != NULL) {
    	gss_buffer_desc buf;
	OM_uint32 major, minor;
	int i;

	major = gss_oid_to_str(&minor, oid, &buf);
	if (GSS_ERROR(major)) {
	    fprintf(stderr, "gss_oid_to_str\n");
	    exit(1);
	}
	printf("%.*s\n\t%s\n", buf.length, buf.value, cfg->name);
	for (i = 0; i < cfg->nparams; i++)
	    printf("\t%s\n", cfg->params[i]);
	printf("\n");

	(void)gss_release_buffer(&minor, &buf);
    }

    return 0;
}
