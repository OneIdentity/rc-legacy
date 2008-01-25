/* (c) 2005 Quest Software, Inc. All rights reserved. */
/* David Leonard */

/*
 * GSSAPI test client.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <gssapi.h>
#include <gssapi_krb5.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "gss-common.h"
#include "authtest.h"

static char client_message[] = "I am the client";

int
main(int argc, char **argv)
{
    struct res res;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctxt = GSS_C_NO_CONTEXT;
    gss_name_t target_name;
    gss_OID target_name_type = GSS_C_NO_OID;
    OM_uint32 req_flags, ret_flags;
    gss_buffer_desc input, output, buf;
    int ch, error, conf_state;
    int conf_req = 0;
    gss_qop_t qop_state;

    req_flags = 0;
    authtest_init();

    error = 0;
    while ((ch = getopt(argc, argv, "cf:nt:")) != -1)
	switch (ch) {
	    case 'f':
		req_flags |= names2flags(optarg); break;
	    case 'c':
		conf_req = 1; break;	/* need conf in wrap() */
	    case 'n':
		base64_whitespace = 0; break;
	    case 't':
		if (strcmp(optarg, "none") == 0)
		    target_name_type = GSS_C_NO_OID;
		else if (strcmp(optarg, "hostbased") == 0)
		    target_name_type = GSS_C_NT_HOSTBASED_SERVICE;
		else if (strcmp(optarg, "krb5") == 0)
		    target_name_type = GSS_KRB5_NT_PRINCIPAL_NAME;
		else {
		    fprintf(stderr, "unknown type: %s\n", optarg);
		    error = 1;
		}
		break;
	    default:
		error = 1;
	}

    if (error || optind + 1 != argc) {
	fprintf(stderr, "usage: %s [-f flags] [-c] [-t type] target\n", 
		argv[0]);
	fprintf(stderr, "\tflags: deleg,mutual,replay,sequence,"
			         "conf,integ,anon\n");
	fprintf(stderr, "\ttypes: none hostbased krb5\n");
	exit(1);
    }

    /* Convert the argument to a GSS name */
    buf.value = argv[optind];
    buf.length = strlen(argv[optind]);
    res.major = gss_import_name(&res.minor, &buf, target_name_type,
	    &target_name);
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_import_name");
    optind++;

    /* Display the name used */
    buf.length = 0;
    buf.value = 0;
    res.major = gss_display_name(&res.minor, target_name, &buf, &target_name_type);
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_display_name");
    debug("target_name = %.*s", buf.length, (char *)buf.value);
    (void)gss_release_buffer(&res.minor, &buf);

    debug("target_name type: %s", oid2str(target_name_type));

    /* Display the request flags we'll be using */
    debug("request flags = %s", flags2str(req_flags)); 

    setbuf(stdout, NULL);

    /* Perform the GSSAPI token loop as initiator */
    input.length = 0;
    input.value = 0;
    output.value = 0;
    output.length = 0;
    do {

	res.major = gss_init_sec_context(&res.minor,
	    cred, 			/* initiator_cred_handle */
	    &ctxt, 			/* context_handle */
	    target_name,		/* target_name */
	    GSS_C_NO_OID,		/* mech_type */
	    req_flags,			/* req_flags */
	    GSS_C_INDEFINITE,		/* time_req */
	    GSS_C_NO_CHANNEL_BINDINGS,	/* channel_bindings */
	    input.value ? &input : NULL,/* input_token */
	    NULL,			/* actual_mech_type */
	    &output,			/* output_token */
	    &ret_flags,			/* ret_flags */
	    NULL);			/* time_rec */

	if (input.value) {
	    free(input.value);
	    input.value = NULL;
	    input.length = 0;
	}

	/* Print output token if there is one */
	if (output.value)
	    writeb64_and_release(&output);

	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_init_sec_context");

	/* Wait for an input token if one is needed */
	if (res.major & GSS_S_CONTINUE_NEEDED)
	    readb64(&input);

    } while (res.major & GSS_S_CONTINUE_NEEDED);

    debug("gss_init_sec_context completed %d", res.major);
    debug("result flags = %s", flags2str(ret_flags));

    /* Wait for and decode the server message */
    readb64(&input);
    res.major = gss_unwrap(&res.minor,
	    ctxt,			/* context_handle */
	    &input,			/* input_message_buffer */
	    &output,			/* output_message_buffer */
	    &conf_state,		/* conf_state */
	    &qop_state);		/* qop_state */
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_unwrap");

    fprintf(stderr, "Message from server: \"%.*s\"\n", 
	    output.length, (char *)output.value);
    fprintf(stderr, "  conf_state = %d, qop_state = %d\n", 
	    conf_state, qop_state);

    free(input.value);
    input.value = 0;
    input.length = 0;

    res.major = gss_release_buffer(&res.minor, &output);
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_release_buffer");
    output.value = 0;
    output.length = 0;

    /* Encode and send the client message */
    input.value = client_message;
    input.length = strlen(client_message);
    fprintf(stderr, "Message to server: \"%.*s\"\n", 
	    input.length, (char *)input.value);
    res.major = gss_wrap(&res.minor,
	    ctxt,			/* context_handle */
	    conf_req,			/* conf_req_flag */
	    GSS_C_QOP_DEFAULT,		/* qop_req */
	    &input,			/* input_message_buffer */
	    &conf_state,		/* conf_state */
	    &output);			/* output_message_buffer */
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_wrap");
    if (output.value) 
	writeb64_and_release(&output);
    input.value = 0;
    input.length = 0;

    exit(0);
}
