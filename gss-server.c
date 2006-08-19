/* (c) 2005 Quest Software, Inc. All rights reserved. */
/* David Leonard */

/*
 * GSSAPI test server. 
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <gssapi.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"
#include "gss-common.h"
#include "authtest.h"

static char server_message[] = "I am the server";

int
main(int argc, char **argv)
{
    struct res res;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t deleg_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctxt = GSS_C_NO_CONTEXT;
    gss_name_t source_name = GSS_C_NO_NAME;
    OM_uint32 ret_flags;
    gss_buffer_desc input, output, buf;
    int conf_state, conf_req = 0;
    gss_qop_t qop_state;
    int ch, error;
    const char *service = NULL;
    int bug6793 = 0;

    authtest_init();

    error = 0;
    while ((ch = getopt(argc, argv, "cs:b:")) != -1)
	switch (ch) {
	    case 'c':
		conf_req = 1; break; /* enable conf in wrap() */
	    case 's':
		service = optarg; break;
	    case 'b':
		switch (atoi(optarg)) {
		    case 6793: bug6793 = 1; break;
		    default:
			fprintf(stderr, "unknown bug -b %s\n", optarg);
			error = 1;
		}
		break;
	    default:
		error = 1;
	}

    if (error || optind != argc) {
	fprintf(stderr, "usage: %s [-c] [-s service] [-b bug]\n", argv[0]);
        exit(1);
    }

    if (service) {
	gss_buffer_desc service_buf;
	gss_name_t service_name;

	service_buf.value = (void *)service;
	service_buf.length = strlen(service);
	res.major = gss_import_name(&res.minor, &service_buf, 
		GSS_C_NT_HOSTBASED_SERVICE, &service_name);
	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_import_name");
	res.major = gss_acquire_cred(&res.minor, service_name,
	    GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, 
	    &cred, NULL, NULL);
	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_acquire_cred");
        (void)gss_release_name(&res.minor, &service_name);

	res.major = gss_inquire_cred(&res.minor, cred, &service_name,
		NULL, NULL, NULL);
	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_inquire_cred");
	res.major = gss_display_name(&res.minor, service_name, &service_buf,
		NULL);
	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_display_name");
	debug("acquired creds for %.*s",
		service_buf.length, (char *)service_buf.value);
	(void)gss_release_buffer(&res.minor, &service_buf);
	(void)gss_release_name(&res.minor, &service_name);
    }

    /* Perform the GSSAPI token loop as acceptor */
    output.value = 0;
    output.length = 0;

    setbuf(stdout, NULL);

    do {
	readb64(&input);
	res.major = gss_accept_sec_context(&res.minor,
	    &ctxt, 			/* context_handle */
	    cred, 			/* acceptor_cred_handle */
	    &input,			/* input_token_buffer */
	    GSS_C_NO_CHANNEL_BINDINGS,	/* input_chan_bindings */
	    bug6793 ? NULL : &source_name, /* src_name */
	    NULL,			/* mech_type */
	    &output,			/* output_token */
	    &ret_flags,			/* ret_flags */
	    NULL,			/* time_rec */
	    &deleg_cred);		/* delegated_cred_handle */
	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_accept_sec_context");
	free(input.value);

	/* Print output token if there is one */
	if (output.value)
	    writeb64_and_release(&output);

    } while (res.major & GSS_S_CONTINUE_NEEDED);

    debug("gss_accept_sec_context completed %d", res.major);
    debug("result flags = %s", flags2str(ret_flags)); 

    /* Display the name used */
    if (source_name != GSS_C_NO_NAME) {
        buf.length = 0;
        buf.value = 0;
        res.major = gss_display_name(&res.minor, source_name, &buf, NULL);
        if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_display_name");
        debug("source = %.*s", buf.length, (char *)buf.value);
        (void)gss_release_buffer(&res.minor, &buf);
    }

    /* Display any credentials delegated */
    if (deleg_cred == GSS_C_NO_CREDENTIAL) {
	debug("no delegated credentials");
    } else {
	gss_name_t name = GSS_C_NO_NAME;
	OM_uint32 lifetime;
	gss_cred_usage_t usage;

	debug("credentials were delegated:");
	res.major = gss_inquire_cred(&res.minor, deleg_cred, &name,
		&lifetime, &usage, NULL);
	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_inquire_cred");

	res.major = gss_display_name(&res.minor, name, &buf, NULL);
	if (GSS_ERROR(res.major))
	    gssdie(1, &res, "gss_display_name");
	debug("    name = %.*s", buf.length, (char *)buf.value);
	(void)gss_release_buffer(&res.minor, &buf);
	(void)gss_release_name(&res.minor, &name);

	debug("    usage = %s",
		usage == GSS_C_INITIATE ? "initiate" :
		usage == GSS_C_ACCEPT   ? "accept" :
		usage == GSS_C_BOTH     ? "initiate+accept" :
					  "unknown");

	debug("    lifetime = %u", lifetime);
    }

    /* Encode and send the server message */
    input.value = server_message;
    input.length = strlen(server_message);
    fprintf(stderr, "Message to client: \"%.*s\"\n", 
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

    /* Wait for and decode the client message */
    readb64(&input);
    res.major = gss_unwrap(&res.minor,
	    ctxt,			/* context_handle */
	    &input,			/* input_message_buffer */
	    &output,			/* output_message_buffer */
	    &conf_state,		/* conf_state */
	    &qop_state);		/* qop_state */
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_unwrap");

    fprintf(stderr, "Message from client: \"%.*s\"\n", 
	    output.length, (char *)output.value);
    fprintf(stderr, "  conf_state = %d, qop_state = %d\n", 
	    conf_state, qop_state);

    free(input.value);
    input.value = 0;
    input.length = 0;

    res.major = gss_release_buffer(&res.minor, &output);
    if (GSS_ERROR(res.major))
	gssdie(1, &res, "gss_release_buffer");

    exit(0);

}
