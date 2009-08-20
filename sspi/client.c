/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Windows Security Service Provider Interface (SSPI) client sample.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include "wsspi.h"
#include "getopt.h"
#include "errmsg.h"
#include "userio.h"
#include "flags.h"
#include "common.h"
#include "wrap.h"
#include "version.h"

static const char client_msg[] = "I am the SSPI client";

static void
client(char *target, char *package, char *principal, ULONG req_flags, int conf_req)
{
    CredHandle credentials;
    TimeStamp expiry;
    CtxtHandle context;
    SecBufferDesc output;
    SecBufferDesc *input, inputdesc;
    SecBuffer buffers[3];
    SecBuffer inbuffers[2];
    ULONG attr = 0;
    SECURITY_STATUS status;
    SECURITY_STATUS free_status;
    int initial;
    ULONG qop;
    char *msg;
    int msg_len;

    /* Acquire credentials */
    printf("Acquiring outbound credentials for %s\n", principal);
    status = sspi->AcquireCredentialsHandle(null_principal(principal),
	package, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL,
	&credentials, &expiry);
    if (status != SEC_E_OK) {
	errmsg("AcquireCredentialsHandle", status);
	exit(1);
    }

    /* Display whose credentials we got */
    print_cred_attrs(&credentials);

    printf("Initializing context for %s\n", target);

    input = NULL;
    initial = 1;
    do {
        /* Set up a buffer structure to receive the output token */
        output.ulVersion = SECBUFFER_VERSION;
        output.cBuffers = 1;
        output.pBuffers = buffers;
        buffers[0].BufferType = SECBUFFER_TOKEN;
        buffers[0].cbBuffer = 0;
        buffers[0].pvBuffer = NULL;

	attr = 0;
        status = sspi->InitializeSecurityContext(
                &credentials,			/* phCredential */
                initial ? NULL : &context,	/* phContext */
                null_principal(target),		/* pszTargetName */
                ISC_REQ_ALLOCATE_MEMORY |	/* fContextReq */
		req_flags,
                0,				/* Reserved1 */
                SECURITY_NATIVE_DREP,		/* TargetDataRep */
                input,				/* pInput */
                0,				/* Reserved2 */
                initial ? &context : NULL,	/* phNewContext */
                &output,			/* pOutput */
                &attr,				/* pContextAttr */
                &expiry);			/* ptsExpiry */
	initial = 0;

        if (input) {
	    user_input_free_token(&inbuffers[0]);
            input = NULL;
        }

        if (output.cBuffers && buffers[0].pvBuffer) {
            user_output_token(&output);
	    free_status = sspi->FreeContextBuffer(buffers[0].pvBuffer);
	    if (free_status != SEC_E_OK)
		errmsg("FreeContextBuffer", free_status);
        }

        switch (status) {
            case SEC_E_OK:			/* Normal success */
            case SEC_I_CONTINUE_NEEDED:		/* Normal continuation */
                break;
            default:
                errmsg("InitializeSecurityContext", status);
                exit(1);
        }

	if (status == SEC_I_CONTINUE_NEEDED) {
	    inputdesc.ulVersion = SECBUFFER_VERSION;
	    inputdesc.cBuffers = 1;
	    inputdesc.pBuffers = inbuffers;
	    input = &inputdesc;
	    user_input_token(&inbuffers[0]);
	}

    } while (status == SEC_I_CONTINUE_NEEDED);

    printf("InitializeSecurityContext() completed\n");


    /* Display context attributes */

    printf("Expiry: %s\n", TimeStamp_to_string(&expiry));
    printf("Flags: <%s>\n", flags2str(attr, FLAGS_KIND_RET));

    print_context_attrs(&context);

    /* Wait for and decode the server message */

    if (!wrap_recv(&context, &msg, &msg_len, &qop))
	exit(1);

    fprintf(stderr, "input qop = 0x%lx\n", qop);
    fprintf(stderr, "Message from server: \"%.*s\"\n", msg_len, msg);

    wrap_recv_free(msg);


    /* Encrypt and send the client message */

    printf("Message to server: \"%s\"\n", client_msg);

    if (!wrap_send(&context, client_msg, strlen(client_msg), conf_req))
	exit(1);

    /* Delete the security context */

    status = sspi->DeleteSecurityContext(&context);
    if (status != SEC_E_OK) {
	errmsg("DeleteSecurityContext", status);
	exit(1);
    }

    status = sspi->FreeCredentialsHandle(&credentials);
    if (status != SEC_E_OK) {
	errmsg("FreeCredentialsHandle", status);
	exit(1);
    }

}

int
main(int argc, char **argv)
{
    int ch;
    int error = 0;
    char *package = "Negotiate";
    char *target = "NULL";
    char *principal = "NULL";
    int lflag = 0;
    ULONG req_flags = 0;
    int conf_req = 0;

    atexit(user_output_flush);

    /* Parse command line arguments */
    while ((ch = getopt(argc, argv, "cf:lp:")) != -1) 
	switch (ch) {
 	case 'f':
	    req_flags |= names2flags(optarg, FLAGS_KIND_REQ);
	    break;
	case 'c':
	    conf_req = 1;	/* only affects EncryptMessage() */
	    break;
	case 'l':
	    lflag = 1;
	    break;
	case 'p':
	    package = optarg;
	    break;
	default:
	    error = 1;
	}

    if (optind < argc)
        target = argv[optind++];
    if (optind < argc)
        principal = argv[optind++];

    if (optind < argc)
	error = 1;

    /* Display usage if there was an error in the arguments */
    if (error) {
	fprintf(stderr, "usage: %s -l\n"
		        "       %s [-c] [-f flags] [-p pkg] "
		                "[target [initiator]]\n"
			"Available flags: %s\n"
			"Version %s\n",
			argv[0], argv[0], 
			flags_all(FLAGS_KIND_REQ),
			version);
	exit(1);
    }

    sspi = InitSecurityInterface();
    if (!sspi) {
        errmsg("InitSecirtyInterface", GetLastError());
	exit(1);
    }

    if (lflag)
	list_pkgs();
    else {
	client(target, package, principal, req_flags, conf_req);
    }

    exit(0);
}
