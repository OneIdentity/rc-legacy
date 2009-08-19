/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Windows Security Service Provider Interface (SSPI) server sample.
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

static const char server_msg[] = "I am the SSPI server";

static void
server(char *package, int req_flags, int conf_req)
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
    SECURITY_STATUS complete_status;
    int initial;
    ULONG qop;
    int msg_len;
    char *msg;

    /* Acquire credentials */
    status = sspi->AcquireCredentialsHandle(NULL, package,
	    SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL,
	    &credentials, &expiry);
    if (status != SEC_E_OK) {
	errmsg("AcquireCredentialsHandle", status);
	exit(1);
    }

    /* Display whose credentials we have */
    print_cred_attrs(&credentials);

    input = NULL;
    initial = 1;
    do {
	/* Receive an input token */
	inputdesc.ulVersion = SECBUFFER_VERSION;
	inputdesc.cBuffers = 1;
	inputdesc.pBuffers = inbuffers;
	input = &inputdesc;
	user_input_token(&inbuffers[0]);

        /* Set up a buffer structure to hold the output token */
        output.ulVersion = SECBUFFER_VERSION;
        output.cBuffers = 1;
        output.pBuffers = buffers;
        buffers[0].BufferType = SECBUFFER_TOKEN;
        buffers[0].cbBuffer = 0;
        buffers[0].pvBuffer = NULL;

	status = sspi->AcceptSecurityContext(
                &credentials,			/* phCredential */
                initial ? NULL : &context,	/* phContext */
                input,				/* pInput */
                ISC_REQ_ALLOCATE_MEMORY |	/* fContextReq */
		req_flags,
                SECURITY_NATIVE_DREP,		/* TargetDataRep */
                initial ? &context : NULL,	/* phNewContext */
                &output,			/* pOutput */
                &attr,				/* pContextAttr */
                &expiry);			/* ptsExpiry */
	initial = 0;

	user_input_free_token(&inbuffers[0]);

        switch (status) {
            case SEC_E_OK:			/* Normal success */
            case SEC_I_COMPLETE_NEEDED:		/* Unusual success */
                break;
            case SEC_I_CONTINUE_NEEDED:		/* Normal continuation */
            case SEC_I_COMPLETE_AND_CONTINUE:	/* Unusual continuation */
                break;
            default:
                errmsg("AcceptSecurityContext", status);
                exit(1);
        }

	if (status == SEC_I_COMPLETE_AND_CONTINUE ||
	    status == SEC_I_COMPLETE_NEEDED) {
		complete_status = sspi->CompleteAuthToken(&context, &output);
		if (complete_status != SEC_E_OK)
		    errmsg("CompleteAuthToken", complete_status);
	}

        if (output.cBuffers && buffers[0].pvBuffer) {
            user_output_token(&output);
	    free_status = sspi->FreeContextBuffer(buffers[0].pvBuffer);
	    if (free_status != SEC_E_OK)
		errmsg("FreeContextBuffer", free_status);
        }

    } while (status == SEC_I_CONTINUE_NEEDED);

    printf("AcceptSecurityContext() completed\n");

    /* Display context attributes */

    printf("Expiry: %s\n", TimeStamp_to_string(&expiry));
    printf("Flags: <%s>\n", flags2str(attr, FLAGS_KIND_RET));
    print_context_attrs(&context);

    /* Encrypt and send the server message */

    printf("Message to client: \"%s\"\n", server_msg);

    output_encrypted(&context, server_msg, strlen(server_msg), conf_req);

    /* Wait for and decode the client message */

    if (!input_encrypted(&context, &msg, &msg_len, &qop))
	exit(1);

    fprintf(stderr, "input qop = 0x%lx\n", qop);
    fprintf(stderr, "Message from server: \"%.*s\"\n",  msg_len, msg);

    input_encrypted_free(msg);


    /* Delete the security context */

    status = sspi->DeleteSecurityContext(&context);
    if (status != SEC_E_OK) {
	errmsg("DeleteSecurityContext", status);
	exit(1);
    }

    /* Delete the credentials */

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
    int lflag = 0;
    ULONG req_flags = 0;
    int conf_req = 0;

    atexit(user_output_flush);

    /* Parse command line arguments */
    while ((ch = getopt(argc, argv, "cf:lp:")) != -1) 
	switch (ch) {
	case 'c':
	    conf_req = 1;	/* only affects EncryptMessage() */
	    break;
	case 'f':
	    req_flags |= names2flags(optarg, FLAGS_KIND_REQ);
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
    if (argc != optind)
	error = 1;

    /* Display usage if there was an error in the arguments */
    if (error) {
	fprintf(stderr, "usage: %s -l\n"
		        "       %s [-c] [-p pkg]\n"
			"Available flags: %s\n",
			argv[0], argv[0], flags_all(FLAGS_KIND_REQ));
	exit(1);
    }

    sspi = InitSecurityInterface();
    if (!sspi) {
        errmsg("InitSecirtyInterface", GetLastError());
	exit(1);
    }

    if (lflag)
	list_pkgs();
    else
	server(package, req_flags, conf_req);

    exit(0);
}
