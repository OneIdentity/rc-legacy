/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Companion program to gss-client/gss-server, but using the Windows SSPI interface.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include "wsspi.h"
#include "getopt.h"
#include "errmsg.h"
#include "userio.h"
#include "flags.h"
#include "common.h"

static const char client_msg[] = "I am the SSPI client";

static void
client(char *target, char *package, ULONG req_flags, int conf_req)
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
    int msg_len;
    SecPkgContext_Sizes sizes;

    /* Acquire credentials */
    status = AcquireCredentialsHandle(NULL, package,
	    SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL,
	    &credentials, &expiry);
    if (status != SEC_E_OK) {
	errmsg("AcquireCredentialsHandle", status);
	exit(1);
    }

    /* Display whose credentials we got */
    print_cred_attrs(&credentials);

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

        status = InitializeSecurityContext(
                &credentials,			/* phCredential */
                initial ? NULL : &context,	/* phContext */
                target,				/* pszTargetName */
		req_flags |
                ISC_REQ_ALLOCATE_MEMORY,	/* fContextReq */
                0,				/* Reserved1 */
                SECURITY_NATIVE_DREP,		/* TargetDataRep */
                input,				/* pInput */
                0,				/* Reserved2 */
                initial ? &context : NULL,	/* phNewContext */
                &output,			/* pOutput */
                &attr,				/* pContextAttr */
                &expiry);			/* ptsExpiry */
	initial = 0;
        switch (status) {
            case SEC_E_OK:			/* Normal success codes */
                break;
            case SEC_I_COMPLETE_AND_CONTINUE:
            case SEC_I_COMPLETE_NEEDED:
                /* CompleteAuthToken() is only to be called on the server side! */
                printf("SSPI requested that CompleteAuthToken() be called on a client?\n");
                exit(1);
            case SEC_I_CONTINUE_NEEDED:
                break;
            default:
                errmsg("InitializeSecurityContext", status);
                exit(1);
        }

        if (output.cBuffers) {
            user_output_token(&output);
	    free_status = FreeContextBuffer(buffers[0].pvBuffer);
	    if (free_status != SEC_E_OK)
		errmsg("FreeContextBuffer", free_status);
        }

        if (input) {
	    user_input_free_token(&inbuffers[0]);
            input = NULL;
        }

        if (status == SEC_I_CONTINUE_NEEDED) {
            inputdesc.ulVersion = SECBUFFER_VERSION;
            inputdesc.cBuffers = 1;
            inputdesc.pBuffers = inbuffers;
            input = &inputdesc;
        }

    } while (status == SEC_I_CONTINUE_NEEDED);

    printf("InitializeSecurityContext completed\n");


    /* Display context attributes */

    printf("Flags: <%s>\n", flags2str(attr, FLAGS_KIND_RET));
    print_context_attrs(&context);

    /* Wait for and decode the server message */

    inputdesc.ulVersion = SECBUFFER_VERSION;
    inputdesc.cBuffers = 2;
    inputdesc.pBuffers = inbuffers;
    /* Put the input token into the bottom part of the sec buffer */
    user_input_token(&inbuffers[0]);
    inbuffers[0].BufferType = SECBUFFER_STREAM;
    /* Prepare an output part */
    inbuffers[1].BufferType = SECBUFFER_DATA;
    inbuffers[1].pvBuffer = NULL;
    inbuffers[1].cbBuffer = 0;

    input = &inputdesc;
    status = DecryptMessage(&context, input, 0, &qop);
    if (status != SEC_E_OK) {
	errmsg("DecryptMessage", status);
	exit(1);
    }
    fprintf(stderr, "Message from server: \"%.*s\"\n", 
	(int)inbuffers[1].cbBuffer, (char *)inbuffers[1].pvBuffer);
    fprintf(stderr, "qop = %ld\n", qop);

    /* Release the buffer that SSPI allocated */
    if (inbuffers[1].pvBuffer) {
        free_status = FreeContextBuffer(inbuffers[1].pvBuffer);
	if (free_status != SEC_E_OK)
	    errmsg("FreeContextBuffer", free_status);
    }

    /* Encrypt and send the client message */

    msg_len = strlen(client_msg);

    /* Get header sizes for building the secbuf */
    status = QueryContextAttributes(&context, SECPKG_ATTR_SIZES, &sizes);
    if (status != SEC_E_OK) {
	errmsg("QueryContextAttributes SIZES", status); /* required */
	exit(1);
    }

    output.ulVersion = SECBUFFER_VERSION;
    output.cBuffers = 3;
    output.pBuffers = buffers;
    buffers[0].BufferType = SECBUFFER_TOKEN;
    buffers[0].cbBuffer = sizes.cbSecurityTrailer;
    buffers[0].pvBuffer = malloc(buffers[0].cbBuffer);
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].cbBuffer = msg_len;
    buffers[1].pvBuffer = malloc(msg_len);
    buffers[2].BufferType = SECBUFFER_PADDING;
    buffers[2].cbBuffer = sizes.cbBlockSize;
    buffers[2].pvBuffer = malloc(buffers[2].cbBuffer);

    /* data is encrypted in-place! */
    memcpy(buffers[1].pvBuffer, client_msg, msg_len);

    status = EncryptMessage(&context, conf_req ? 0 : SECQOP_WRAP_NO_ENCRYPT,
	    &output, 0);
    if (status != SEC_E_OK) {
	errmsg("EncryptMessage", status);
	exit(1);
    }

    printf("Encrypt buffers: %ld+%ld+%ld\n", buffers[0].cbBuffer, 
	    buffers[1].cbBuffer, buffers[2].cbBuffer);

    user_output_token(&output);

    /* Release the secbuf we allocated */
    free(buffers[0].pvBuffer);
    free(buffers[1].pvBuffer);
    free(buffers[2].pvBuffer);


    /* Delete the security context */

    status = DeleteSecurityContext(&context);
    if (status != SEC_E_OK) {
	errmsg("DeleteSecurityContext", status);
	exit(1);
    }

}

int
main(int argc, char **argv)
{
    int ch;
    int error = 0;
    char *package = "Negotiate";
    char *target = NULL;
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
    if (!lflag && argc != optind + 1)
	error = 1;

    /* Display usage if there was an error in the arguments */
    if (error) {
	fprintf(stderr, "usage: %s -l\n"
		        "       %s [-c] [-f flags] [-p pkg] target\n"
			"Available flags: %s\n",
			argv[0], argv[0], flags_all(FLAGS_KIND_REQ));
	exit(1);
    }

    if (lflag)
	list_pkgs();
    else {
	target = argv[optind];
	client(target, package, req_flags, conf_req);
    }

    exit(0);
}
