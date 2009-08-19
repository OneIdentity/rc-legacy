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

static const char client_msg[] = "I am the SSPI client";

/* Lists the SSPI security packages available */
static void
list_pkgs()
{
    SECURITY_STATUS status;
    PSecPkgInfo pkgs;
    ULONG count;
    int i;

    status = EnumerateSecurityPackages(&count, &pkgs);
    if (status != SEC_E_OK) {
	errmsg("EnumerateSecurityPackages", status);
	exit(1);
    }

    for (i = 0; i < count; i++) {
	printf("\t%s\n", pkgs[i].Name);
	if (pkgs[i].Comment)
	    printf("\t\t- %s\n", pkgs[i].Comment);
    }
}

static const char *
TimeStamp_to_string(TimeStamp *ts) {
    SYSTEMTIME st;
    static char buf[1024];

    FileTimeToSystemTime((FILETIME *)ts, &st);
    snprintf(buf, sizeof buf, "%05u-%02u-%02u %02u:%02u:%02u.%03u",
	    st.wYear, st.wMonth, st.wDay,
	    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

/* Prints information about context attributes */
static void print_context_attrs(CtxtHandle *context)
{
    SecPkgContext_Sizes sizes;
    SecPkgContext_StreamSizes stream_sizes;
    SecPkgContext_Authority authority;
    SecPkgContext_KeyInfo key_info;
    SecPkgContext_Lifespan life_span;
    SECURITY_STATUS status;

    status = QueryContextAttributes(context, SECPKG_ATTR_AUTHORITY, 
	   &authority);
    if (status == SEC_E_OK)
	printf("authority.name          = %s\n", authority.sAuthorityName);
    else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes AUTHORITY", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_KEY_INFO, 
	   &key_info);
    if (status == SEC_E_OK) {
	printf("key_info.sig_algorithm  = %s\n",
		key_info.sSignatureAlgorithmName);
	printf("key_info.enc_algorithm  = %s\n",
		key_info.sEncryptAlgorithmName);
	printf("key_info.key_size    m  = %ld bits\n", key_info.KeySize);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes KEY_INFO", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_LIFESPAN, 
	   &life_span);
    if (status == SEC_E_OK) {
	printf("life_span.start         = %s\n",
		TimeStamp_to_string(&life_span.tsStart));
	printf("life_span.expiry        = %s\n",
		TimeStamp_to_string(&life_span.tsExpiry));
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes LIFESPAN", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_SIZES, &sizes);
    if (status == SEC_E_OK) {
	printf("sizes.cbMaxToken        = %10ld\n", sizes.cbMaxToken);
	printf("sizes.cbMaxSignature    = %10ld\n", sizes.cbMaxSignature);
	printf("sizes.cbBlockSize       = %10ld\n", sizes.cbBlockSize);
	printf("sizes.cbSecurityTrailer = %10ld\n", sizes.cbSecurityTrailer);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes SIZES", status);

    status = QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, 
	    &stream_sizes);
    if (status == SEC_E_OK) {
	printf("stream_sizes.cbHeader   = %10ld\n", 
		stream_sizes.cbHeader);
	printf("stream_sizes.cbTrailer  = %10ld\n", 
		stream_sizes.cbTrailer);
/*	printf("stream_sizes.cbMaximumMessage = %10ld\n", 
		stream_sizes.cbMaximumMessage);
	printf("stream_sizes.cbBuffers  = %10ld\n", 
		stream_sizes.cbBuffers);
*/	printf("stream_sizes.cbBlockSize= %10ld\n", 
		stream_sizes.cbBlockSize);
    } else if (status != SEC_E_UNSUPPORTED_FUNCTION)
	errmsg("QueryContextAttributes STREAM_SIZES", status);
}

/* Prints information about the credentials */
static void
print_cred_attrs(CredHandle *credentials)
{
    SecPkgCredentials_Names names;
    SECURITY_STATUS status;

    status = QueryCredentialsAttributes(credentials, 
	    SECPKG_CRED_ATTR_NAMES, &names);
    if (status != SEC_E_OK)
	errmsg("QueryCredentialsAttributes", status);
    else
	printf("credential.userName: %s\n", names.sUserName);
}

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
