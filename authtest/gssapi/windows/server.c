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
#include "deleg.h"
#include "version.h"

static const char server_msg[] = "I am the SSPI server";

/* Do something interesting with a context containing delegation */
static void
delegated(CtxtHandle *context)
{
    SECURITY_STATUS status;
    SECURITY_STATUS ac_status;
    CredHandle credentials;
    TimeStamp expiry = { 0, 0 };
    SecPkgContext_PackageInfo pkg_info;
    char *package;

    printf("Credentials were delegated\n");

    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_PACKAGE_INFO, 
	   &pkg_info);
    if (status != SEC_E_OK) {
	errmsg("QueryContextAttributes PACKAGE_INFO", status);
	return;
    }

    package = (char *)pkg_info.PackageInfo->Name;

    printf(">> Impersonating delegated context\n");
    status = ImpersonateSecurityContext(context);
    if (status != SEC_E_OK) {
	errmsg("ImpersonateSecurityContext", status);
	return;
    }

    printf(">> Acquiring delegated credentials, package=%s\n", package);

    /* Acquire credentials */
    ac_status = sspi->AcquireCredentialsHandle(
	    NULL, 				/* pszPrincipal */
	    package,				/* pszPackage */
	    SECPKG_CRED_OUTBOUND, 		/* fCredentialUse */
	    NULL, 				/* pvLogonID */
	    NULL, 				/* pAuthData */
	    NULL, 				/* pGetKeyFn */
	    NULL,				/* pvGetKeyArgument */
	    &credentials, 			/* phCredential */
	    &expiry);				/* ptsExpiry */

    if (ac_status != SEC_E_OK) {
	errmsg("AcquireCredentialsHandle", ac_status);
    } else {

	printf(">> Acquired delegated credentials!\n");

	print_cred_attrs(&credentials);

	printf(">> Expiry: %s\n", TimeStamp_to_string(&expiry));

	printf(">> Freeing delegated credentials\n");
	status = sspi->FreeCredentialsHandle(&credentials);
	if (status != SEC_E_OK)
	    errmsg("FreeCredentialsHandle", status);
    }

    printf(">> Reverting from impersonation\n");
    status = RevertSecurityContext(context);
    if (status != SEC_E_OK) {
	errmsg("RevertSecurityContext", status);
	exit(1);
    }

} 

static void
server(char *package, char *principal, int req_flags, int conf_req)
{
    CredHandle credentials;
    TimeStamp expiry = { 0, 0 };
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
    //HANDLE deleg_token = INVALID_HANDLE_VALUE;

    if (req_flags & ASC_REQ_DELEGATE)
	print_self_info();

    /* Acquire credentials */
    printf("Acquiring inbound credentials for %s\n", principal);

    status = sspi->AcquireCredentialsHandle(null_principal(principal),
	package, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL,
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
                ASC_REQ_ALLOCATE_MEMORY |	/* fContextReq */
		req_flags,
                SECURITY_NATIVE_DREP,		/* TargetDataRep */
                &context,			/* phNewContext */
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
		if (complete_status != SEC_E_OK) {
		    errmsg("CompleteAuthToken", complete_status);
		    exit(1);
		}
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

    if (attr & ASC_RET_DELEGATE)
	delegated(&context);

#if 0
    /* Attempt to fetch any delegated credential */
    // Argh another broken bit in mingw's <sspi.h>
    // status = sspi->QuerySecurityContextToken(&context, &deleg_token);
    status = ((QUERY_SECURITY_CONTEXT_TOKEN_FN)sspi->Unknown5)(&context, &deleg_token);
    if (status == SEC_E_OK) {
	printf("Credentials delegated:\n");
	print_token_info(deleg_token);
	CloseHandle(deleg_token);

	delegated(&context, package);

    } else 
	errmsg("QuerySecurityContextToken", status);
#endif

    /* Encrypt and send the server message */

    printf("Message to client: \"%s\"\n", server_msg);

    wrap_send(&context, server_msg, strlen(server_msg), conf_req);

    /* Wait for and decode the client message */

    if (!wrap_recv(&context, &msg, &msg_len, &qop))
	exit(1);

    fprintf(stderr, "input qop = 0x%lx\n", qop);
    fprintf(stderr, "Message from server: \"%.*s\"\n",  msg_len, msg);

    wrap_recv_free(msg);


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
    char *principal = "NULL";
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

    if (optind < argc)
	principal = argv[optind++];

    if (optind < argc)
	error = 1;

    /* Display usage if there was an error in the arguments */
    if (error) {
	fprintf(stderr, "usage: %s -l\n"
		        "       %s [-c] [-f flags] [-p pkg] [target]\n"
			"Available flags: %s\n"
			"Version %s\n",
			argv[0], argv[0], flags_all(FLAGS_KIND_REQ),
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
    else
	server(package, principal, req_flags, conf_req);

    exit(0);
}
