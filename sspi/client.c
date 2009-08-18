/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Companion program to gss-client/gss-server, but using the Windows SSPI interface.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include <windows.h>
#include <ntsecpkg.h>	/* Gah! */
#include <security.h>
#include "getopt.h"
#include "errmsg.h"
#include "userio.h"
#include "flags.h"

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


static void
client(char *target, char *package, ULONG req_flags, int conf_req)
{
    CredHandle credentials;
    TimeStamp expiry;
    CtxtHandle context;
    SecBufferDesc output;
    SecBufferDesc *input, inputdesc;
    SecPkgCredentials_Names names;
    SecBuffer buffers[1];
    SecBuffer inbuffers[1];
    ULONG attr;
    int i;
    SECURITY_STATUS status;
    int initial;

    /* Acquire credentials */
    status = AcquireCredentialsHandle(NULL, package,
	    SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL,
	    &credentials, &expiry);
    if (status != SEC_E_OK) {
	errmsg("AcquireCredentialsHandle", status);
	exit(1);
    }

    /* Display whose credentials we got */
    status = QueryCredentialsAttributes(&credentials, 
	    SECPKG_CRED_ATTR_NAMES, &names);
    if (status != SEC_E_OK)
	errmsg("QueryCredentialsAttributes", status);
    else
	printf("Acquired credentials for: %s\n", names.sUserName);

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
            /* XXX TBD: free output */
        }

        if (input) {
            free(inbuffers[0].pvBuffer); /* from last call to input_token */
            inbuffers[0].pvBuffer = NULL;
            inbuffers[0].cbBuffer = 0;
            input = NULL;
        }

        if (status == SEC_I_CONTINUE_NEEDED) {
            inputdesc.ulVersion = SECBUFFER_VERSION;
            inputdesc.cBuffers = 1;
            inputdesc.pBuffers = inbuffers;
            user_input_token(&inbuffers[0]);
            input = &inputdesc;
        }

    } while (status == SEC_I_CONTINUE_NEEDED);

    printf("InitializeSecurityContext completed\n");

    /* 
     * TBD:
     *  input
     *  unwrap
     *  wrap
     *  output
     */
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
	    req_flags |= names2flags(optarg);
	    break;
	case 'c':
	    conf_req = 1;
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
			argv[0], argv[0], flags_all());
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
