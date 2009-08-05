/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Companion program to gss-client/gss-server, but using the Windows SSPI interface.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include <windows.h>
#include <security.h>
#include "base64.h"
#include "getopt.h"

/* Prints a windows error code as readable text. */
static void
errmsg(const char *msg, int status)
{
    static char buffer[16384];

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|   /* dwFlags */
		  FORMAT_MESSAGE_IGNORE_INSERTS,
		  0,                            /* lpSource */
		  status,                       /* dwMessageId */
		  0,                            /* dwLanguageId */
		  buffer,                       /* lpBuffer */
		  sizeof buffer,                /* nSize */
		  0);                           /* Arguments */
    fprintf(stderr, "%s: %s\n", msg, buffer);
}

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

/* Dump the resulting token buffers in base64 */
static void
print_token(SecBufferDesc *desc)
{
    SecBuffer *buf;
    int base64_len;
    char *base64;
    int i;

    for (i = 0; i < desc->cBuffers; i++) {
        buf = desc->pBuffers + i;
	base64_len = base64_encode(buf->pvBuffer, buf->cbBuffer, NULL, 0);
	base64 = malloc(base64_len);
	base64_encode(buf->pvBuffer, buf->cbBuffer, base64, base64_len);
	printf("output: %.*s.\n", base64_len, base64);
        free(base64);
    }
}

/* Prompt for and input a bas64 string and put the binary into a new SecBuffer */
static void
input_token(SecBuffer *buf)
{
    char sbuf[65537], *dec;
    int bufpos, inlen, ch;

    bufpos = 0;
    while ((ch = fgetc(stdin)) != EOF) {
        if (ch == '.')
            break;
        if (!isspace(ch) && bufpos + 1 < sizeof sbuf)
            sbuf[bufpos++] = ch;
    }
    sbuf[bufpos] = '\0';
    if (ch == EOF) {
        fprintf(stderr, "fgetc: EOF\n");
        exit(1);
    }
    dec = base64_string_decode(sbuf, &inlen);
    if (!dec) {
        fprintf(stderr, "base64_string_decode: failed\n");
        exit(1);
    }
    printf("\n");

    buf->BufferType = SECBUFFER_TOKEN;
    buf->pvBuffer = dec;
    buf->cbBuffer = inlen;
}


static void
client(char *target, char *package)
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

    context = NULL;
    input = NULL;
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
                context,			/* phContext */
                target,				/* pszTargetName */
                ISC_REQ_ALLOCATE_MEMORY,	/* fContextReq */
                0,				/* Reserved1 */
                SECURITY_NATIVE_DREP,		/* TargetDataRep */
                input,				/* pInput */
                0,				/* Reserved2 */
                &context,			/* phNewContext */
                &output,			/* pOutput */
                &attr,				/* pContextAttr */
                &expiry);			/* ptsExpiry */
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
            print_token(&output);
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
            input_token(&inbuffers[0]);
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

    /* Parse command line arguments */
    while ((ch = getopt(argc, argv, "lp:")) != -1) 
	switch (ch) {
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
		        "       %s [-p pkg] target\n",
			argv[0], argv[0]);
	exit(1);
    }

    if (lflag)
	list_pkgs();
    else {
	target = argv[optind];
	client(target, package);
    }

    exit(0);
}
