/* (c) 2009 Quest Software, Inc. All rights reserved */

#include <stdio.h>
#include "common.h"
#include "wsspi.h"
#include "errmsg.h"
#include "wrap.h"
#include "userio.h"

/*
 * Encrypts a message and then sends it to the output
 */
int
wrap_send(CtxtHandle *context, const char *msg, int msg_len, 
		int conf_req)
{
    SecPkgContext_Sizes sizes;
    SECURITY_STATUS status;
    SecBuffer buffers[3];
    SecBufferDesc output;
    char *token, *data, *padding;
    int ret = 0;

    /* Get header sizes for building the secbuf */
    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_SIZES, 
		    &sizes);
    if (status != SEC_E_OK) {
	errmsg("QueryContextAttributes SIZES", status);
	return 0;
    }

    /*
     * SAP gsskrb5 uses:
     *      TOKEN   = sizes.cbSecurityTrailer, malloc()
     *      DATA    = msg_len, malloc+memcpy(data)
     *      PADDING = sizes.cbBlockSize, malloc()
     *
     * Platform SDK example uses:
     *      TOKEN   = sizes.cbSecurityTrailer
     *      DATA    = msg_len
     *     (but they also send the cbSecurityTrailer size OOB for decrypt?)
     *
     * Platform SDK documentation isn't clear, since it assumes SSL, but
     * it seems to indicate:
     *      STREAM_HEADER  = (no init)
     *      DATA           = msg_len
     *      STREAM_TAILIER = (no init)
     *      EMPTY          = (no init)
     *      PADDING        = "must use" ?
     *
     * In  "The Security Support Provider Interface Revisited", K Brown, 2001
     * (http://msdn.microsoft.com/en-us/magazine/cc301890.aspx) 
     * there are two configurations, one for GSSAPI compatibility:
     *      TOKEN  = sizes.cbSecurityTrailer
     *      DATA   = msg_len
     *      PADDING = sizes.cbBlockSize
     * and the other for "Raw SSPI":
     *      DATA   = msg_len
     *      TOKEN  = sizes.cbSecurityTrailer
     * (The drawback of the "Raw SSPI" is that you must communicate the
     * size of the two SecBufs to decrypt it)
     */

    token = malloc(sizes.cbSecurityTrailer);
    data = malloc(msg_len);
    padding = malloc(sizes.cbBlockSize);

    /* data is encrypted in-place, so make a copy */
    memcpy(data, msg, msg_len);

    output.ulVersion = SECBUFFER_VERSION;
    output.cBuffers = 3;
    output.pBuffers = buffers;
    buffers[0].BufferType = SECBUFFER_TOKEN;
    buffers[0].cbBuffer = sizes.cbSecurityTrailer;
    buffers[0].pvBuffer = token;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].cbBuffer = msg_len;
    buffers[1].pvBuffer = data;
    buffers[2].BufferType = SECBUFFER_PADDING;
    buffers[2].cbBuffer = sizes.cbBlockSize;
    buffers[2].pvBuffer = padding;

    status = sspi->EncryptMessage(
	    context, 					/* phContext */
	    conf_req ? 0 : SECQOP_WRAP_NO_ENCRYPT,	/* fQOP */
	    &output, 					/* pMessage */
	    0);						/* MessageSeqNo */

    if (status == SEC_E_OK) {
	printf("Encrypt buffers: TOKEN %ld DATA %ld PAD %ld\n", 
		buffers[0].cbBuffer, 
		buffers[1].cbBuffer, 
		buffers[2].cbBuffer);

	user_output_token(&output);
	ret = 1;
    } else {
	errmsg("EncryptMessage", status);
	ret = 0;
    }

    free(padding);
    free(data);
    free(token);

    return ret;
}

/*
 * Receives an input token, and then decrypts it.
 * Returns 1 on success, or 0 on failure.
 * On success, the decrypted pointer must be freed with wrap_recv_free().
 */
int
wrap_recv(CtxtHandle *context, char **msg_ret, int *msg_len_ret, 
		ULONG *qop)
{
    SecBufferDesc inputdesc;
    SecBuffer inbuffers[2];
    SECURITY_STATUS status;
    char *plaintext = NULL;
    int plaintext_len = 0;

    /*
     * SAP gsskrb5 uses this structure
     *     STREAM  token_len
     *     DATA    (null)
     * After decrypt, the DATA buffer points *into* the STREAM
     * buffer, because SSPI decrypts in-place.
     *
     * K Brown agrees, but describes "Raw SSPI" decryption to use
     *     DATA    size of ciphertext (same as plaintext)
     *     TOKEN   size of resulting security trailer
     */

    inputdesc.ulVersion = SECBUFFER_VERSION;
    inputdesc.cBuffers = 2;
    inputdesc.pBuffers = inbuffers;

    /* Input a token directly into a buffer */
    user_input_token(&inbuffers[0]);
    inbuffers[0].BufferType = SECBUFFER_STREAM; /* Change type to STREAM */

    /* Prepare an output part */
    inbuffers[1].BufferType = SECBUFFER_DATA;
    inbuffers[1].pvBuffer = NULL;
    inbuffers[1].cbBuffer = 0;

    status = sspi->DecryptMessage(context, &inputdesc, 0, qop);

    if (status == SEC_E_OK) {
	plaintext_len = inbuffers[1].cbBuffer;
	plaintext = malloc(plaintext_len);
	memcpy(plaintext, inbuffers[1].pvBuffer, plaintext_len);
    }

    user_input_free_token(&inbuffers[0]);

    if (status != SEC_E_OK) {
	errmsg("DecryptMessage", status);
	return 0;
    }

    *msg_ret = plaintext;
    *msg_len_ret = plaintext_len;
    return 1;
}

void
wrap_recv_free(char *msg)
{
    if (msg) {
        free(msg);
    }
}
