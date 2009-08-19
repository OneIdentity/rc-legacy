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

    /* Get header sizes for building the secbuf */
    status = sspi->QueryContextAttributes(context, SECPKG_ATTR_SIZES, &sizes);
    if (status != SEC_E_OK) {
	errmsg("QueryContextAttributes SIZES", status);
	return 0;
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
    memcpy(buffers[1].pvBuffer, msg, msg_len);

    status = sspi->EncryptMessage(context, 
	    conf_req ? 0 : SECQOP_WRAP_NO_ENCRYPT,
	    &output, 0);
    if (status != SEC_E_OK) {
	errmsg("EncryptMessage", status);
	return 0;
    }

    printf("Encrypt buffers: %ld+%ld+%ld\n", buffers[0].cbBuffer, 
	    buffers[1].cbBuffer, buffers[2].cbBuffer);

    user_output_token(&output);

    /* Release the secbuf we allocated */
    free(buffers[0].pvBuffer);
    free(buffers[1].pvBuffer);
    free(buffers[2].pvBuffer);

    return 1;
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

    status = sspi->DecryptMessage(context, &inputdesc, 0, qop);

    user_input_free_token(&inbuffers[0]);

    if (status != SEC_E_OK) {
	errmsg("DecryptMessage", status);
	return 0;
    }

    *msg_ret = (char *)inbuffers[1].pvBuffer;
    *msg_len_ret = inbuffers[1].cbBuffer;
    return 1;
}

void
wrap_recv_free(char *msg)
{
    SECURITY_STATUS status;

    if (msg) {
        status = sspi->FreeContextBuffer(msg);
	if (status != SEC_E_OK)
	    errmsg("FreeContextBuffer", status);
    }
}
