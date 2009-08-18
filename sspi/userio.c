/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Companion program to gss-client/gss-server, but using the Windows SSPI interface.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include <windows.h>
#include <ntsecpkg.h>	/* Gah! */
#include <security.h>
#include "base64.h"
#include "clipboard.h"

/* Dump the resulting token buffers in base64 */
void
user_output_token(SecBufferDesc *desc)
{
    SecBuffer *buf;
    int base64_len;
    char *base64;
    int i, j;

    for (i = 0; i < desc->cBuffers; i++) {
        buf = desc->pBuffers + i;
	base64_len = base64_encode(buf->pvBuffer, buf->cbBuffer, NULL, 0);
	base64 = malloc(base64_len);
	base64_encode(buf->pvBuffer, buf->cbBuffer, base64, base64_len);
	printf("output: ");
	for (j = 0; j < base64_len; j += 75)
		printf("\n %.*s", 
			j + 75 <= base64_len ? 75 : base64_len - j,
			base64 + j);
	printf(".\n");
	clipboard_copyto(base64, base64_len, ".\r\n");
        free(base64);
    }
}

/* Prompt for and input a bas64 string and put the binary into a new SecBuffer */
void
user_input_token(SecBuffer *buf)
{
    char sbuf[65537], *dec;
    int bufpos, inlen, ch;

    printf("input: "); fflush(stdout);

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

