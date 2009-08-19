/* (c) 2009 Quest Software, Inc. All rights reserved */
/*
 * Companion program to gss-client/gss-server, but using the Windows SSPI interface.
 * David Leonard, 2009.
 */

#include <stdio.h>
#include <ctype.h>
#include "wsspi.h"
#include "base64.h"
#include "clipboard.h"

static char *clipboard_text = NULL;
static int clipboard_text_len = 0;
static int clipboard_text_space = 0;

/* Appends text to be copied to the system clipboard later by 
 * user_output_flush() */
static void
append_text_to_clipboard(const char *text, int text_len)
{
    char *newbuf;
    int new_len;

    if (!text_len)
	return;

    new_len = clipboard_text_len + text_len;

    if (clipboard_text_space == 0) {
	clipboard_text_space = 1024;
	while (clipboard_text_space < new_len)
	    clipboard_text_space *= 2;
	clipboard_text = malloc(clipboard_text_space);
	if (!clipboard_text) {
	    fprintf(stderr, "Out of memory creating clipboard buf\n");
	    return;
	}
    }

    if (clipboard_text_space < new_len) {
	while (clipboard_text_space < new_len)
	    clipboard_text_space *= 2;
	newbuf = realloc(clipboard_text, clipboard_text_space);
	if (!newbuf) {
	    fprintf(stderr, "Out of memory adding text to clipboard buf\n");
	    return;
	}
	clipboard_text = newbuf;
    }
    memcpy(clipboard_text + clipboard_text_len, text, text_len);
    clipboard_text_len = new_len;
}

/* Flushes user output. */
void
user_output_flush()
{
    if (clipboard_text_len) {
	if (clipboard_copyto(clipboard_text, clipboard_text_len, ""))
	    printf("[output tokens copied to clipboard]\n");
	clipboard_text_len = 0;
    }
    fflush(stdout);
}

/* Dumps the SSP token buffers in base64 to the user. Output is
 * terminated with a period and a newline so it can be cut-and-paste
 * to the corresponding client or server process. */
void
user_output_token(SecBufferDesc *desc)
{
    SecBuffer *buf;
    base64_enc_state_t b64;
    int i, j;
    int linelen = 0;
    char out[4];
    int outlen;

    printf("output: ");
    base64_encode_init(&b64);
    for (i = 0; i < desc->cBuffers; i++) {

        buf = desc->pBuffers + i;
	for (j = 0; j < buf->cbBuffer; j++) {
	    outlen = base64_encode_sub(&b64, (char *)buf->pvBuffer + j, 1,
		out, sizeof out);
	    if (outlen < 0) {
	        fprintf(stderr, "base64_encode_sub error\n");
		exit(1);
	    }
	    if (outlen) {
		printf("%.*s", outlen, out);
		append_text_to_clipboard(out, outlen);
		linelen += outlen;
		if (linelen >= 64) {
		    printf("\n ");
		    linelen = 0;
		    append_text_to_clipboard("\r\n ", 3);
		}
	    }	
	}	
    }
    outlen = base64_encode_fini(&b64, out, sizeof out);
    if (outlen) {
	printf("%.*s", outlen, out);
	append_text_to_clipboard(out, outlen);
    }
    printf(".\n");
    append_text_to_clipboard(".\r\n", strlen(".\r\n"));
}

/*
 * Prompts for and reads in a bas64 string terminated by a period,
 * and put the decoded binary into a new SecBuffer structure.
 * Whitespace is ignored.
 */
void
user_input_token(SecBuffer *buf)
{
    char sbuf[65537], *dec;
    int bufpos, inlen, ch;

    buf->cbBuffer = 0;
    buf->pvBuffer = NULL;

    user_output_flush();

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

void
user_input_free_token(SecBuffer *buf)
{
    if (buf->pvBuffer) {
        free(buf->pvBuffer);
	buf->pvBuffer = NULL;
	buf->cbBuffer = 0;
    }
}
