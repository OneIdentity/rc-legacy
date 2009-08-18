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

static char *clipboard_text = NULL;
static int clipboard_text_len = 0;

/* Appends text to be copied to the system clipboard later by 
 * user_output_flush() */
static void
append_text_to_clipboard(const char *text, int text_len)
{
    char *newbuf;

    if (!text_len)
	return;

    if (clipboard_text == NULL) {
	newbuf = malloc(text_len);
	clipboard_text_len = 0;
    } else
	newbuf = realloc(clipboard_text, clipboard_text_len + text_len);

    if (!newbuf) {
	fprintf(stderr, "Out of memory adding text to clipboard text buffer\n");
	return;
    }

    clipboard_text = newbuf;
    memcpy(clipboard_text + clipboard_text_len, text, text_len);
    clipboard_text_len += text_len;
}

/* Flushes user output. */
void
user_output_flush()
{
    if (clipboard_text) {
	if (clipboard_copyto(clipboard_text, clipboard_text_len, ""))
	    printf("[copied output tokens to clipboard]\n");
	free(clipboard_text);
	clipboard_text = NULL;
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
	append_text_to_clipboard(base64, base64_len);
	append_text_to_clipboard(".\r\n", strlen(".\r\n"));
        free(base64);
    }
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

    printf("input: "); 
    user_output_flush();

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

