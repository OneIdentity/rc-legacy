/* $Vintela: winxcons.c,v 1.6 2005/08/11 03:40:33 davidl Exp $ */
/*
 * Copyright (c) 2005 Quest Software, Inc. 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * a. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * b. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * c. Neither the name of Quest Software, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission. THIS SOFTWARE
 *    IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 *    BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 *    THE POSSIBILITY OF SUCH DAMAGE.
 */ 

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include "putty.h"
#include "wconsrc.h"
#include "winxcons.h"

struct winxcons winxcons;

/* Parameter structure passed to general dialog */
struct param {
	const char *msg;
       	char *reply;
       	int replysz;
	int simple;
};

static void winxcons_console_restore(void);
static BOOL CALLBACK DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, 
	LPARAM lParam);
static void reset_dialog_message(void);
static void fatalerror(const char *msg);
static void winxcons_nul_handle(DWORD);

/* Static variables used to buffer messages for the next dialog */
static char *dialog_message = NULL;
static int dialog_message_length = 0;

/* Hides/shows the console window. State is saved on first invocation
 * so that it can be automatically restored on exit */
void winxcons_console_hide(int hide)
{
    HWND console;
   
    /* Note: GetConsoleWindow requires WINVER >= 0x0500 */
    console = GetConsoleWindow();
    if (!console)
	return;

    /* If unknown, save the current state now */
    if (winxcons.console_was_hidden == -1) {
	if (IsWindowVisible(console))
	    winxcons.console_was_hidden = 0;
	else
	    winxcons.console_was_hidden = 1;
    }

    debug(("%s console\n", hide ? "Hiding" : "Showing"));
    ShowWindow(console, hide ? SW_HIDE : SW_SHOW);
}

/* Restores the console window state. Called during exit */
static void winxcons_console_restore()
{
    switch (winxcons.console_was_hidden) {
    case 0:
	ShowWindow(GetConsoleWindow(), SW_SHOW);
	break;
    case 1:
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	break;
    case -1:
	/* Don't know. Don't change */
	break;
    }
    winxcons.console_was_hidden = -1;
}

/* Initialise winxcons; should be called early from main() */
void winxcons_init()
{
    /*
     * Detect if we have a console.
     * If we are invoked as PLINKW, then there is rarely
     * a console.
     */
    winxcons.has_console = GetConsoleWindow() != NULL;
    winxcons.console_was_hidden = -1;

    if (winxcons.has_console)
	SetConsoleTitle("Quest PLink");
}

/* Handle to the null device */
static HANDLE winxcons_nul = INVALID_HANDLE_VALUE;

/* Sets one of the standard file descriptors to NUL */
static void winxcons_nul_handle(DWORD std_handle)
{
    if (winxcons_nul == INVALID_HANDLE_VALUE) {
	/* Open NUL for read */
	winxcons_nul = CreateFile("NUL", GENERIC_READ | GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	    OPEN_EXISTING, 0, NULL);
	if (winxcons_nul == INVALID_HANDLE_VALUE)
	    fatalerror("CreateFile: cannot open NUL");
    }

    /* Set stdin to NUL */
    if (!SetStdHandle(std_handle, winxcons_nul))
	fatalerror("SetStdHandle");
}

/* Processes a command-line parameter. Returns 0 if no parameters consumed */
int winxcons_process_param(char *p, Config *cfg)
{
    if (!p)
	return 0;
    if (strcmp(p, "-use_vintela_gui_w_pwd") == 0) {
	winxcons.use_gui = 1;
	winxcons.use_gui_passwd = 1;
    } else if (strcmp(p, "-use_vintela_gui_no_pwd") == 0) {
	winxcons.use_gui = 1;
	winxcons.use_gui_passwd = 0;
    } else if (strcmp(p, "-hide_console") == 0) {
	winxcons_console_hide(1);
    } else if (strcmp(p, "-auto_store_key_in_cache") == 0) {
	winxcons.always_store_keys = 1;
    } else if (strcmp(p, "-no_in") == 0) {
	winxcons_nul_handle(STD_INPUT_HANDLE);
    } else if (strcmp(p, "-no_out") == 0) {
	winxcons_nul_handle(STD_OUTPUT_HANDLE);
    } else
	return 0;
    return 1;
}

/* Prints usage for some processed command-line arguments */
void winxcons_print_usage()
{
    printf("  -use_vintela_gui_w_pwd\n"
           "            Use dialogs instead of console for all prompts\n");
    printf("  -use_vintela_gui_no_pwd\n"
	   "            Use dialogs instead of console for all prompts except password\n");
    printf("  -hide_console\n"
           "            Hides console window. Useful when automated.\n");
    printf("  -auto_store_key_in_cache\n"
           "            Always trust new host fingerprints (dangerous)\n");
    printf("  -no_in    Redirect input from NUL:\n");
    printf("  -no_out   Redirect output to NUL:\n");
}

/* Clean up; should be called during exit processing */
void winxcons_cleanup_exit(int code)
{
    winxcons_console_restore();
}

/* Displays the last Windows error using fatalbox() */
static void fatalerror(const char *msg) 
{
    char *errortext = 0;
    int len;

    len = FormatMessage(
	    FORMAT_MESSAGE_ALLOCATE_BUFFER |
	    FORMAT_MESSAGE_FROM_SYSTEM,		/* dwFlags */
	    0 /* ignored */,			/* lpSource */
	    GetLastError(),			/* dwMessageId */
	    0 /* default */,			/* dwLanguageId */
	    (LPTSTR)&errortext,			/* lpBuffer */
	    0, 					/* nSize */
	    0);					/* Arguments */
    if (len == 0) {
	msg = "(Error constructing error message)";
	len = strlen(msg);
    }
    fatalbox("%s: %.*s", msg, len, errortext);
    /* NOTREACHED */
}

/* Handles dialog callback messages during winxcons_get_line() */
static BOOL CALLBACK DialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, 
	LPARAM lParam)
{
    struct param *param = (struct param *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    HWND ctl;
    int len;
    const char *message;

    switch (uMsg) {
    case WM_INITDIALOG:
	/* Store the initialisation parameter in the userdata slot */
	param = (struct param *)lParam;
	SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)param);

	message = dialog_message ? dialog_message : "(no message)";

	/* Initialise the fields from the param structure */
	if (param->simple) {
	    if (!SetWindowText(hwnd, message))
		fatalerror("SetWindowText()");
	} else {
	    if (!SetDlgItemText(hwnd, IDC_MESSAGE, message))
		fatalerror("SetDlgItemText(MESSAGE)");
	}

	/* Leave focus on the response field */
	if ((ctl = GetDlgItem(hwnd, IDC_RESPONSE)) == NULL)
	    fatalerror("GetDlgItem(RESPONSE)");
	(void)SetFocus(ctl);
	break;

    case WM_COMMAND:
	switch (LOWORD(wParam)) {
	case IDOK:
	    /* User clicked OK - copy out the response text and end */
	    len = GetDlgItemText(hwnd, IDC_RESPONSE, param->reply,
		param->replysz);
	    if (len == 0 && GetLastError() != ERROR_SUCCESS)
	        fatalerror("GetDlgItemText(RESPONSE)");
	    if (!EndDialog(hwnd, IDOK))
	        fatalerror("EndDialog");
	    break;

	case IDCANCEL:
	    /* User clicked cancel */
	    if (!EndDialog(hwnd, IDCANCEL))
	        fatalerror("EndDialog");
	    break;
	}
	break;
    }

    return FALSE;
}

/* Appends text to the buffer that is shown in the next dialog */
void winxcons_printf(const char *fmt, ...)
{
    va_list ap;
    char *msg, *s, *p;
    char *new_dialog_message;
    int msglen;
    int new_dialog_message_length;

    /* Expand the argument text */
    va_start(ap, fmt);
    msg = dupvprintf(fmt, ap);
    va_end(ap);

    /* Calculate how much space is needed after translating \n to \r\n */
    for (msglen = 0, s = msg; *s; s++) {
	if (*s == '\n')
	    msglen++;
	msglen++;
    }

    if (!msglen)
	return;

    /* Construct the new appended text */
    new_dialog_message_length = dialog_message_length + msglen;
    new_dialog_message = snewn(new_dialog_message_length + 1, char);
    if (dialog_message_length)
	memcpy(new_dialog_message, dialog_message, dialog_message_length);
    for (p = new_dialog_message + dialog_message_length, s = msg; *s; s++) {
	if (*s == '\n') 
	    *p++ = '\r';
	*p++ = *s;
    }
    assert(p == new_dialog_message + new_dialog_message_length);
    *p = '\0';

    /* Replace the old dialog message text with the new */
    sfree(dialog_message);
    dialog_message = new_dialog_message;
    dialog_message_length = new_dialog_message_length;
}

/* Resets the dialog message text buffer to the empty string */
static void reset_dialog_message()
{
    sfree(dialog_message);
    dialog_message = NULL;
    dialog_message_length = 0;
}

/* 
 * Displays a dialog box to get a response from the user.
 * If the buffered text is short and contains no newlines, then we
 * use a simplified dialog. Otherwise, we use the general (clunky)
 * dialog.
 * Returns 0 if the user pressed Cancel.
 */
int winxcons_get_line(char *reply, int replysz, int is_pw)
{
    struct param param;
    int result;
    int dialogid;

    assert(reply != NULL);
    assert(replysz > 0);

    param.reply = reply;
    param.replysz = replysz;

#define MAX_SIMPLE_MESSAGE_LENGTH 18

    if (dialog_message_length <= MAX_SIMPLE_MESSAGE_LENGTH &&
	    dialog_message && !strchr(dialog_message, '\n'))
    {
	dialogid = is_pw ? IDD_SIMPLE_PASSWORD : IDD_SIMPLE_RESPONSE;
	param.simple = 1;
    } else {
	dialogid = is_pw ? IDD_GENERAL_PASSWORD : IDD_GENERAL_RESPONSE;
	param.simple = 0;
    }

    result = DialogBoxParam(
	    GetModuleHandle(NULL),			/* hInstance */
	    MAKEINTRESOURCE(dialogid),			/* lpTemplateName */
	    GetConsoleWindow(),				/* hWndParent */
	    DialogProc, 				/* lpDialogFunc */
	    (LPARAM)&param);				/* dwInitParam */

    reset_dialog_message();

    switch (result) {
    case IDOK:
	return 1;
    case IDCANCEL:
	return 0;
    default:
	if (result < 0)
	    fatalerror("DialogBoxParam()");
	else
	    fatalbox("DialogBoxParam(): unexpected result %d", result);
	return -1; /* NOTREACHED */
    }
}
