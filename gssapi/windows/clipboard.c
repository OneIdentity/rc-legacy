/* (c) 2009, Quest Software, Inc. All rights reserved. */

#include <stdio.h>
#include <windows.h>
#include "clipboard.h"
#include "errmsg.h"

/*
 * Copies the given text to the system clipboard.
 * It also appends the nul-terminated suffix to the end.
 * The passed-in data must be ASCII text without NULs.
 * This only works if a console is allocated to the process.
 * Returns true if data was successfuly copied to the clipboard.
 */
int
clipboard_copyto(const char *data, int data_len, const char *suffix)
{
    HWND console = NULL;
    HGLOBAL hClipBuf = NULL;
    LPTSTR pzClipBuf = NULL;
    int clipboard_opened = 0;
    int ret = 0;
    int suffix_len = suffix ? strlen(suffix) : 0;

    /* Access the clipboard */

    console = GetConsoleWindow();
    if (!console) {
	errmsg("GetConsoleWindow", GetLastError());
	goto cleanup;
    }

    if (!OpenClipboard(console)) {
	errmsg("OpenClipboard", GetLastError());
	goto cleanup;
    }
    clipboard_opened = 1;

    if (!EmptyClipboard()) {
	errmsg("EmptyClipboard", GetLastError());
	goto cleanup;
    }

    /* Copy the arguments into a global memory buffer */

    hClipBuf = GlobalAlloc(GMEM_MOVEABLE, data_len + suffix_len + 1);
    if (hClipBuf == NULL) {
	errmsg("GlobalAlloc", GetLastError());
	goto cleanup;
    }

    pzClipBuf = GlobalLock(hClipBuf);
    if (!pzClipBuf) {
	errmsg("GlobalLock", GetLastError());
	goto cleanup;
    }

    memcpy(pzClipBuf, data, data_len);
    memcpy(pzClipBuf + data_len, suffix, suffix_len);
    pzClipBuf[data_len + suffix_len] = 0;

    if (!GlobalUnlock(hClipBuf)) {
	DWORD error = GetLastError();
	if (error != NO_ERROR) {
	    errmsg("GlobalUnlock", error);
	    goto cleanup;
	}
    }
    pzClipBuf = NULL;

    /* Send the buffer to the clipboard */

    if (SetClipboardData(CF_TEXT, hClipBuf) == NULL) {
	errmsg("SetClipboardData", GetLastError());
	goto cleanup;
    }
    hClipBuf = NULL;	/* The datacopy is now owned by clipboard */

    ret = 1;

cleanup:
    if (clipboard_opened)
	(void)CloseClipboard();
    if (pzClipBuf && hClipBuf)
	(void)GlobalUnlock(hClipBuf);
    if (hClipBuf)
	(void)GlobalFree(hClipBuf);
    return ret;
}
