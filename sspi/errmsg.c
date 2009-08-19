/* (c) 2009 Quest Software, Inc. All rights reserved */

#include <stdio.h>
#include "wsspi.h"
#include "errmsg.h"

static struct {
    int value;
    const char *name;
} errtab[] = {
    { SEC_E_OK, "SEC_E_OK" },
    { SEC_E_INSUFFICIENT_MEMORY, "SEC_E_INSUFFICIENT_MEMORY" },
    { SEC_E_INVALID_HANDLE, "SEC_E_INVALID_HANDLE" },
    { SEC_E_UNSUPPORTED_FUNCTION, "SEC_E_UNSUPPORTED_FUNCTION" },
    { SEC_E_TARGET_UNKNOWN, "SEC_E_TARGET_UNKNOWN" },
    { SEC_E_INTERNAL_ERROR, "SEC_E_INTERNAL_ERROR" },
    { SEC_E_SECPKG_NOT_FOUND, "SEC_E_SECPKG_NOT_FOUND" },
    { SEC_E_NOT_OWNER, "SEC_E_NOT_OWNER" },
    { SEC_E_INVALID_TOKEN, "SEC_E_INVALID_TOKEN" },
    { SEC_E_QOP_NOT_SUPPORTED, "SEC_E_QOP_NOT_SUPPORTED" },
    { SEC_E_LOGON_DENIED, "SEC_E_LOGON_DENIED" },
    { SEC_E_UNKNOWN_CREDENTIALS, "SEC_E_UNKNOWN_CREDENTIALS" },
    { SEC_E_NO_CREDENTIALS, "SEC_E_NO_CREDENTIALS" },
    { SEC_E_NO_AUTHENTICATING_AUTHORITY, "SEC_E_NO_AUTHENTICATING_AUTHORITY" },
    { SEC_E_INCOMPLETE_MESSAGE, "SEC_E_INCOMPLETE_MESSAGE" }
};
#define nerrtab (sizeof errtab / sizeof errtab[0])

/* Prints a windows error code as readable text. */
void
errmsg(const char *msg, int status)
{
    static char buffer[16384];
    int i;
    const char *status_name = NULL;

    for (i = 0; i < nerrtab; i++)
	if (errtab[i].value == status) {
	    status_name = errtab[i].name;
	    break;
	}

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|   /* dwFlags */
		  FORMAT_MESSAGE_IGNORE_INSERTS,
		  0,                            /* lpSource */
		  status,                       /* dwMessageId */
		  0,                            /* dwLanguageId */
		  buffer,                       /* lpBuffer */
		  sizeof buffer,                /* nSize */
		  0);                           /* Arguments */
    if (status_name)
	fprintf(stderr, "%s: %s: %s\n", msg, status_name, buffer);
    else
        fprintf(stderr, "%s: 0x%x: %s\n", msg, status, buffer);
}
