/* (c) 2009 Quest Software, Inc. All rights reserved */

#include <stdio.h>
#include <windows.h>
#include "errmsg.h"

/* Prints a windows error code as readable text. */
void
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
