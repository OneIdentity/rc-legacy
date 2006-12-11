/********************************************************************
* Copyright (c) 2005 Quest Software, Inc. 
* Portions of this code are derived from IBM Sample Programs, 
* (C) Copyright IBM Corp. 1997-2004.
* All rights reserved.
*
* Author:  Seth Ellsworth
*
* Company: Quest Software, Inc. 
*
* Purpose: Provide a LAM/PAM authentication security plug-in for 
*          DB2 8.2. 
*
* Legal:   This script is provided under the terms of the
*          "Vintela Resouce Central License" avaliable in
*          the included LICENSE file.
********************************************************************/

#ifndef LOG_H
#define LOG_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>

#include <unistd.h>
#include <sys/types.h>
#include <time.h>


/* The internal max line length includes room for a line
 * separator (CR/LF on Windows, LF on UNIX) and a NULL byte.
 */
#define MAX_LINE_LENGTH     1027

// Things that should log even if logging is turned off ( debug-level = 0 )
#define SLOG_CRIT   0

// Authentication requests only.
#define SLOG_NORMAL 1

// Error message from authentications.
#define SLOG_EXTEND 2

// Function calls starting.
// Debug stuff.
#define SLOG_DEBUG  3

// Anything else.
#define SLOG_ALL    4


void slog_init( );

void slog( int level, const char* msg, ... );

char *GetEntryFromFile( const char*, const char* );

#define func_start() slog( SLOG_DEBUG, "%s: starting", __FUNCTION__)

#define test_mem() if( vas_db2_plugin_test_memory( __FUNCTION__ ) ) \
                       return DB2SEC_PLUGIN_NOMEM

#endif
