/********************************************************************
* Copyright (c) 2007 Quest Software, Inc.
* All rights reserved.
*
* Author:  Seth Ellsworth
*
* Company: Quest Software, Inc.
*
* Purpose: Does a LAM authenticate on a user. Must be given setuid 
*          root when run by non-root users.
*
* Legal:   This script is provided under the terms of the
*          "Resouce Central License" avaliable at
*          http://rc.vintela.com/topics/db2_sys-auth/license.php
*          or in the included LICENSE file.
********************************************************************/


#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usersec.h>

#include "config.h"
#include "log.h"

int lam_auth_user( char *username, char *password ) {
    int reenter = 0;
    int retval = 0;
    char *authmsg = NULL;

    func_start();
    do {
	retval = authenticate( username, password, &reenter, &authmsg );
	slog( SLOG_EXTEND, "%s: authenticate returned <%d> for user <%s>", 
	    __FUNCTION__, retval, username );
    } while (reenter);
    
    if( retval == 0 )
	return 0;
    else
	return 1;	
}
 
int main(int argc, char* argv[])
{
    int retval;
    struct passwd *pwd = NULL;
    char password[128];
    char *cptr = NULL;

    func_start();

    /* Check usage */
    if( argc != 2 )
    {
        fprintf( stderr, 
		"Usage: %s <name> (password will be read from stdin).\n", 
		argv[0]);
        exit ( 1 );
    }

    /* Check for user */
    if( ( pwd = getpwnam( argv[1] ) ) == NULL ) {
        fprintf( stderr, "ERROR: Unable to find user name %s!\n", argv[1] );
        slog( SLOG_EXTEND, "%s: unable to find user <%s>", __FUNCTION__, 
		argv[1] );
        exit( ENOENT );
    }

    /* Read password from stdin */
    if( read(STDIN_FILENO, password, 128) <= 0 )
    {
        slog( SLOG_EXTEND, 
	    "%s: error reading password from std_in for user <%s>, errno <%d>",
	    __FUNCTION__, argv[1], errno );
        exit( EIO );
    }

    /* Check and trim \n if present. */
    if( ( cptr = (char *)memchr( password,'\n', strlen(password) ) ) != NULL ) {
	*cptr = '\0';
    }

    /* Run the auth_user function. */
    retval = lam_auth_user( argv[1], password );

#if 0
    slog( SLOG_EXTEND, "%s: received return value <%d> from authentication "
	    "attempt for user <%s>", __FUNCTION__, retval, argv[1] );
#endif
    
    exit( retval );
}
