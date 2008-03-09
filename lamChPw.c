/********************************************************************
* Copyright (c) 2007 Quest Software, Inc.
* All rights reserved.
*
* Author:  Seth Ellsworth
*
* Company: Quest Software, Inc.
*
* Purpose: Does a LAM password change for a user. Must be seteuid
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

const int MAX_LEN = 128;
static int debug = 0;
/* Returns: 
 * 0: Success
 * 1: Bad initial password
 * 2: Bad password change
*/

int lam_change_password( char *username, char *password_old, char *password_new ) {
    int first_time = 1;
    int reenter = 0;
    int retval = 0;
    char *authmsg = NULL;

    func_start();
    /* First, prep by sending just the username, no password. */
    retval = chpass( username, NULL, &reenter, &authmsg );
    if( debug )
    {
        fprintf( stderr, "%s: chpass returned <%d>, auth msg: <%s>\n", __FUNCTION__, retval, authmsg?authmsg:"<empty>" );
    }

    while( reenter )
    {
        /* First time, send the old password, then send the new password twice.
         * Well, its likely twice, but in fact it will be sent until it 
         * decideds it is done ( reenter == 0 ).
        */
        if( debug )
        {
            fprintf( stderr, "%s: auth msg: <%s>\n", __FUNCTION__, authmsg?authmsg:"<empty>" );
            fprintf( stderr, "%s: sending password %s\n", __FUNCTION__, first_time ? password_old : password_new );
        }
        retval = chpass( username, first_time ? password_old : password_new, &reenter, &authmsg );
        first_time = 0;

        if( debug )
        {
            fprintf( stderr, "%s: authenticate returned <%d>, reenter <%d> for user <%s> and msg <%s>\n", 
                  __FUNCTION__, retval, reenter, username, authmsg?authmsg:"<empty>" );
            fprintf( stderr, "%s:\n", __FUNCTION__ );
        }
    }
    if( retval == 0 )
	return 0;
    else
	return 2;	
}
 
int lam_auth_user( char *username, char *password ) {
    int reenter = 0;
    int retval = 0;
    char *authmsg = NULL;

    func_start();
    retval = authenticate( username, password, &reenter, &authmsg );
    slog( SLOG_EXTEND, "%s: authenticate returned <%d> for user <%s>",
          __FUNCTION__, retval, username );
    
    if( retval == 0 )
	return 0;
    else
	return 1;	
}
 
int main(int argc, char* argv[])
{
    int retval = 0;
    int rval = 0;
    struct passwd *pwd = NULL;
    char password_in[MAX_LEN];
    char password_old[MAX_LEN];
    char password_new[MAX_LEN];
    char *cptr = NULL;

    func_start();

    /* Check usage */
    if( argc != 2 )
    {
        fprintf( stderr, 
		"Usage: %s <name> (new/old password will be read from stdin).\n", 
		argv[0]);
        exit ( 1 );
    }

    if( getenv( "SETHS_DEBUG" ) )
        debug = 1;

    /* Check for user */
    if( ( pwd = getpwnam( argv[1] ) ) == NULL ) {
        fprintf( stderr, "ERROR: Unable to find user name %s!\n", argv[1] );
        slog( SLOG_EXTEND, "%s: unable to find user <%s>", __FUNCTION__, 
		argv[1] );
        exit( ENOENT );
    }

    /* Read passwords from stdin */
    /* They will be <oldpassword>\0<newpassword>\0 */
    if( ( rval = read(STDIN_FILENO, password_in, MAX_LEN) ) <= 0 )
    {
        fprintf( stderr, "error reading old password from std_in for user <%s>, errno <%d>\n", argv[1], errno );
        slog( SLOG_EXTEND, 
	    "%s: error reading old password from std_in for user <%s>, errno <%d>",
	    __FUNCTION__, argv[1], errno );
        exit( EIO );
    }

    /* Check and trim all \n's if present. */
    while( ( cptr = (char *)memchr( password_in,'\n', strlen(password_in) ) ) != NULL ) {
    	*cptr = '\0';
    }

    strncpy( password_old, password_in, MAX_LEN );
    cptr = &password_in[strlen(password_in)];
    /* Do this twice, jsut in case it came in <pw>\n\0<pw> */
    if( *cptr == '\0' )
        ++cptr;
    if( *cptr == '\0' )
        ++cptr;
    strncpy( password_new, cptr, MAX_LEN );
    
    /* Double check for \n's */
    while( ( cptr = (char *)memchr( password_old,'\n', strlen(password_old) ) ) != NULL ) {
    	*cptr = '\0';
    }

    /* Double check for \n's */
    while( ( cptr = (char *)memchr( password_new,'\n', strlen(password_new) ) ) != NULL ) {
    	*cptr = '\0';
    }

    /* First auth the user ( verify the old password ) */
    retval = lam_auth_user( argv[1], password_old );

    if( retval )
        exit( retval );

    /* Run the auth_user function. */
    if( setuid( pwd->pw_uid ) == 0 )
        retval = lam_change_password( argv[1], password_old, password_new );
    else
        retval = 1;

#if 0
    slog( SLOG_EXTEND, "%s: received return value <%d> from authentication "
	    "attempt for user <%s>", __FUNCTION__, retval, argv[1] );
#endif
    
    exit( retval );
}
