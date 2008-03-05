/********************************************************************
* (c) 2007 Quest Software, Inc. All rights reserved.
* All rights reserved.
*
* Author:  Seth Ellsworth
* 
* Company: Quest Software, Inc.
* 
* Purpose: Authenticate a username/password through PAM
*
* Notes:   Change to use the wanted serivce, uses sys-auth<bits> right now.
*          If you get a warning on line 71, probably means you need
*          to set the OS correctly in the Makefile.
*
* Legal:   This script is provided under the terms of the
*          "Resouce Central License" avaliable at
*          http://rc.vintela.com/topics/db2_sys-auth/license.php
*          or in the included LICENSE file.
********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "log.h"

#if defined(__64BIT__)
#define EXAMPLE_PAM_SERVICE_NAME "sys-auth64"
#else
#define EXAMPLE_PAM_SERVICE_NAME "sys-auth32"
#endif	

static const char* pw = NULL;

static int conversation( int num_msg,
#if defined(SOLARIS) || defined(AIX) 
                         struct pam_message** msg,
#else
                         const struct pam_message** msg,
#endif
                         struct pam_response** resp,
                         void *appdata_ptr )
{
    int i = 0;

    /* malloc the replies, PAM owns this memory */
    *resp = malloc( num_msg * sizeof(struct pam_response) );
    memset( *resp, 0, num_msg * sizeof(struct pam_response) );

    /* TODO: make this interactive */
    for( i = 0; i < num_msg; i++ )
    {
        if( msg[i]->msg_style == PAM_PROMPT_ECHO_OFF )
            (*resp)[i].resp = (char*)strdup( pw );
    }

    return PAM_SUCCESS;
}



/* Doing the actual work, through use of pam conversations               *
 * Uses the static variable pw to pass the password to the conversation. *
 * Returns 0 on success, or a pam error on failure.                      */
int pam_auth_user( const char *name, const char *password ) {
	struct pam_conv conv = { conversation, NULL };
	int retval;
	pam_handle_t *pamh = NULL;
    int retval_b;

	func_start();
	/* Start pam, using the defined service. */
	if ( ( retval = pam_start( EXAMPLE_PAM_SERVICE_NAME, name, &conv, &pamh ) ) != PAM_SUCCESS ) {
        slog( SLOG_EXTEND, "%s: pam_start failed, returned <%d>", __FUNCTION__, retval );
		return retval;
	}

	/* Set the password for the conversation. */
	pw = password;
	/* The actual authentication. */
	retval = pam_authenticate(pamh, 0); 
	
	/* Clear off the pw pointer*/
	pw = NULL;
    slog( SLOG_DEBUG, "%s: received return value <%d> from authentication attempt for user <%s>", __FUNCTION__, retval, name );

    retval_b = pam_acct_mgmt( pamh, 0 );

    pam_end( pamh, retval_b );

    if( ( retval == PAM_AUTH_ERR && retval_b == PAM_NEW_AUTHTOK_REQD ) || 
        ( retval == PAM_SUCCESS && retval_b == PAM_NEW_AUTHTOK_REQD ) )
        retval = 4;
    else if( retval == PAM_SUCCESS )
        retval = 0;
    else if( retval == PAM_AUTH_ERR )
        retval = 1;
    else 
        retval = 7;

	return retval;
}

int main(int argc, char* argv[])
{
        int retval, retval_a, retval_m, result = 0;
        struct passwd *pwd = NULL;
        char password[128];
        char *cptr = NULL;

        func_start();

        /* Check usage */
        if( argc != 2 )
        {
                fprintf( stderr, "Usage: %s <name> (password will be read from stdin).\n", argv[0]);
                exit ( 1 );
        }

        /* Check for user */
        if( ( pwd = getpwnam( argv[1] ) ) == NULL ) {
                fprintf( stderr, "ERROR: Unable to find user name %s!\n", argv[1] );
                slog( SLOG_EXTEND, "%s: unable to find user <%s>", __FUNCTION__, argv[1] );
                exit( ENOENT );
        }

        /* Read password from stdin */
        if( ( result = read(STDIN_FILENO, password, 128) ) <= 0 )
        {
                slog( SLOG_EXTEND, "%s: error reading password from std_in for user <%s>, errno <%d>", __FUNCTION__, argv[1], errno );
                exit( EIO );
        }
        password[result] = '\0';

        /* Check and trim \n if present. */
        if(  ( cptr = (char *)memchr( password,'\n', strlen(password) ) ) != NULL ) {
                *cptr = '\0';
        }

        /* Run the auth_user function. */
        retval = pam_auth_user( argv[1], password );
    
        
        exit( retval );
}

