/********************************************************************
* Copyright (c) 2005 Vintela, Inc.
* All rights reserved.
*
* Author:  Seth Ellsworth
* 
* Company: Vintela, Inc.
* 
* Purpose: Try a user/pw against PAM.
*
* Notes:   Change to use the wanted serivce, uses OTHER right now.
*          If you get a warning on line 71, probably means you need
*          to set the OS correctly in the Makefile.
*
* Legal:   This script is provided under the terms of the 
*          "Vintela Resouce Central License" avaliable at
*          http://rc.vintela.com/topics/openssh/license.php#vintela
********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "config.h"

void _log(char * funct, const char * msg){
#if SHOW_ERROR
        char buff[1028];
        FILE * file = fopen("/tmp/sys-auth.log", "aw");
        strcpy( buff, "Function Name: " );
        strcat( buff, funct );
        strcat( buff, ", Message: " );
        strcat( buff, msg );
        fputs( buff, file );
        fputc( '\n', file );
        fclose( file );
#endif
}


void _logd( char * funct, const int num ){
#if SHOW_ERROR
        if( !SHOW_ERROR ) return;
        char buff[1028];
        FILE * file = fopen("/tmp/sys-auth.log", "aw");
        fprintf( file, "Function Name: %s, Number: %d\n", funct, num);
        fclose( file );
#endif
}

#define logd(num) _logd((char*)__FUNCTION__, num)
#define log(msg) _log((char*)__FUNCTION__, msg)
#define func_start() log("Started!")

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

	func_start();
	/* Start pam, using the defined service. */
	if ( ( retval = pam_start( EXAMPLE_PAM_SERVICE_NAME, name, &conv, &pamh ) ) != PAM_SUCCESS ) {
		log( "Failed to run pam_start." );
		return retval;
	}
	log( "PAM started." );

	/* Set the password for the conversation. */
	pw = password;
	/* The actual authentication. */
	if ( ( retval = pam_authenticate(pamh, 0) ) != PAM_SUCCESS ) {
		return retval;
	}
	
	/* Clear off the pw */
	pw = NULL;

	return 0;
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
                fprintf( stderr, "Usage: %s <name> (password will be read from stdin).\n", argv[0]);
                exit ( 1 );
        }

        /* Check for user */
        if( ( pwd = getpwnam( argv[1] ) ) == NULL ) {
                fprintf( stderr, "ERROR: Unable to find user name %s!\n", argv[1] );
                exit( ENOENT );
        }

        log( "User:" );
        log( argv[1] );

        /* Read password from stdin */
        if( read(STDIN_FILENO, password, 128) <= 0 )
                exit( EIO );

        /* Check and trim \n if present. */
        if(  ( cptr = (char *)memchr( password,'\n', strlen(password) ) ) != NULL ) {
                log( "Found a '\\n'." );
		log( "Passowrd, before:" );
		log( password );
                *cptr = '\0';
        }

        log( "Password:" );
        log( password );

        /* Run the auth_user function. */
        retval = pam_auth_user( argv[1], password );

        log( "Return val:" );
        logd( retval );

        exit( retval );
}

