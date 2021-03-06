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
#define EXAMPLE_PAM_SERVICE_NAME "sys-auth"
#else
#define EXAMPLE_PAM_SERVICE_NAME "sys-auth"
#endif	

const int MAX_LEN = 128;

/* Returns: 
 * 0: Success
 * 1: Bad initial password
 * 2: Bad password change
*/

static const char* pw_old = NULL;

static const char* pw_new = NULL;

static int debug = 0;

static int auth_conv( int num_msg,
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
            (*resp)[i].resp = (char*)strdup( pw_old );
    }

    return PAM_SUCCESS;
}

static int state = 0;

static int chpw_conv( int num_msg,
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
        if( debug )
            fprintf( stderr, "msg: <%s> style:<%d> pw_old:<%s> pw_new:<%s> state:<%d>\n", msg[i]->msg, msg[i]->msg_style, pw_old, pw_new, state );
        if( msg[i]->msg_style == PAM_PROMPT_ECHO_OFF )
        {
            
            if( debug )
                fprintf( stderr, "returning: <%s>\n", state == 0 ? pw_old : pw_new );
            (*resp)[i].resp = (char*)strdup( state == 0 ? pw_old : pw_new );
            ++state;
        }
    }

    return PAM_SUCCESS;
}



/* Doing the actual work, through use of pam conversations               *
 * Uses the static variable pw to pass the password to the conversation. *
 * Returns 0 on success, or a pam error on failure.                      */
int pam_change_password( const char *name, const char *password_old, char *password_new ) {
	struct pam_conv conv = { chpw_conv, NULL };
	int retval;
	pam_handle_t *pamh = NULL;

	func_start();
	/* Start pam, using the defined service. */
	if ( ( retval = pam_start( EXAMPLE_PAM_SERVICE_NAME, name, &conv, &pamh ) ) != PAM_SUCCESS ) {
        slog( SLOG_EXTEND, "%s: pam_start failed, returned <%d>", __FUNCTION__, retval );
		return retval;
	}

	/* Set the password for the conversation. */
	pw_old = password_old;
	pw_new = password_new;
	/* The actual authentication. */
//    pam_set_item( pamh, PAM_OLDAUTHTOK, pw_new);
//    pam_set_item( pamh, PAM_AUTHTOK, pw_new);
    if( debug )
        fprintf( stderr, "getuid()<%d> geteuid()<%d>\n", getuid(), geteuid() );
	retval = pam_chauthtok(pamh, 0); 

    pam_end( pamh, retval );
	
	/* Clear off the pw pointer*/
	pw_old = NULL;
	pw_new = NULL;
    slog( SLOG_DEBUG, "%s: received return value <%d> from chauthtok attempt for user <%s>", __FUNCTION__, retval, name );
    if( debug )
        fprintf( stderr , "%s: received return value <%d> from chauthtok attempt for user <%s>\n", __FUNCTION__, retval, name );

    /* On HP, if it failed and the machine doesn't have pam requisite patch, 
     * pam_unix will return user unknown, so default back to this, we know the
     * user exists because it got past the auth. */
    if( retval == PAM_USER_UNKNOWN )
    {
        retval = PAM_AUTHTOK_ERR;
        if( debug )
            fprintf( stderr , "%s: changing retval to <%d>\n", __FUNCTION__, retval );
    }

	return retval;
}

/* Doing the actual work, through use of pam conversations               *
 * Uses the static variable pw to pass the password to the conversation. *
 * Returns 0 on success, or a pam error on failure.                      */
int pam_auth_user( const char *name, const char *password ) {
	struct pam_conv conv = { auth_conv, NULL };
	int retval, retval_b;
	pam_handle_t *pamh = NULL;

	func_start();
	/* Start pam, using the defined service. */
	if ( ( retval = pam_start( EXAMPLE_PAM_SERVICE_NAME, name, &conv, &pamh ) ) != PAM_SUCCESS ) {
        slog( SLOG_EXTEND, "%s: pam_start failed, returned <%d>", __FUNCTION__, retval );
		return retval;
	}

	/* Set the password for the conversation. */
	pw_old = password;
	/* The actual authentication. */
	retval = pam_authenticate(pamh, 0); 

    retval_b = pam_acct_mgmt( pamh, 0 );

    pam_end( pamh, retval_b );
	
	/* Clear off the pw pointer*/
	pw_old = NULL;
    slog( SLOG_DEBUG, "%s: received return value <%d> from authentication attempt for user <%s>", __FUNCTION__, retval, name );

    if( ( retval == PAM_AUTH_ERR && retval_b == PAM_NEW_AUTHTOK_REQD ) ||
        ( retval == PAM_SUCCESS && retval_b == PAM_NEW_AUTHTOK_REQD ) )
        retval = PAM_NEW_AUTHTOK_REQD;

	return retval;
}

void _lower( char *name ) {
    char * cptr = NULL;
    int count = 0;
    while( name[count] != '\0' ) {
        name[count] = tolower(name[count]);
        ++count;
    }
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
    char userBuffer[MAX_LINE_LENGTH];

    func_start();

    /* Check usage */
    if( argc != 2 )
    {
        fprintf( stderr, 
		"Usage: %s <name> (new/old password will be read from stdin).\n", 
		argv[0]);
        exit ( EINVAL );
    }

    if( getenv( "SETHS_DEBUG" ) )
        debug = 1;

    memset(userBuffer, '\0', MAX_LINE_LENGTH);

    strcpy( userBuffer, argv[1] );

    /* Check for user */
    if( ( pwd = getpwnam( userBuffer ) ) == NULL ) {
        _lower( userBuffer );
        if( ( pwd = getpwnam( userBuffer ) ) == NULL ) {
            slog( SLOG_EXTEND, "%s: unable to find user <%s>", __FUNCTION__, argv[1] );
            fprintf( stdout, "3\n", retval );
            exit( 3 );
        }
    }


    /* Read passwords from stdin */
    /* They will be <oldpassword>\0<newpassword>\0 */
    if( ( rval = read(STDIN_FILENO, password_in, MAX_LEN) ) <= 0 )
    {
        fprintf( stderr, "error reading old password from std_in for user <%s>, errno <%d>\n", userBuffer, errno );
        slog( SLOG_EXTEND, 
	    "%s: error reading old password from std_in for user <%s>, errno <%d>",
	    __FUNCTION__, userBuffer, errno );
        fprintf( stdout, "%d\n", EIO);
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
    retval = pam_auth_user( userBuffer, password_old );

    if( retval && retval != PAM_NEW_AUTHTOK_REQD )
        goto FINISHED;

    /* Run the auth_user function. */
//    if( setuid( pwd->pw_uid ) == 0 )
    retval = pam_change_password( userBuffer, password_old, password_new );
 //   else
//        retval = PAM_USER_UNKNOWN;

#if 0
    slog( SLOG_EXTEND, "%s: received return value <%d> from authentication "
	    "attempt for user <%s>", __FUNCTION__, retval, argv[1] );
#endif

    /*
    case 1:
    retval = DB2SEC_PLUGIN_BADPWD;
    break;
    case 2:
    retval = DB2SEC_PLUGIN_BAD_NEWPASSWORD;
    break;
    case 3:
    retval = DB2SEC_PLUGIN_BADUSER;
    break;
    case 4:
    retval = DB2SEC_PLUGIN_PWD_EXPIRED;
    break;
    default:
    retval = DB2SEC_PLUGIN_UNKNOWNERROR;
    */
    
FINISHED:
    if( retval == PAM_SUCCESS )
    {
        retval = 0;
    }
    else if( retval == PAM_AUTH_ERR )
    {
        retval = 1;
    }
    else if( retval == PAM_MAXTRIES || retval == PAM_AUTHTOK_ERR )
    {
        retval = 2;
    }
    else if( retval == PAM_USER_UNKNOWN )
    {
        retval = 3;
    }
    else if( retval == PAM_NEW_AUTHTOK_REQD )
    {
        retval = 4;
    }
    else
    {
        retval = 5;
    }

    fprintf( stdout, "%d\n", retval );

    exit( retval );
}
