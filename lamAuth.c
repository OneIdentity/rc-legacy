/********************************************************************
* Copyright (c) 2005 Quest Software, Inc.
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
*          "Vintela Resouce Central License" avaliable in
*          the included LICENSE file.
********************************************************************/


#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usersec.h>

#include "config.h"

void _log(char * funct, const char * msg){
#if SHOW_ERROR
        char buff[1028];
        FILE * file = fopen("/tmp/sys-auth.log", "aw");
        if( file == NULL )
                        return;
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
        if( file == NULL )
            return;
        fprintf( file, "Function Name: %s, Number: %d\n", funct, num);
        fclose( file );
#endif
}

#define logd(num) _logd(__FUNCTION__, num)
#define log(msg) _log(__FUNCTION__, msg)
#define func_start() log("Started!")

int lam_auth_user( char *username, char *password ) {
	int reenter = 0;
	int retval = 0;
	char *authmsg = NULL;

	func_start();
	do {
		retval = authenticate( username, password, &reenter, &authmsg );
		if( authmsg != NULL ) log( authmsg );
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
		*cptr = '\0';
	}

	log( "Password:" );
	log( password );

        /* Run the auth_user function. */
        retval = lam_auth_user( argv[1], password );

	log( "Return val:" );
	logd( retval );

        exit( retval );
}
