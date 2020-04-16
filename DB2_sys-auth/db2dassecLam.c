/*-------------------------------------------------------------------------*/
/* SAMPLE CODE TO IMPLEMENT YOUR OWN AUTHENTICATION MECHANISM.             */
/* DISCLAIMERS :                                                           */
/*   - this will NOT compile as is                                         */
/*   - this is not warranted in any way                                    */
/*   - IBM is not responsible for this program in any way                  */
/*   - the interface illustrated herein may change in future DB2 versions  */
/* INSTRUCTIONS :                                                          */
/*  1) Fill out the "TBD" portions of the program.                         */
/*  2) Build it.                                                           */
/*  3) db2stop                                                             */
/*  4) Place the resulting executable in das/adm/db2dassec and make it     */
/*     a setuid-root program (if req'd by your authentication mechanism.)  */
/*  5) db2start                                                            */
/*-------------------------------------------------------------------------*/
 
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <usersec.h>
 
/* Define process exit codes */
#define PASSWORD_OK       0                    /* Password is valid          */
#define BAD_PASSWORD      1                    /* Invalid password provided  */
#define SYSTEM_ERROR      2                    /* Undefined system error     */
#define OTHER_ERROR       3                    /* All other errors           */

#define MAXLINE 610

int lam_auth_user( char *username, char *password ) 
{
    int reenter = 0;
    int retval = 0;
    char *authmsg = NULL;

    do {
        retval = authenticate( username, password, &reenter, &authmsg );
    } while (reenter);

    if( retval == 0 )
        return 0;
    else
        return 1;
}

int main(int argc, char *argv[])
{
    char userid[MAXLINE + 1] = {'\0'};
    char password[MAXLINE + 1]={'\0'};
    int rc = BAD_PASSWORD;
    int rval = 1;
           
    /* Argv[1] is the file descriptor number for a pipe on which */
    /* the parent will write the userid and password.            */
           
    char cLine[MAXLINE + 1]={'\0'};
    char *pszPassword = NULL ;

    /* Check usage */
    if( argc != 2 )
    {
        fprintf( stderr, "Usage: %s <file descripter number to read from> (userid/password will be read from that descriptor).\n", argv[0]);
        exit ( 1 );
    }
                
    int bytesRead = read(atol(argv[1]), cLine, MAXLINE); 
    if ( bytesRead != MAXLINE )
    {
        rc = OTHER_ERROR;
        goto exit;
    }
                    
    cLine[ bytesRead ] = '\0' ;
                      
    strncpy( userid, cLine, sizeof( userid ) ) ;
    userid[ MAXLINE ] = '\0' ;
                          
    pszPassword = cLine + strlen( cLine ) + 1 ;
    strncpy( password, pszPassword, sizeof( password ) ) ;
    password[ MAXLINE ] = '\0' ;
                                
    /* TBD : Do your stuff - verify the password and userid using your */
    /*       own means.                                                */
    rval = lam_auth_user( userid, password );
    if ( rval == 0 )
    {
        rc = PASSWORD_OK;
    }
    else if ( rval == 1 )
    {
        rc = BAD_PASSWORD;
    }
    else
    {
        rc = OTHER_ERROR;
    }

exit:
    exit(rc);
}
