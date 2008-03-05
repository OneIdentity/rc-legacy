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
#include <pwd.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
 
/* Define process exit codes */
#define PASSWORD_OK       0                    /* Password is valid          */
#define BAD_PASSWORD      1                    /* Invalid password provided  */
#define SYSTEM_ERROR      2                    /* Undefined system error     */
#define OTHER_ERROR       3                    /* All other errors           */

#define MAXLINE 610

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

    /* Start pam, using the defined service. */
    if ( ( retval = pam_start( EXAMPLE_PAM_SERVICE_NAME, name, &conv, &pamh ) ) != PAM_SUCCESS ) {
        return retval;
    }

    /* Set the password for the conversation. */
    pw = password;
    /* The actual authentication. */
    retval = pam_authenticate(pamh, 0);

    /* Clear off the pw pointer*/
    pw = NULL;

    return retval;
}

int main(int argc, char *argv[])
{
    char userid[MAXLINE + 1] = {'\0'};
    char password[MAXLINE + 1]={'\0'};
    int rc = BAD_PASSWORD;
    int rval = PAM_AUTH_ERR;
           
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
        fprintf( stderr, "%s: failed, bytesRead: <%d>\n", __FUNCTION__, bytesRead );

        rc = OTHER_ERROR;
        goto exit;
    }
    else
        fprintf( stderr, "%s: bytesRead: <%d>\n", __FUNCTION__, bytesRead );
                    
    cLine[ bytesRead ] = '\0' ;
                      
    strncpy( userid, cLine, sizeof( userid ) ) ;
    userid[ MAXLINE ] = '\0' ;
                          
    pszPassword = cLine + strlen( cLine ) + 1 ;
    strncpy( password, pszPassword, sizeof( password ) ) ;
    password[ MAXLINE ] = '\0' ;
   
/*    fprintf( stderr, "%s: using userid: <%s> password: <%s>\n", __FUNCTION__, userid, password );
*/
    
    /* TBD : Do your stuff - verify the password and userid using your */
    /*       own means.                                                */
    rval = pam_auth_user( userid, password );
/*    fprintf( stderr, "%s: rval: <%d>\n", __FUNCTION__, rval ); 
*/
    if ( rval == PAM_SUCCESS )
    {
        rc = PASSWORD_OK;
    }
    else if ( rval == PAM_AUTH_ERR )
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
