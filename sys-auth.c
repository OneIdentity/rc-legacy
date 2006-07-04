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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>

#include "sqlenv.h"
#include "db2secPlugin.h"

#include "config.h"

#include <unistd.h>
#include <sys/types.h>

static const char * const CONF_FILE = "/etc/sys-auth.conf";

/* The internal max line length includes room for a line
 * separator (CR/LF on Windows, LF on UNIX) and a NULL byte.
 */
#define MAX_LINE_LENGTH     1027

// Authentication requests only.
#define SLOG_NORMAL 1

// Error message from authentications.
#define SLOG_EXTEND 2

// Function calls starting.
// Debug stuff.
#define SLOG_DEBUG  3

// Anything else.
#define SLOG_ALL    4

static int G_log_init  = -1;
static int G_log_level = -1;
static int G_log_to_syslog = -1;

void slog_init( )
{
    FILE *f;
    char buf[MAX_LINE_LENGTH];
    
    if( G_log_init != -1 )
        return;
    
    f = fopen( CONF_FILE, "r" );
    if( f == NULL )
    {
        G_log_level = SLOG_NORMAL;
        G_log_to_syslog = 1;
        return;
    }

    while( fgets( buf, MAX_LINE_LENGTH, f ) )
    {
        int lvl = 0;
        if( sscanf( buf, "debug-level = %1i", &lvl ) )
        {
            if( lvl < SLOG_NORMAL || lvl > SLOG_ALL )
                G_log_level = SLOG_NORMAL;
            else
                G_log_level = lvl;
            break;
        }   
    }
    fclose( f );

    if( G_log_to_syslog )
    {
        openlog( "sys-auth", LOG_PID, LOG_DAEMON );
    }
}

void slog( int level, const char* msg, ... )
{
    slog_init();
    if( level > G_log_level )
        return;
    syslog( 0, msg );
}

#define func_start() slog( SLOG_EXTEND, "%s: starting", __FUNCTION__)

db2secLogMessage *logFunc = NULL;


#define SUCCESS 1
#define FAILURE 0

#define MAX_C_BUFF 512

/********************************************************************
 * Helper functions.
 *******************************************************************/

void lower( char *username ) {
    char * cptr = NULL;
    int count = 0;
    slog( SLOG_ALL, "%s: lowering <%s>", __FUNCTION__ );
    while( username[count] != '\0' ) {
        username[count] = tolower(username[count]);
        ++count;
    }
}

sig_atomic_t sigt = 0;

void sigHandle( int signo ) {
    if( signo == SIGCHLD )
        sigt = 1;
    return;
}

int authUser(char *username, char *password) {
    int   retval   = 0;
    int   status   = 0;
    pid_t pid      = 0;
    struct sigaction sigact;
    struct sigaction osigact;
    int stdin_fds[] = { -1, -1 };
    char prog_path[MAX_C_BUFF];
    char prog_file[MAX_C_BUFF];
    char *cptr = NULL;
    struct passwd *pwd = NULL;
    
    func_start();

    memset(&sigact, 0, sizeof(sigact));
    memset(&osigact, 0, sizeof(osigact));

    sigact.sa_handler = sigHandle;

    sigaction(SIGCHLD, &sigact, &osigact);

    errno = 0;


    if ( pipe( stdin_fds ) != 0 ) { 
        retval = errno;
        slog( SLOG_NORMAL, "%s: Pipe failed!", __FUNCTION__ );
        goto EXIT;
    }
        
    if( ( pid = fork() ) == 0 ) /* Child Process */
    {
        slog( SLOG_DEBUG, "%s: child process with pid %d", __FUNCTION__, getpid() );
        
        close( stdin_fds[1] );
        if( dup2( stdin_fds[0], STDIN_FILENO ) != STDIN_FILENO )
        {
            slog( SLOG_NORMAL, "%s: dup2 failed, errno %d", __FUNCTION__, errno );
            retval = errno;
            goto EXIT;
        }
        close( stdin_fds[0] );


        if( ( cptr = getenv("DB2INSTANCE") ) == NULL ) 
        {
            slog( SLOG_NORMAL, "%s: Unable to obtain DB2INSTANCE environment variable", __FUNCTION__ );
            _exit( EFAULT );
        }
        if( ( pwd = getpwnam( cptr ) ) == NULL ) 
        {
            slog( SLOG_NORMAL, "%s: unable to obtain DB2INSTANCE <%s> user information", __FUNCTION__, cptr );
            _exit( EFAULT );
        }
        cptr = pwd->pw_dir; 
        slog( SLOG_DEBUG, "%s: found directory <%s>", __FUNCTION__, cptr );
        
        strncpy( prog_path, cptr, MAX_C_BUFF);

        strcat( prog_path, "/sqllib/security" );
#ifdef __64BIT__
        strcat( prog_path, "64/plugin/sys-auth64" );
        strcpy( prog_file, "sys-auth64" );
#else    
        strcat( prog_path, "32/plugin/sys-auth32" );
        strcpy( prog_file, "sys-auth32" );
#endif

        slog( SLOG_DEBUG, "%s: executing program <%s> from path <%s>", __FUNCTION__, prog_file, prog_path );

        if( execl( prog_path, prog_file, username, NULL ) == -1 ) 
        {
            slog( SLOG_NORMAL, "%s: execl failed with errno <%s>", __FUNCTION__, errno ? errno : ECHILD );
            _exit( errno ? errno : ECHILD );
        }
    } 
    else if ( pid < 0 ) /* Fork failed */
    {        
            slog( SLOG_NORMAL, "%s: Fork Failed!", __FUNCTION__ );
            retval = 1;
            goto EXIT;
    } 
    else  /* Parent Process */
    {
        FILE *stream;

        close( stdin_fds[0] );
        slog( SLOG_ALL, "%s: sending password to child process", __FUNCTION__ );
        stream = fdopen (stdin_fds[1], "w");
        fprintf( stream, "%s%c", password, '\0' );
        fflush( stream );
        slog( SLOG_ALL, "%s: password sent", __FUNCTION__ );
        slog( SLOG_DEBUG, "%s: parent process <%d> waiting for child process <%d>", __FUNCTION__, getpid(), (int)pid );
        while( ( retval = waitpid( pid, &status, 0 ) ) == -1 )  
        {
            if( errno == EINTR ) { 
                if( sigt == 1 )
                    continue;
            } 
            break;
        }
        close( stdin_fds[1] );
        slog( SLOG_DEBUG, "%s: child process returned with value <%d>", __FUNCTION__, retval );
        sigaction(SIGCHLD, &osigact, NULL);
    }

    if( retval == -1 )
        goto EXIT;
    if( WEXITSTATUS(status) == 0 )
        retval = 0;

EXIT:
        if( retval == 0 ) {
                slog( SLOG_NORMAL, "%s: Successful authentication attempt for user <%s>", __FUNCTION__, username );
                return SUCCESS;
        } else {
                if( G_log_level > SLOG_NORMAL )
                    slog( SLOG_EXTEND, "%s: Failed authentication attempt for user <%s>, error <%d>", __FUNCTION__, username, retval );
                return FAILURE;
        }
}

int checkUser( const char* username ) {
    struct passwd *pwd = NULL;
    int retval = FAILURE;

    func_start();
    slog( SLOG_DEBUG, "%s: checking user <%s>", __FUNCTION__, username );
    if( ( pwd = (struct passwd*)getpwnam(username) ) == NULL ) {
        slog( SLOG_DEBUG, "%s: user <%s> not found", __FUNCTION__, username );
        errno = ENOENT;
        return FAILURE;
    }
    slog( SLOG_DEBUG, "%s: found user <%s>", __FUNCTION__, username );
    return SUCCESS;
}

int checkGroup( const char* groupname) {
    struct group *grp= NULL;
    int retval = FAILURE;

    func_start();
    slog( SLOG_DEBUG, "%s: checking group <%s>", __FUNCTION__, groupname );
    if( ( grp = (struct group*)getgrnam(groupname) ) == NULL ) {
        slog( SLOG_EXTEND, "%s: group <%s> not found", __FUNCTION__, groupname );
        errno = ENOENT;
        return FAILURE;
    }
    slog( SLOG_DEBUG, "%s: found group <%s>", __FUNCTION__, groupname );
    return SUCCESS;
}

int isUserInGroup( const char* username, struct group *grp ){
    int retval = FAILURE;
    struct passwd *pwd = NULL;
    char **members = NULL;

    func_start();

    if( grp == NULL ) {
        slog( SLOG_ALL, "%s: this should never happen, but called with a NULL group struct. ", __FUNCTION__ );
        return FAILURE;
    }
    slog( SLOG_DEBUG, "%s: checking group <%s> for user <%s>", __FUNCTION__, grp->gr_name, username );

    if( grp->gr_mem == NULL ){
        slog( SLOG_ALL, "%s: group has no members", __FUNCTION__ );
        return FAILURE;
    }

    members = grp->gr_mem;

    while( *members && ( retval != SUCCESS ) ) 
    {
        if( strcmp(username, *members) == 0 )
            retval = SUCCESS;
        ++members;
    }    

    if( retval == SUCCESS )
    {
        slog( SLOG_DEBUG, "%s: user <%s> is in group <%s>", __FUNCTION__, username, grp->gr_name );
    }
    else
    {// Add check for user-gid == group gid.    
        if( ( pwd = (struct passwd*)getpwnam(username) ) == NULL ) {
            slog( SLOG_DEBUG, "%s: user <%s> not found", __FUNCTION__, username );
            errno = ENOENT;
            return FAILURE;
        }
        if( pwd->pw_gid == grp->gr_gid )
        {
            // User has GID membership.
            slog( SLOG_DEBUG, "%s: user <%s> has group membership in <%s> through implicit pgid->gid.", __FUNCTION__, username, grp->gr_name );
            retval = SUCCESS;
        }
        else
        {
            slog( SLOG_DEBUG, "%s: user <%s> is not in group <%s>", __FUNCTION__, username, grp->gr_name );
        }
    }
    return retval;
}

int FindGroupsForUser( const char* username, char *groups, int *numgroups ) {
    struct group *grp = NULL;
    char * cptr = NULL;
    char *grset = NULL;
    char *gr = NULL;
    char delims[] = ",";
    char userBuffer[MAX_LINE_LENGTH];
    int gid;
    int groupcount = 0;
    int length = 0;
    memset(userBuffer, '\0', MAX_LINE_LENGTH);
    func_start();
    strcpy( userBuffer, username );
    lower( userBuffer );
    if( checkUser( userBuffer ) != SUCCESS )
        return -1;

#ifdef AIX
    /* Since we are on AIX, we can use getgrset. Get that, tokenize the 
     * result, and add to the buffer as the group resolves to names. 
     */
    if( ( grset = getgrset( userBuffer ) ) == NULL ) {
        return DB2SEC_PLUGIN_UNKNOWNERROR;    
    } 
    slog( SLOG_ALL, "%s: on AIX, using getgrset", __FUNCTION__ );
    slog( SLOG_DEBUG, "%s: getgrset returned <%s>", __FUNCTION__, grset );
    cptr = groups;
    gr = strtok( grset, delims );
    while( gr != NULL ) {
        if( ( grp = getgrgid( atoi( gr ) ) ) != NULL ) 
        {
            length = strlen( grp->gr_name );
            *((unsigned char*)cptr) = (unsigned char)length;
            ++cptr;
            memcpy(cptr, grp->gr_name, length );
            cptr += length;
            ++groupcount;
        }
        gr = strtok( NULL, delims );
    }
    *cptr = '\0';
    if(grset)
        free(grset);    
#else
    setgrent();
    cptr = groups;
    slog( SLOG_ALL, "%s: non-AIX, using getgrent cycle", __FUNCTION__ );
    while( ( grp = getgrent() ) != NULL ) {
        if( ( isUserInGroup( userBuffer, grp ) ) == SUCCESS ) {
            length = strlen( grp->gr_name );
            *((unsigned char*)cptr) = (unsigned char)length;
            ++cptr;
            memcpy(cptr, grp->gr_name, length );
            cptr += length;
            ++groupcount;
        }
    }
    *cptr = '\0';
    endgrent();
#endif

    *numgroups = groupcount;
    slog( SLOG_DEBUG, "%s: returning group string <%s>", __FUNCTION__, groups );
    return 0;
}





/*-------------------------------------------------------
 * Plugin functions
 *-------------------------------------------------------*/

/* CheckPassword()
 * Look up a user, check their password.
 *
 * If a domain name ("namespace") is specified it is appended to
 * the userid with an "@" separator (userid@domain) and that string
 * is then used for the file lookup.
 *
 * The maximum length for the userid (or userid@domain) is
 * SQL_AUTHID_SZ, since it will be returned as the DB2 Authorization
 * ID later.
 */
SQL_API_RC SQL_API_FN CheckPassword(const char *userid,
                         db2int32 useridLength,
                         const char *domain,
                         db2int32 domainLength,
                         db2int32 domainType,           /* ignored */
                         const char *password,
                         db2int32 passwordLength,
                         const char *newPassword,
                         db2int32 newPasswordLength,
                         const char *databaseName,      /* not used */
                         db2int32 databaseNameLength,   /* not used */
                         db2Uint32 connection_details,
                         void **token,                  /* not used */
                         char **errorMessage,
                         db2int32 *errorMessageLength)
{
    int rc = DB2SEC_PLUGIN_OK;
    int length;

    char user[SQL_AUTHID_SZ + 1];       /* User name (possibly with @domain) */

    char *cptr;

    *errorMessage = NULL;
    *errorMessageLength = 0;
    func_start();

    memset(user, '\0', SQL_AUTHID_SZ + 1);

    if ( useridLength > SQL_AUTHID_SZ )
    {
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }
    strncpy(user, userid, useridLength);

    slog( SLOG_NORMAL, "%s: Authentication attempt for user %s", __FUNCTION__, user );
    /* Was a new password supplied? */
    if (newPassword != NULL && newPasswordLength > 0)
    {
        slog( SLOG_EXTEND, "%s: do not support password change for user %s", __FUNCTION__, user );
        rc = DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED;
        goto exit;
    }


    if( ( rc = checkUser( user ) ) != SUCCESS ) {
        if( errno == ENOENT )
            rc = DB2SEC_PLUGIN_BADUSER;
        else 
            rc = DB2SEC_PLUGIN_UNKNOWNERROR;
        goto exit;
    }
    rc = DB2SEC_PLUGIN_OK;

    /* Check the password, if supplied. */
    if (password != NULL && passwordLength > 0)
    {
        char pwdBuf[128];
        memcpy(pwdBuf, password, passwordLength);
        pwdBuf[passwordLength] = '\0';
        if( authUser( user , pwdBuf ) != SUCCESS )
            rc = DB2SEC_PLUGIN_BADPWD;
    }
    else
    {
        /* No password was supplied.  This is okay as long
         * as the following conditions are true:
         *
         *  - The username came from WhoAmI(), and
         *  - If we're on the server side, the connection must
         *    be "local" (originating from the same machine)
         *
         * Note that "DB2SEC_USERID_FROM_OS" means that the userid
         * was obtained from the plugin by calling the function
         * supplied for "db2secGetDefaultLoginContext".
         */
        if (!(connection_details & DB2SEC_USERID_FROM_OS) ||
            ((connection_details & DB2SEC_VALIDATING_ON_SERVER_SIDE) &&
             !(connection_details & DB2SEC_CONNECTION_ISLOCAL)))
        {
            /* Of of the conditions was not met, fail. */
            rc = DB2SEC_PLUGIN_BADPWD;
        }
        else
            SLOG( SLOG_EXTEND, "%s: user <%s> authenticated without password", __FUNCTION__, user );
    }

exit:
 
    if( rc == DB2SEC_PLUGIN_BADUSER )
        slog( SLOG_NORMAL, "%s: unknown user <%s>", __FUNCTION__, user );
    else if( rc == DB2SEC_PLUGIN_BADPWD)
        slog( SLOG_NORMAL, "%s: failed authentication for user <%s>", __FUNCTION__, user );
    else if ( rc == DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED )
        slog( SLOG_NORMAL, "%s: password change not supported for user <%s>", __FUNCTION__, user );
    else if ( rc == DB2SEC_PLUGIN_OK )
        slog( SLOG_NORMAL, "%s: successful authentication for user <%s>", __FUNCTION__, user );
    else
        slog( SLOG_NORMAL, "%s: unknown error while trying to authenticate user <%s>", __FUNCTION__, user );

    return(rc);
}


/* GetAuthIDs()
 * Return the username (possibly with the domain name appended) to
 * DB2 as both the System Authentication ID and the Initial Session
 * Authorization ID.
 */
SQL_API_RC SQL_API_FN GetAuthIDs(const char *userid,
                      db2int32 useridLength,
                      const char *domain,
                      db2int32 domainLength,
                      db2int32 domainType,              /* not used */
                      const char *databaseName,         /* not used */
                      db2int32 databaseNameLength,      /* not used */
                      void **token,                     /* not used */
                      char systemAuthID[],
                      db2int32 *systemAuthIDLength,
                      char sessionAuthID[],
                      db2int32 *sessionAuthIDLength,
                      char username[],
                      db2int32 *usernameLength,
                      db2int32 *sessionType,
                      char **errorMessage,
                      db2int32 *errorMessageLength)
{
    int rc = DB2SEC_PLUGIN_OK;
    int length;
    char user[SQL_AUTHID_SZ + 1];       /* User name (possibly with @domain) */

    *errorMessage = NULL;
    *errorMessageLength = 0;
    func_start();

    memset(user, '\0', sizeof(user));

    /* Check for a domain name, and make sure the userid length is ok. */
    if (domain != NULL && domainLength > 0)
    {
        if ( (useridLength + 1 + domainLength) > SQL_AUTHID_SZ )
        {
            rc = DB2SEC_PLUGIN_BADUSER;
            goto exit;
        }
        strncpy(user, userid, useridLength);
        strcat(user, "@");
        strncat(user, domain, domainLength);
    }
    else
    {
        if ( useridLength > SQL_AUTHID_SZ )
        {
            rc = DB2SEC_PLUGIN_BADUSER;
            goto exit;
        }
        strncpy(user, userid, useridLength);
    }

    length = strlen(user);

    memcpy(systemAuthID, user, length);
    *systemAuthIDLength = length;
    memcpy(sessionAuthID, user, length);
    *sessionAuthIDLength = length;
    *sessionType = 0;               /* TBD ?! */
    memcpy(username, user, length);
    *usernameLength = length;

exit:
    return(rc);
}


/* DoesAuthIDExist()
 * Determine if the supplied DB2 Authorization ID is associated with
 * a valid user.
 */
SQL_API_RC SQL_API_FN DoesAuthIDExist(const char *authID,
                           db2int32 authIDLength,
                           char **errorMessage,
                           db2int32 *errorMessageLength)
{
    int rc;
    char lineBuf[MAX_LINE_LENGTH];
    char localAuthID[SQL_AUTHID_SZ + 1];

    *errorMessage = NULL;
    *errorMessageLength = 0;

    func_start();
    /* NULL terminate the authID */
    if (authIDLength > SQL_AUTHID_SZ)
    {
        char msg[512];
        memcpy(localAuthID, authID, SQL_AUTHID_SZ);
        localAuthID[SQL_AUTHID_SZ] = '\0';
        snprintf(msg, 512,
             "DoesAuthIDExist: authID too long (%d bytes): %s... (truncated)",
             authIDLength, localAuthID);

        msg[511]='\0';            /* ensure NULL terminated */
        logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "DoesAuthIDExist: authID too long";
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    memcpy(localAuthID, authID, authIDLength);
    localAuthID[authIDLength] = '\0';


    if( ( rc = checkUser( localAuthID ) ) != SUCCESS ) {
        if( errno == ENOENT )
            rc = DB2SEC_PLUGIN_BADUSER;
        else 
            rc = DB2SEC_PLUGIN_UNKNOWNERROR;
        goto exit;
    }
        rc = DB2SEC_PLUGIN_OK;

exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
    return(rc);
}


/* WhoAmI()
 * Determine the default user identity associated with the current
 * process context.
 *
 * For simplicity this plugin returns the string found in the
 * DB2DEFAULTUSER environment variable, or an error if that variable
 * is undefined.
 *
 * Modification: read getuid(), unless DB2DEFAULTUSER is set.
 */
SQL_API_RC SQL_API_FN WhoAmI(char authID[],
                  db2int32 *authIDLength,
                  char userid[],
                  db2int32 *useridLength,
                  db2int32 useridType,              /* ignored */
                  char domain[],
                  db2int32 *domainLength,
                  db2int32 *domainType,
                  const char *databaseName,         /* not used */
                  db2int32 databaseNameLength,      /* not used */
                  void **token,                     /* not used */
                  char **errorMessage,
                  db2int32 *errorMessageLength)
{
    int rc = DB2SEC_PLUGIN_OK;
    int length;
    char *user;

    *errorMessage = NULL;
    *errorMessageLength = 0;

    authID[0] = '\0';
    *authIDLength = 0;
    userid[0] = '\0';
    *useridLength = 0;
    domain[0] = '\0';
    *domainLength = 0;
    *domainType = DB2SEC_USER_NAMESPACE_UNDEFINED;
    int uid;
    struct passwd *pwd = NULL; 
    func_start();

    user = getenv("DB2DEFAULTUSER");

    if( user )
    {
        slog( SLOG_DEBUG, "%s: found DB2DEFAULTUSER of <%s>", __FUNCTION__, user );
    }
    else
    {
        uid = getuid();
        pwd = (struct passwd*)getpwuid(uid);
        if( pwd != NULL )
        {
            slog( SLOG_DEBUG, "%s: got name of <%s> from uid <%d>", __FUNCTION__, user, uid );
            user = pwd->pw_name; 
        }
        else
        {
            slog( SLOG_NORMAL, "%s: unable to get name from uid <%d>", __FUNCTION__, uid );
            rc = DB2SEC_PLUGIN_BADUSER;
            goto exit;
        }
    }
        
    /* Check the length */
    if (user != NULL)
    {
        length = strlen(user);
        if (length > SQL_AUTHID_SZ)
        {
            *errorMessage = "user name too long";
            slog( SLOG_EXTEND, "%s: user name <%s> too long", __FUNCTION__, user );
            rc = DB2SEC_PLUGIN_BADUSER;
            goto exit;
        }

        strcpy(authID, user);
        *authIDLength = length;
        strcpy(userid, user);
        *useridLength = length;
    }

exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
    if( rc == DB2SEC_PLUGIN_BADUSER )
        slog(  SLOG_EXTEND, "%s: failed on user <%s>", __FUNCTION__, user ? user : "UNKNOWN" );
    else if ( rc == DB2SEC_PLUGIN_OK )
        slog( SLOG_EXTEND, "%s: I am user <%s>", __FUNCTION__, user );
    else
        slog( SLOG_EXTEND, "%s: unknown Error", __FUNCTION__ );

    return(rc);
}


/* LookupGroups()
 * Return the list of groups to which a user belongs.
 *
 * For this plugin this involves finding the provided authorization
 * ID in the User definition file and returning all fields after
 * the second.
 */
SQL_API_RC SQL_API_FN LookupGroups(const char *authID,
                        db2int32 authIDLength,
                        const char *userid,             /* ignored */
                        db2int32 useridLength,          /* ignored */
                        const char *domain,             /* ignored */
                        db2int32 domainLength,          /* ignored */
                        db2int32 domainType,            /* ignored */
                        const char *databaseName,       /* ignored */
                        db2int32 databaseNameLength,    /* ignored */
                        void *token,                    /* ignored */
                        db2int32 tokenType,             /* ignored */
                        db2int32 location,              /* ignored */
                        const char *authPluginName,     /* ignored */
                        db2int32 authPluginNameLength,  /* ignored */
                        void **groupList,
                        db2int32 *groupCount,
                        char **errorMessage,
                        db2int32 *errorMessageLength)
{
    int rc = DB2SEC_PLUGIN_OK;
    int length = 0;
    int ngroups = 0;
    char * gtest = NULL;
    char * gtest2 = NULL;
    char localAuthID[SQL_AUTHID_SZ + 1];
    //char readBuffer[MAX_LINE_LENGTH];
    char *cptr = NULL;

    *errorMessage = NULL;
    *errorMessageLength = 0;

    func_start();

    /* NULL terminate the authID */
    if (authIDLength > SQL_AUTHID_SZ)
    {
        char msg[512];
        memcpy(localAuthID, authID, SQL_AUTHID_SZ);
        localAuthID[SQL_AUTHID_SZ] = '\0';
        snprintf(msg, 512,
             "LookupGroups: authID too long (%d bytes): %s... (truncated)",
             authIDLength, localAuthID);

        msg[511]='\0';            /* ensure NULL terminated */
        logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "LookupGroups: authID too long";
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    memcpy(localAuthID, authID, authIDLength);
    localAuthID[authIDLength] = '\0';

    *groupList = malloc(MAX_LINE_LENGTH);
    if (*groupList == NULL)
    {
        *errorMessage = "malloc failed for group memory";
        rc = DB2SEC_PLUGIN_NOMEM;
        goto exit;
    }
    
    rc = FindGroupsForUser( localAuthID , *groupList , &ngroups ); 
    errno = ENOENT;
    if (rc == -1)
    {
        if( errno == ENOENT )
            rc = DB2SEC_PLUGIN_BADUSER;
        else
            rc = DB2SEC_PLUGIN_UNKNOWNERROR;
        goto exit;
    }
    *groupCount = ngroups;
    
exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
    return(rc);
}


/* FreeGroupList()
 * Free a group list allocated in LookupGroups().
 */
SQL_API_RC SQL_API_FN FreeGroupList(void *ptr,
                         char **errorMessage,
                         db2int32 *errorMessageLength)
{
    func_start();
    if (ptr != NULL)
    {
        free(ptr);
    }
    *errorMessage = NULL;
    *errorMessageLength = 0;
    return(DB2SEC_PLUGIN_OK);
}


/* DoesGroupExist
 */
SQL_API_RC SQL_API_FN DoesGroupExist(const char *groupName,
                          db2int32 groupNameLength,
                          char **errorMessage,
                          db2int32 *errorMessageLength)
{
    int rc = DB2SEC_PLUGIN_OK;

    char localGroupName[DB2SEC_MAX_AUTHID_LENGTH + 1];
    char readBuffer[MAX_LINE_LENGTH];

    int foundGroup = 0;

    *errorMessage = NULL;
    *errorMessageLength = 0;

    func_start();

    if (groupName == NULL)
    {
        *errorMessage = "NULL group name supplied";
        rc = DB2SEC_PLUGIN_UNKNOWNERROR;
        goto exit;
    }

    /* NULL terminate the group name */
    if (groupNameLength > DB2SEC_MAX_AUTHID_LENGTH)
    {
        char msg[512];
        memcpy(localGroupName, groupName, DB2SEC_MAX_AUTHID_LENGTH);
        localGroupName[DB2SEC_MAX_AUTHID_LENGTH] = '\0';
        snprintf(msg, 512,
             "DoesGroupExist: group name too long (%d bytes): %s... (truncated)",
             groupNameLength, localGroupName);

        msg[511]='\0';            /* ensure NULL terminated */
        logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "DoesGroupExist: group name too long";
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    memcpy(localGroupName, groupName, groupNameLength);
    localGroupName[groupNameLength] = '\0';


    if ( checkGroup( localGroupName ) == SUCCESS )
        rc = DB2SEC_PLUGIN_OK;
    else
        rc = DB2SEC_PLUGIN_INVALIDUSERORGROUP;


exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }

    return(rc);
}

/* FreeToken()
 * This plugin does not make use of the "token" parameter,
 * so this function is a no-op.
 */
SQL_API_RC SQL_API_FN FreeToken(void *token,
                     char **errorMessage,
                     db2int32 *errorMessageLength)
{
    *errorMessage = NULL;
    *errorMessageLength = 0;
    func_start();
    return(DB2SEC_PLUGIN_OK);
}


/* FreeErrorMessage()
 * All of the error messages returned by this plugin are
 * literal C strings, so this function is a no-op.
 */
SQL_API_RC SQL_API_FN FreeErrorMessage(char *msg)
{
    func_start();
    return(DB2SEC_PLUGIN_OK);
}

/* PluginTerminate()
 * There is no cleanup required when this plugin is unloaded.
 */
SQL_API_RC SQL_API_FN PluginTerminate(char **errorMessage,
                           db2int32 *errorMessageLength)
{
    *errorMessage = NULL;
    *errorMessageLength = 0;
    func_start();
    return(DB2SEC_PLUGIN_OK);
}


/*
 * PLUGIN INITIALIZATION FUNCTIONS
 *
 * Unlike previous functions in this file, the names of these
 * functions must match those defined in db2secPlugin.h.
 */

/* Server-side userid/password authentication plugin initialization */
SQL_API_RC SQL_API_FN db2secServerAuthPluginInit(
                    db2int32 version,
                    void *server_fns,
                    db2secGetConDetails *getConDetails_fn,
                    db2secLogMessage *msgFunc,
                    char **errorMessage,
                    db2int32 *errorMessageLength)
{
    db2secUseridPasswordServerAuthFunctions_1 *p;

    p = (db2secUseridPasswordServerAuthFunctions_1 *)server_fns;

    p->version = 1;         /* We're a version 1 plugin */
    p->plugintype = DB2SEC_PLUGIN_TYPE_USERID_PASSWORD;
    p->db2secValidatePassword = CheckPassword;
    p->db2secGetAuthIDs = GetAuthIDs;
    p->db2secDoesAuthIDExist = DoesAuthIDExist;
    p->db2secFreeToken = FreeToken;
    p->db2secFreeErrormsg = FreeErrorMessage;
    p->db2secServerAuthPluginTerm = PluginTerminate;

    logFunc = msgFunc;

    func_start();

    *errorMessage = NULL;
    *errorMessageLength = 0;
    return(DB2SEC_PLUGIN_OK);
}

SQL_API_RC SQL_API_FN db2secClientAuthPluginInit (db2int32 version,
                                       void *client_fns,
                                       db2secLogMessage *msgFunc,
                                       char **errorMessage,
                                       db2int32 *errorMessageLength)
{
    db2secUseridPasswordClientAuthFunctions_1 *p;

    p = (db2secUseridPasswordClientAuthFunctions_1 *)client_fns;

    p->version = 1;         /* We're a version 1 plugin */
    p->plugintype = DB2SEC_PLUGIN_TYPE_USERID_PASSWORD;
    p->db2secRemapUserid = NULL;    /* optional */
    p->db2secGetDefaultLoginContext = &WhoAmI;
    p->db2secValidatePassword = &CheckPassword;
    p->db2secFreeToken = &FreeToken;
    p->db2secFreeErrormsg = &FreeErrorMessage;
    p->db2secClientAuthPluginTerm = &PluginTerminate;

    logFunc = msgFunc;

    func_start();
    *errorMessage = NULL;
    *errorMessageLength = 0;
    return(DB2SEC_PLUGIN_OK);
}

SQL_API_RC SQL_API_FN db2secGroupPluginInit(db2int32 version,
                                 void *group_fns,
                                 db2secLogMessage *msgFunc,
                                 char **errorMessage,
                                 db2int32 *errorMessageLength)
{
    db2secGroupFunction_1  *p;

    p = (db2secGroupFunction_1 *)group_fns;

    p->version = 1;         /* We're a version 1 plugin */
    p->plugintype = DB2SEC_PLUGIN_TYPE_GROUP;
    p->db2secGetGroupsForUser = &LookupGroups;
    p->db2secDoesGroupExist = &DoesGroupExist;
    p->db2secFreeGroupListMemory = &FreeGroupList;
    p->db2secFreeErrormsg = &FreeErrorMessage;
    p->db2secPluginTerm = &PluginTerminate;

    logFunc = msgFunc;
    func_start();

    *errorMessage = NULL;
    *errorMessageLength = 0;
    return(DB2SEC_PLUGIN_OK);
}
