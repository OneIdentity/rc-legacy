/********************************************************************
* (c) 2007 Quest Software, Inc. All rights reserved.
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
*          "Resouce Central License" avaliable at
*          http://rc.vintela.com/topics/db2_sys-auth/license.php
*          or in the included LICENSE file.
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

#include "db2secPlugin.h"

#include "log.h"

#include <unistd.h>
#include <sys/types.h>

#ifdef AIX
#include <usersec.h>
#endif

db2secLogMessage *logFunc = NULL;


#define SUCCESS 1
#define FAILURE 0

#define MAX_C_BUFF 512

/********************************************************************
 * Helper functions.
 *******************************************************************/

/* Test an 11k chunk of memory, which is needed for group calls. 
 * This is to warn in case the current thread/process is out
 * of memory.
*/
int vas_db2_plugin_test_memory( const char *func ) {
    char *ptr = NULL;
    char out[MAX_LINE_LENGTH];

    strncpy( out, func, MAX_LINE_LENGTH - 1 );
    strcat( out, ": testing for 11K available memory" );
    slog( SLOG_ALL, out );
    
    ptr = malloc( 11 * 1024 );
    if( !ptr )
    {
        strcat( out, " - BAD - Unable to malloc 11KB" );
        slog( SLOG_CRIT, out );
        return 1;
    }
    else
    {
        strcat( out, " - GOOD" );
        slog( SLOG_ALL, out );
        free( ptr );
    }
    return 0;
}

void vas_db2_plugin_lower( char *username ) {
    char * cptr = NULL;
    int count = 0;
    slog( SLOG_ALL, "%s: lowering <%s>", __FUNCTION__, username );
    while( username[count] != '\0' ) {
        username[count] = tolower(username[count]);
        ++count;
    }
}

sig_atomic_t vas_db2_plugin_sigt = 0;

sig_atomic_t vas_db2_plugin_sigp = 0;

void vas_db2_plugin_sig_handle( int signo ) {
    if( signo == SIGCHLD )
        vas_db2_plugin_sigt = 1;
    if( signo == SIGPIPE )
        vas_db2_plugin_sigp = 1;
    return;
}

int vas_db2_plugin_auth_user(char *username, char *password) {
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

    sigact.sa_handler = vas_db2_plugin_sig_handle;

    sigaction(SIGCHLD, &sigact, &osigact);
    sigaction(SIGPIPE, &sigact, &osigact);

    errno = 0;


    if ( pipe( stdin_fds ) != 0 ) { 
        retval = errno;
        slog( SLOG_NORMAL, "%s: Pipe failed!", __FUNCTION__ );
        goto EXIT;
    }
        
    if( ( pid = fork() ) == 0 ) /* Child Process */
    {
        slog( SLOG_DEBUG, "%s: child process with pid %d", __FUNCTION__, 
		getpid() );
        
        close( stdin_fds[1] );
        if( dup2( stdin_fds[0], STDIN_FILENO ) != STDIN_FILENO )
        {
            slog( SLOG_NORMAL, "%s: dup2 failed, errno %d", __FUNCTION__, 
		    errno );
            retval = errno;
            goto EXIT;
        }
        close( stdin_fds[0] );


        if( ( cptr = getenv( "DB2INSTANCE" ) ) == NULL ) 
        {
            slog( SLOG_NORMAL, "%s: Unable to obtain DB2INSTANCE environment"
		   " variable, trying uid <%d>", __FUNCTION__, getuid() );
            pwd = getpwuid( getuid() );
        }
        else
        { 
            pwd = getpwnam( cptr );
        }

        if( pwd == NULL ) 
        {
            slog( SLOG_NORMAL, "%s: unable to obtain running user information",
		    __FUNCTION__ );
            _exit( EFAULT );
        }
        
        
        cptr = pwd->pw_dir; 
        slog( SLOG_DEBUG, "%s: found directory <%s>", __FUNCTION__, cptr );
        
        strncpy( prog_path, cptr, MAX_C_BUFF - 1);

        strcat( prog_path, "/sqllib/security" );
#ifdef __64BIT__
        strcat( prog_path, "64/plugin/sys-auth64" );
        strcpy( prog_file, "sys-auth64" );
#else    
        strcat( prog_path, "32/plugin/sys-auth32" );
        strcpy( prog_file, "sys-auth32" );
#endif

        if( access( prog_path, X_OK ) != 0 )
        {
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s>, "
		    "trying pamAuth in the current directory",
		    __FUNCTION__, prog_path );
            memset( prog_path, 0, MAX_C_BUFF);
            if( getcwd( prog_path, MAX_C_BUFF) == NULL )
            {
                slog( SLOG_NORMAL,
		    "%s: getcwd FAILED with errno <%d> string <%s>. Trying .",
		    __FUNCTION__, errno, strerror( errno ) );
                strcpy( prog_path, "." );
            }
            
#ifdef __64BIT__
            strcat( prog_path, "/pamAuth64" );
#else    
            strcat( prog_path, "/pamAuth32" );
#endif
            if( access( prog_path, X_OK ) != 0 )
            {
                slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
		       "in current directory", __FUNCTION__, prog_path );
                return( FAILURE );
            }
        }
        
        slog( SLOG_DEBUG, "%s: executing program <%s> from path <%s>", 
		__FUNCTION__, prog_file, prog_path );

        if( execl( prog_path, prog_file, username, NULL ) == -1 ) 
        {
            slog( SLOG_NORMAL, "%s: execl failed with errno <%s>", 
		    __FUNCTION__, errno ? errno : ECHILD );
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
        slog( SLOG_DEBUG, "%s: parent process <%d> waiting for child process "
		"<%d>", __FUNCTION__, getpid(), (int)pid );
        while( ( retval = waitpid( pid, &status, 0 ) ) == -1 )  
        {
            if( errno == EINTR ) { 
                if( vas_db2_plugin_sigt == 1 )
                    continue;
                if( vas_db2_plugin_sigp == 1 )
                    break;
            } 
            break;
        }
        close( stdin_fds[1] );
        fclose( stream );
        slog( SLOG_DEBUG, "%s: child process returned with value <%d>", 
		__FUNCTION__, retval );
        sigaction(SIGCHLD, &osigact, NULL);
        sigaction(SIGPIPE, &osigact, NULL);
    }

    if( retval == -1 )
        goto EXIT;
    if( WEXITSTATUS(status) == 0 )
        retval = 0;

EXIT:
        if( retval == 0 ) {
#if 0
                slog( SLOG_NORMAL, "%s: Successful authentication attempt "
			"for user <%s>", __FUNCTION__, username );
#endif
                return SUCCESS;
        } else {
                slog( SLOG_EXTEND, "%s: Failed authentication attempt for user "
			"<%s>, error <%d>", __FUNCTION__, username, 
			WEXITSTATUS(status) );
                return FAILURE;
        }
}

/* Return the pgid so it doesn't have to be determined again. */
int vas_db2_plugin_check_user( const char* username, gid_t *pgid ) {
    struct passwd *pwd = NULL;
    int retval = FAILURE;

    func_start();
    
    slog( SLOG_DEBUG, "%s: checking user <%s>", __FUNCTION__, username );
    if( ( pwd = (struct passwd*)getpwnam(username) ) == NULL ) {
        slog( SLOG_DEBUG, "%s: user <%s> not found, errno <%d>, msg <%s>",
                          __FUNCTION__,
                          username,
                          errno,
                          strerror( errno ) );
        if( errno == 0 )
        {
            /* pthreads sets a 'different' errno, so assume ENOENT. */
            slog( SLOG_DEBUG, "%s: errno of 0 found, setting to ENOENT "
		    "for the pthreads issue", __FUNCTION__ );
            errno = ENOENT;
        }
        return FAILURE;
    }
    slog( SLOG_DEBUG, "%s: found user <%s><%s>", __FUNCTION__, username, 
	    pwd->pw_name );
    if( pgid )
        *pgid = pwd->pw_gid;
    return SUCCESS;
}

int vas_db2_plugin_check_group( const char* groupname) {
    struct group *grp= NULL;
    int retval = FAILURE;

    func_start();
    slog( SLOG_DEBUG, "%s: checking group <%s>", __FUNCTION__, groupname );
    if( ( grp = (struct group*)getgrnam(groupname) ) == NULL ) {
        slog( SLOG_EXTEND, "%s: group <%s> not found", __FUNCTION__, groupname);
        errno = ENOENT;
        return FAILURE;
    }
    slog( SLOG_DEBUG, "%s: found group <%s><%s>", __FUNCTION__, groupname,
	    grp->gr_name );
    return SUCCESS;
}

int vas_db2_plugin_is_user_in_group( const char* username, struct group *grp,
       	gid_t pgid ) {
    int retval = FAILURE, d = 0;
    struct passwd *pwd = NULL;
    char **members = NULL;

    func_start();

    if( grp == NULL ) {
        slog( SLOG_ALL, "%s: this should never happen, but called with a NULL "
		"group struct. ", __FUNCTION__ );
        return FAILURE;
    }
    slog( SLOG_DEBUG, "%s: checking group <%s> for user <%s>", __FUNCTION__, 
	    grp->gr_name, username );

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
        slog( SLOG_DEBUG, "%s: user <%s> is in group <%s>", __FUNCTION__, 
		username, grp->gr_name );
    }
    else
    {/* Add check for user-gid == group gid. */
        if( pgid == grp->gr_gid )
        {
            /* User has GID membership. */
            slog( SLOG_DEBUG, "%s: user <%s> has group membership in <%s> "
		    "through implicit pgid->gid.", __FUNCTION__, username, 
		    grp->gr_name );
            retval = SUCCESS;
        }
        else
        {
            slog( SLOG_DEBUG, "%s: user <%s> is not in group <%s>", 
		    __FUNCTION__, username, grp->gr_name );
        }
    }
    return retval;
}

int vas_db2_plugin_find_groups_for_user( const char* username, char *groups,
       	int *numgroups ) {
    struct group *grp = NULL;
    char *cptr = NULL;
    char *grset = NULL;
    char *gr = NULL;
    char delims[] = ",";
    char userBuffer[MAX_LINE_LENGTH];
    gid_t gid, pgid;
    int groupcount = 0;
    int length = 0;
    int rval = 0;
    memset(userBuffer, '\0', MAX_LINE_LENGTH);
    func_start();

    if( !username || username[0] == '\0' ||
        !groups || !numgroups )
    {
        slog( SLOG_NORMAL, "%s: called with an invalid paramater", 
		__FUNCTION__ );
        return DB2SEC_PLUGIN_BAD_INPUT_PARAMETERS;
    }

    strcpy( userBuffer, username );
    
    if( ( rval = vas_db2_plugin_check_user( userBuffer, &pgid ) ) != SUCCESS )
    {
        vas_db2_plugin_lower( userBuffer );
        if( ( rval = vas_db2_plugin_check_user( userBuffer, &pgid ) ) 
		!= SUCCESS )
        {
            slog( SLOG_EXTEND, "%s: vas_db2_plugin_check_user returned <%d>"
		   " for user <%s>", __FUNCTION__, rval, userBuffer );
            return DB2SEC_PLUGIN_BADUSER;
        }
    }

#ifdef AIX
    /* Since we are on AIX, we can use getgrset. Get that, tokenize the 
     * result, and add to the buffer as the group resolves to names. 
     */
    /* New: Fall through to the other function, this combines the groups
     * so local groups are also considered. 
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

    if(grset)
        free(grset);    
    grset = NULL;

    /* Add the VAS specific groups, checking for duplicates. */
    /* Uses the SEC_LIST attribute:
     *  The format of the attribute is a series of concatenated strings, 
     *  each null-terminated. The last string in the series is terminated 
     *  by two successive null characters.
    */
    if( setauthdb( "VAS", NULL ) == 0 &&
        getuserattr( userBuffer, S_GROUPS, (void*)&grset, SEC_LIST ) == 0 ) 
    {
        gr = grset;
        while( *gr != '\0' )
        {
            if( strstr( groups, gr ) == NULL )
            {
                length = strlen( gr );
                *((unsigned char*)cptr) = (unsigned char)length;
                ++cptr;
                memcpy(cptr, gr, length );
                cptr += length;
                ++groupcount;
            }

            while( *gr != '\0' )
                ++gr;
            ++gr;
        }
    }

    /* Re-set to default */
    setauthdb( NULL, NULL );
#else
    cptr = groups;
#endif
    setgrent();
    slog( SLOG_ALL, "%s: using getgrent cycle", __FUNCTION__ );
    while( ( grp = getgrent() ) != NULL ) {
        if( ( vas_db2_plugin_is_user_in_group( userBuffer, grp, pgid ) ) 
		== SUCCESS ) {
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

    *numgroups = groupcount;
    slog( SLOG_DEBUG, "%s: returning group string <%s>", __FUNCTION__, groups );
    return 0;
}





/*-------------------------------------------------------
 * Plugin functions
 *-------------------------------------------------------*/

/* vas_db2_plugin_check_password()
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
SQL_API_RC SQL_API_FN vas_db2_plugin_check_password(const char *userid,
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
    test_mem();

    memset(user, '\0', SQL_AUTHID_SZ + 1);

    if ( useridLength > SQL_AUTHID_SZ )
    {
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }
    strncpy(user, userid, useridLength);
    if( ( cptr = strchr( user, '@' ) ) != NULL )
        *cptr = '\0';

    slog( SLOG_EXTEND, "%s: Authentication attempt for user %s", __FUNCTION__, 
	    user );
    /* Was a new password supplied? */
    if (newPassword != NULL && newPasswordLength > 0)
    {
        slog( SLOG_EXTEND, "%s: do not support password change for user %s", 
		__FUNCTION__, user );
        rc = DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED;
        goto exit;
    }

    {
        struct passwd *pwd = NULL;
        int retval = FAILURE;

        slog( SLOG_EXTEND, "%s: checking user <%s>", __FUNCTION__, user );
        if( ( pwd = (struct passwd*)getpwnam(user) ) == NULL ) {
            vas_db2_plugin_lower( user );
            if( (  pwd = (struct passwd*)getpwnam(user) ) == NULL ) {
                slog( SLOG_NORMAL, "%s: user <%s> not found, errno <%d>, "
		    "msg <%s>", __FUNCTION__, user, errno, strerror( errno ) );
                rc = FAILURE;
		/* pthreads sets a different errno, so assume ENOENT */
                if( errno == 0 )
                    errno = ENOENT;
            }
            else
            {
                slog( SLOG_EXTEND, "%s: found user <%s>", __FUNCTION__, user );
                rc = SUCCESS;
            }
        }
        else
        {
            slog( SLOG_EXTEND, "%s: found user <%s>", __FUNCTION__, user );
            rc = SUCCESS;
        }
    }

    if( rc != SUCCESS ) {
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
        if( vas_db2_plugin_auth_user( user , pwdBuf ) != SUCCESS )
            rc = DB2SEC_PLUGIN_BADPWD;
    }
    else
    {
        /* No password was supplied.  This is okay as long
         * as the following conditions are true:
         *
         *  - The username came from vas_db2_plugin_who_am_i(), and
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
            slog( SLOG_EXTEND, "%s: user <%s> authenticated without password",
		    __FUNCTION__, user );
    }

exit:
 
    if( rc == DB2SEC_PLUGIN_BADUSER )
        slog( SLOG_NORMAL, "%s: unknown user <%s>", __FUNCTION__, user );
    else if( rc == DB2SEC_PLUGIN_BADPWD)
        slog( SLOG_NORMAL, "%s: failed authentication for user <%s>", 
		__FUNCTION__, user );
    else if ( rc == DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED )
        slog( SLOG_NORMAL, "%s: password change not supported for user <%s>", 
		__FUNCTION__, user );
    else if ( rc == DB2SEC_PLUGIN_OK )
        slog( SLOG_NORMAL, "%s: successful authentication for user <%s>", 
		__FUNCTION__, user );
    else
        slog( SLOG_NORMAL, "%s: unknown error while trying to authenticate user"
	       " <%s>", __FUNCTION__, user );

    return(rc);
}


/* vas_db2_plugin_get_auth_ids()
 * Return the username (possibly with the domain name appended) to
 * DB2 as both the System Authentication ID and the Initial Session
 * Authorization ID.
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_get_auth_ids(const char *userid,
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
    test_mem();

    memset(user, '\0', sizeof(user));

    /* Check for a domain name, and make sure the userid length is ok. */

    /* Don't use domain name, DB2 puts in the short name, which would 
     * not be recognized by VAS ( hence the '&& 0' here ) */
    if (domain != NULL && domainLength > 0 && 0 )
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


/* vas_db2_plugin_does_auth_id_exist()
 * Determine if the supplied DB2 Authorization ID is associated with
 * a valid user.
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_does_auth_id_exist(const char *authID,
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
    test_mem();
    /* NULL terminate the authID */
    if (authIDLength > SQL_AUTHID_SZ)
    {
        char msg[512];
        memcpy(localAuthID, authID, SQL_AUTHID_SZ);
        localAuthID[SQL_AUTHID_SZ] = '\0';
        snprintf(msg, 512, "vas_db2_plugin_does_auth_id_exist: "
		"authID too long (%d bytes): %s... (truncated)",
		authIDLength, localAuthID);

        msg[511]='\0';            /* ensure NULL terminated */
        logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "vas_db2_plugin_does_auth_id_exist: authID too long";
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    memcpy(localAuthID, authID, authIDLength);
    localAuthID[authIDLength] = '\0';


    if( ( rc = vas_db2_plugin_check_user( localAuthID, NULL ) ) != SUCCESS ) {
        vas_db2_plugin_lower( localAuthID );
        if( ( rc = vas_db2_plugin_check_user( localAuthID, NULL ) ) != SUCCESS){
            if( errno == ENOENT )
                rc = DB2SEC_PLUGIN_BADUSER;
            else 
                rc = DB2SEC_PLUGIN_UNKNOWNERROR;
            goto exit;
        }
    }
        rc = DB2SEC_PLUGIN_OK;

exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
    return(rc);
}


/* vas_db2_plugin_who_am_i()
 * Determine the default user identity associated with the current
 * process context.
 *
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_who_am_i(char authID[],
                  db2int32 *authIDLength,
                  char userid[],
                  db2int32 *useridLength,
                  db2int32 useridType,              /* real or effective */
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
    char *user = NULL;

    *errorMessage = NULL;
    *errorMessageLength = 0;

    authID[0] = '\0';
    *authIDLength = 0;
    userid[0] = '\0';
    *useridLength = 0;
    if( domain ) domain[0] = '\0';
    if( domainLength ) *domainLength = 0;
    if( domainType ) *domainType = DB2SEC_USER_NAMESPACE_UNDEFINED;
    int uid;
    struct passwd *pwd = NULL; 
    func_start();
    test_mem();

#if 0
    /*
     * This is really bad, don't follow the example code in this way,
     * otherwise anyone who can get on the machine and run export
     * DB2DEFAULTUSER=<instance owner> will BE the instance owner the
     * the box. I sure hope I am not understanding this, and it isn't
     * the gaping security hole it seems.
     *
     * It doesn't seem as bad, as you can't set the ENV of the process
     * this runs in ( DB2 seems to keep a pool of 'auth' threads going,
     * it isn't going to make one jstu for you, and even if it did,
     * it woudl be spawned by another environment, so the export is
     * useless )
     */
    user = getenv("DB2DEFAULTUSER");

    if( user )
    {
        slog( SLOG_DEBUG, "%s: found DB2DEFAULTUSER of <%s>", __FUNCTION__, 
		user );
    }
    else
#endif
    {
        if (DB2SEC_PLUGIN_REAL_USER_NAME == useridType) 
            pwd = getpwuid((uid = getuid())); 
        else 
            pwd = getpwuid((uid = geteuid())); 

        if( pwd != NULL )
        {
            user = pwd->pw_name; 
            slog( SLOG_DEBUG, "%s: got name of <%s> from uid <%d>", 
		    __FUNCTION__, user, uid );
        }
        else
        {
            slog( SLOG_NORMAL, "%s: unable to get name from uid <%d>", 
		    __FUNCTION__, uid );
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
            slog( SLOG_EXTEND, "%s: user name <%s> too long", 
		    __FUNCTION__, user );
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
        slog(  SLOG_EXTEND, "%s: failed on user <%s>", __FUNCTION__, 
		user ? user : "UNKNOWN" );
    else if ( rc == DB2SEC_PLUGIN_OK )
        slog( SLOG_EXTEND, "%s: I am user <%s>", __FUNCTION__, user );
    else
        slog( SLOG_EXTEND, "%s: unknown Error", __FUNCTION__ );

    return(rc);
}


/* vas_db2_plugin_lookup_groups()
 * Return the list of groups to which a user belongs.
 *
 * For this plugin this involves finding the provided authorization
 * ID in the User definition file and returning all fields after
 * the second.
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_lookup_groups(const char *authID,
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
    /* char readBuffer[MAX_LINE_LENGTH]; */
    char *cptr = NULL;

    *errorMessage = NULL;
    *errorMessageLength = 0;

    func_start();
    test_mem();

    /* NULL terminate the authID */
    if (authIDLength > SQL_AUTHID_SZ)
    {
        char msg[512];
        memcpy(localAuthID, authID, SQL_AUTHID_SZ);
        localAuthID[SQL_AUTHID_SZ] = '\0';
        snprintf(msg, 512,
             "vas_db2_plugin_lookup_groups: authID too long (%d bytes): "
	     "%s... (truncated)",
             authIDLength, localAuthID);

        msg[511]='\0';            /* ensure NULL terminated */
        logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "vas_db2_plugin_lookup_groups: authID too long";
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    memcpy(localAuthID, authID, authIDLength);
    localAuthID[authIDLength] = '\0';
    if( ( cptr = strchr( localAuthID, '@' ) ) != NULL )
        *cptr = '\0';

    *groupList = malloc(MAX_LINE_LENGTH);
    if (*groupList == NULL)
    {
        *errorMessage = "malloc failed for group memory";
        rc = DB2SEC_PLUGIN_NOMEM;
        goto exit;
    }
    
    rc = vas_db2_plugin_find_groups_for_user( localAuthID , *groupList ,
	    &ngroups ); 
    if (rc == -1)
    {
        if( errno == ENOENT )
            rc = DB2SEC_PLUGIN_BADUSER;
        else
            rc = DB2SEC_PLUGIN_UNKNOWNERROR;
        slog( SLOG_DEBUG, "%s: vas_db2_plugin_find_groups_for_user failed "
		"for user <%s> errno <%d>, ", 
                      __FUNCTION__, 
                      localAuthID, 
                      errno );
        goto exit;
    }
    slog( SLOG_DEBUG, "%s: vas_db2_plugin_find_groups_for_user for user <%s>"
	   " returned groups <%s>", __FUNCTION__, localAuthID, 
	   (ngroups > 0) ? (char *)*groupList : "None" );
    *groupCount = ngroups;
    
exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
    return(rc);
}


/* vas_db2_plugin_free_group_list()
 * Free a group list allocated in vas_db2_plugin_lookup_groups().
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_free_group_list(void *ptr,
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


/* vas_db2_plugin_does_group_exist
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_does_group_exist(const char *groupName,
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
    test_mem();

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
             "vas_db2_plugin_does_group_exist: group name too long (%d bytes):"
	     " %s... (truncated)",
             groupNameLength, localGroupName);

        msg[511]='\0';            /* ensure NULL terminated */
        logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "vas_db2_plugin_does_group_exist: group name too long";
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    memcpy(localGroupName, groupName, groupNameLength);
    localGroupName[groupNameLength] = '\0';


    if ( vas_db2_plugin_check_group( localGroupName ) == SUCCESS )
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

/* vas_db2_plugin_free_token()
 * This plugin does not make use of the "token" parameter,
 * so this function is a no-op.
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_free_token(void *token,
                     char **errorMessage,
                     db2int32 *errorMessageLength)
{
    *errorMessage = NULL;
    *errorMessageLength = 0;
    func_start();
    return(DB2SEC_PLUGIN_OK);
}


/* vas_db2_plugin_free_error_message()
 * All of the error messages returned by this plugin are
 * literal C strings, so this function is a no-op.
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_free_error_message(char *msg)
{
    func_start();
    return(DB2SEC_PLUGIN_OK);
}

/* vas_db2_plugin_plugin_terminate()
 * There is no cleanup required when this plugin is unloaded.
 */
SQL_API_RC SQL_API_FN vas_db2_plugin_plugin_terminate(char **errorMessage,
                           db2int32 *errorMessageLength)
{
    *errorMessage = NULL;
    *errorMessageLength = 0;
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
    p->db2secValidatePassword = vas_db2_plugin_check_password;
    p->db2secGetAuthIDs = vas_db2_plugin_get_auth_ids;
    p->db2secDoesAuthIDExist = vas_db2_plugin_does_auth_id_exist;
    p->db2secFreeToken = vas_db2_plugin_free_token;
    p->db2secFreeErrormsg = vas_db2_plugin_free_error_message;
    p->db2secServerAuthPluginTerm = vas_db2_plugin_plugin_terminate;

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

    memset( client_fns, 0, sizeof( db2secUseridPasswordClientAuthFunctions_1 ));

    p = (db2secUseridPasswordClientAuthFunctions_1 *)client_fns;

    p->version = 1;         /* We're a version 1 plugin */
    p->plugintype = DB2SEC_PLUGIN_TYPE_USERID_PASSWORD;
    p->db2secRemapUserid = NULL;    /* optional */
    p->db2secGetDefaultLoginContext = &vas_db2_plugin_who_am_i;
    p->db2secValidatePassword = &vas_db2_plugin_check_password;
    p->db2secFreeToken = &vas_db2_plugin_free_token;
    p->db2secFreeErrormsg = &vas_db2_plugin_free_error_message;
    p->db2secClientAuthPluginTerm = &vas_db2_plugin_plugin_terminate;

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
    p->db2secGetGroupsForUser = &vas_db2_plugin_lookup_groups;
    p->db2secDoesGroupExist = &vas_db2_plugin_does_group_exist;
    p->db2secFreeGroupListMemory = &vas_db2_plugin_free_group_list;
    p->db2secFreeErrormsg = &vas_db2_plugin_free_error_message;
    p->db2secPluginTerm = &vas_db2_plugin_plugin_terminate;

    logFunc = msgFunc;
    func_start();

    *errorMessage = NULL;
    *errorMessageLength = 0;
    return(DB2SEC_PLUGIN_OK);
}

char *vas_db2_plugin_get_version( )
{
    return( VERSION );
}

