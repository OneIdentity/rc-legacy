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

#include "sqlenv.h"
#include "db2secPlugin.h"

#include "config.h"

#include <unistd.h>
#include <sys/types.h>

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

db2secLogMessage *logFunc = NULL;

/* The internal max line length includes room for a line
 * separator (CR/LF on Windows, LF on UNIX) and a NULL byte.
 */
#define MAX_LINE_LENGTH     1027

#define SUCCESS 1
#define FAILURE 0

#define MAX_C_BUFF 512

/********************************************************************
 * Helper functions.
 *******************************************************************/

void lower( char * username ) {
	char * cptr = NULL;
	int count = 0;
	log( username );
	while( username[count] != '\0' ) {
		username[count] = tolower(username[count]);
		++count;
	}
	log( username );
}

sig_atomic_t sigt = 0;

void sigHandle( int signo ) {
	if( signo == SIGCHLD )
		sigt = 1;
	return;
}

int authUser(char *username, char *password) {
        int retval = 0;
        int status = 0;
        pid_t pid = 0;
	struct sigaction sigact;
	struct sigaction osigact;
	int stdin_fds[] = { -1, -1 };
	char prog_path[MAX_C_BUFF];
	char prog_file[MAX_C_BUFF];
	char *cptr = NULL;

	memset(&sigact, 0, sizeof(sigact));
	memset(&osigact, 0, sizeof(osigact));

 	sigact.sa_handler = sigHandle;

	sigaction(SIGCHLD, &sigact, &osigact);

	errno = 0;

        func_start();
        log( username );
        log( password );

	if ( pipe( stdin_fds ) != 0 ) { 
		retval = errno;
		log( "Pipe failed!" );
		goto exit;
	}

        if( ( pid = fork() ) == 0 ) { /* Child Process */
                log( "Child proc forked to run auth." );
                logd( getpid() );
		close( stdin_fds[1] );
		if( dup2( stdin_fds[0], STDIN_FILENO ) != STDIN_FILENO )
		{
			retval = errno;
			log( "Dup2 failed!" );
			goto exit;
		}
		close( stdin_fds[0] );
	
	
		if( ( cptr = getenv("HOME") ) == NULL ) {
			log( "Unable to obtain HOME." );
			_exit( EFAULT );
		}
		
		strncpy( prog_path, cptr, MAX_C_BUFF);

		strcat( prog_path, "/sqllib/security" );
#ifdef _64
		strcat( prog_path, "64/plugin/sys-auth64" );
		strcpy( prog_file, "sys-auth64" );
#else	
		strcat( prog_path, "32/plugin/sys-auth32" );
		strcpy( prog_file, "sys-auth32" );
#endif

		log( "PATH: ");
		log( prog_path );

		log( "FILE: ");
		log( prog_file );

                if( execl( prog_path, prog_file, username, NULL ) == -1 ) {
                        log( "execl failed!" );
                        _exit( errno ? errno : ECHILD );
                }
        } else if ( pid < 0 ) { /* Fork failed */
                log( "Fork Failed!" );
                retval = 1;
                goto exit;
        } else { /* Parent Process */
		FILE *stream;
		close( stdin_fds[0] );
		log( "Sending password" );
       		stream = fdopen (stdin_fds[1], "w");
		fprintf( stream, "%s%c", password, '\0' );
		fflush( stream );
		log( "Password sent." );
                log( "Parent proc, waiting for child." );
                logd( (int)pid );
                logd( getpid() );
                while( ( retval = waitpid( pid, &status, 0 ) ) == -1 )  {
			if( errno == EINTR ) { 
				if( sigt == 1 )
					continue;
			} 
			break;
		}
		close( stdin_fds[1] );
                log( "Parent done." );
		logd( retval );
		sigaction(SIGCHLD, &osigact, NULL);
        }
        logd( retval );
	if( retval == -1 )
		goto exit;
        if( WEXITSTATUS(status) == 0 )
                retval = 0;

exit:
        logd(retval);
        if( retval == 0 ) {
                log( "SUCCESS!" );
                return SUCCESS;
        } else {
                log( "FAILURE!" );
                return FAILURE;
        }
}

int checkUser( const char* username ) {
	struct passwd *pwd = NULL;
	int retval = FAILURE;

	func_start();
	log( username );
	if( ( pwd = (struct passwd*)getpwnam(username) ) == NULL ) {
		log("User not found!");
		errno = ENOENT;
		return FAILURE;
	}
	return SUCCESS;
}

int checkGroup( const char* groupname) {
	struct group *grp= NULL;
	int retval = FAILURE;

	func_start();
	log( groupname );
	if( ( grp = (struct group*)getgrnam(groupname) ) == NULL ) {
		log("Group not found!");
		errno = ENOENT;
		return FAILURE;
	}
	return SUCCESS;
}

int isUserInGroup( const char* username, struct group *grp ){
	int retval = FAILURE;
	char **members = NULL;

	log( "Started!" );
	log( username );

	if( grp == NULL ) {
		log( "Null group!" );
		return FAILURE;
	}
	log( "Group name:" );
	log( grp->gr_name );

	if( grp->gr_mem == NULL ){
		log( "Null Members!" );
		return FAILURE;
	}

	members = grp->gr_mem;

        while( *members && ( retval != SUCCESS ) ) {
		if( strcmp(username, *members) == 0 )
			retval = SUCCESS;
		++members;
	}	
	if( retval == SUCCESS )
		log( "User is in group!" );
	else
		log( "User is not in group!" );
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
	log( username );
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
	log( "Found AIX, using getgrset." );
	log( grset );
	cptr = groups;
	gr = strtok( grset, delims );
	while( gr != NULL ) {
		if( ( grp = getgrgid( atoi( gr ) ) ) != NULL ) {
			log( grp->gr_name );
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
	log( "Not AIX, using getgrent cycle." );
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
	log( groups );
	log( "Done!" );	
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

    /* Was a new password supplied? */
    if (newPassword != NULL && newPasswordLength > 0)
    {
        rc = DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED;
        goto exit;
    }


	if( ( rc = checkUser( user ) ) != SUCCESS ) {
		if( errno == ENOENT )
			rc = DB2SEC_PLUGIN_BADUSER;
		else 
			rc = DB2SEC_PLUGIN_UNKNOWNERROR;
		log( "Error checking user." );
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
    }

exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
 
   if( rc == DB2SEC_PLUGIN_BADUSER )
        log("Bad User!");
   else if( rc == DB2SEC_PLUGIN_BADPWD)
        log("Bad Password!");
    else if ( rc == DB2SEC_PLUGIN_OK )
        log( "OK!" );
    else
        log( "Unknown Error!" );

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

		msg[511]='\0';			/* ensure NULL terminated */
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

    uid = getuid();
    pwd = (struct passwd*)getpwuid(uid);
    if( pwd != NULL )
	log(pwd->pw_name);
    user = pwd->pw_name; 
    /* Check the length */
    if (user != NULL)
    {
        length = strlen(user);
        if (length > SQL_AUTHID_SZ)
        {
            *errorMessage = "Default user name (from DB2DEFAULTUSER) too long";
            rc = DB2SEC_PLUGIN_BADUSER;
            goto exit;
        }

        strcpy(authID, user);
        *authIDLength = length;
        strcpy(userid, user);
        *useridLength = length;
    }
    else
    {
        *errorMessage = "DB2DEFAULTUSER not defined";
	log("DB2DEFAULTUSER not defined");
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
    if( rc == DB2SEC_PLUGIN_BADUSER )
	log("Bad User!");
    else if ( rc == DB2SEC_PLUGIN_OK )
	log( "OK!" );
    else
	log( "Unknown Error!" );

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

		msg[511]='\0';			/* ensure NULL terminated */
		logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "LookupGroups: authID too long";
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    memcpy(localAuthID, authID, authIDLength);
    localAuthID[authIDLength] = '\0';
    log( localAuthID );

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
	log( "Done!" );
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
	log( "Done!" );
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

		msg[511]='\0';			/* ensure NULL terminated */
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
