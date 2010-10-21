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

#include "config.h"

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
#define CHPWFAILURE -1

#define MAX_C_BUFF 512

/********************************************************************
 * Helper functions.
 *******************************************************************/

/* Close all open fd's except for stdin, stdout, stderr. */
void 
#define MAXFD 16384
close_fds( void )
{
    long                maxfds = MAXFD;
    int i = 0;

    if( ( maxfds = sysconf(_SC_OPEN_MAX) ) > MAXFD )
        maxfds = MAXFD;
    else if( maxfds < 3 )
        maxfds = 1024

    for( i = 3; i < maxfds; ++i )
        close( i );
}

int
util_usleep( int utimeout )
{
    struct timeval      tv = { 0, 0 };
    int                 rval = 0;

    /* This is a portable millisecond sleep timer, using select */
    if( utimeout == 0 )
        return( 0 );

    tv.tv_sec = utimeout / 1000000;
    tv.tv_usec = utimeout % 1000000;

    /* Actually use the timer */
    rval = select( 0, NULL, NULL, NULL, &tv );

    /* If the select failed, return the errno back to the caller */
    if( rval < 0 )
    {
        /* If errno is zero (because of a thread problem, then return
         *          * back the -1 value from select
         *                   */
        if( errno != 0 )
            rval = errno;
    }

    return( rval );
}


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
        strcat( out, " - BAD - Unable to malloc 11KB, if on AIX move to VAS 3.1.2.47+" );
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

int vas_db2_plugin_change_password(char *username, char *password_old, char *password_new )
{
    int   retval   = 0;
    int   status   = 0;
    pid_t pid      = 0;
    int stdin_fds[] = { -1, -1 };
    int stdout_fds[] = { -1, -1 };
    char prog_path[MAX_C_BUFF];
    char prog_file[MAX_C_BUFF];
    char *cptr = NULL;
    struct passwd *pwd = NULL;
    struct passwd p;
    char buf[2048];
    int     rnum = rand();
    
    func_start();

    errno = 0;


    if ( pipe( stdin_fds ) != 0 ) { 
        retval = errno;
        if( !retval ) retval = -1;
        slog( SLOG_NORMAL, "%s: Pipe failed!", __FUNCTION__ );
        goto EXIT;
    }

    if ( pipe( stdout_fds ) != 0 ) {
        retval = errno;
        if( !retval ) retval = -1;
        slog( SLOG_CRIT, "%s: Pipe on stdout_fds failed, errno <%d>", __FUNCTION__, errno );
        goto EXIT;
    }
        
    if( ( cptr = getenv( "DB2INSTANCE" ) ) == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: Unable to obtain DB2INSTANCE environment" " variable, trying uid <%d>", __FUNCTION__, getuid() );
        getpwuid_r( getuid(), &p, buf, 2048, &pwd );
    }
    else
    { 
        getpwnam_r( cptr, &p, buf, 2048, &pwd );
    }

    if( pwd == NULL || pwd->pw_dir == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: unable to obtain running user information", __FUNCTION__ );
        retval = -1;
        goto EXIT;
    }
    
    cptr = pwd->pw_dir; 
    
    strncpy( prog_path, cptr, MAX_C_BUFF - 1);

    strcat( prog_path, "/sqllib/security" );
#ifdef __64BIT__
    strcat( prog_path, "64/plugin/sys-chpw" );
#else    
    strcat( prog_path, "32/plugin/sys-chpw" );
#endif
    strcpy( prog_file, "sys-chpw" );

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
        
        /* On AIX 5.1 lets test out LAM there. */
#ifdef AIX51
        strcat( prog_path, "/lamChPw" );
#else
        strcat( prog_path, "/pamChPw" );
#endif
        
        if( access( prog_path, X_OK ) != 0 )
        {
#ifdef AIX
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
           "in current directory, trying LAM", __FUNCTION__, prog_path );
            /* Clear off the previous look for the Pam version so we can stick
             * on the Lam version.
            */
            cptr = strrchr( prog_path, '/' );
            if( cptr )
                *cptr = '\0';
            
            strcat( prog_path, "/lamChPw" );

            if( access( prog_path, X_OK ) != 0 )
            {
                slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
                        "in current directory", __FUNCTION__, prog_path );
                retval = -1;
                goto EXIT;
            }
#else
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
           "in current directory", __FUNCTION__, prog_path );
            retval = -1;
            goto EXIT;
#endif
        }
    }

    if( ( pid = fork() ) == 0 ) /* Child Process */
    {
        close( stdin_fds[1] );
        stdin_fds[1] = -1;
        if( dup2( stdin_fds[0], STDIN_FILENO ) != STDIN_FILENO )
        {
            slog( SLOG_NORMAL, "%s: dup2 failed, errno %d", __FUNCTION__, errno );
            _exit( errno ? errno : ECHILD );
        }
        close( stdin_fds[0] );
        stdin_fds[0] = -1;

        close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( dup2( stdout_fds[1], STDOUT_FILENO ) != STDOUT_FILENO )
        {
            slog( SLOG_CRIT, "%s: dup2 failed, errno <%d>", __FUNCTION__, errno );
            _exit( errno ? errno : ECHILD );
        }
        close( stdout_fds[1] );
        stdout_fds[1] = -1;

        close_fds();
        

        if( execl( prog_path, prog_file, username, NULL ) == -1 ) 
        {
            slog( SLOG_NORMAL, "%s: execl failed executing <%s><%s> with errno <%d>", __FUNCTION__, prog_file, prog_path, errno ? errno : ECHILD );
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
        char buf[4] = { -1, 0, 0, 0 };
        int r = 0, result = 0;

        slog( SLOG_DEBUG, "%s: child process pid: <%d> <sys-chpw><%s>", __FUNCTION__, (int)pid, username );
        r = close( stdout_fds[1] );
        stdout_fds[1] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s:(%u) close failed, pipe hosed<%d><%d><%d>", __FUNCTION__,rnum, r, errno, stdout_fds[1] );


        close( stdin_fds[0] );
        stdin_fds[0] = -1;
        slog( SLOG_ALL, "%s: sending passwords to child process", __FUNCTION__ );
        stream = fdopen (stdin_fds[1], "w");
        fprintf( stream, "%s%c%s%c", password_old, '\0', password_new, '\0' );
        fclose( stream );
        stdin_fds[1] = -1;
        slog( SLOG_ALL, "%s: passwords sent", __FUNCTION__ );
READ:
        errno = 0;
        if( ( result = read( stdout_fds[0], (void*)buf, 4 ) ) <= 0 )
        {
            if( result == -1 && errno == EINTR )
                goto READ;
            slog( SLOG_EXTEND, "%s:(%u) error reading output from sys-auth for user: <%s>, errno: <%d>", __FUNCTION__,rnum,  username, errno );
            retval = EIO;
        }
        else
        {
            slog( SLOG_EXTEND, "%s:(%u) got result <%s> from reading child", __FUNCTION__,rnum, buf );
            if( isdigit( (int)buf[0] ) )
                retval = atoi( buf );
            else
                retval = DB2SEC_PLUGIN_UNKNOWNERROR;
        }
        r = close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s:(%u) second close failed, pipe hosed<%d><%d><%d>", __FUNCTION__,rnum,  r, errno, stdout_fds[0] );

        /* Just in case DB2 didn't snag it, try to reap our child. */
        /* 10ms delay */
        util_usleep( 10000 );
        waitpid( pid, &status, 0 );
        
#if 0
        slog( SLOG_DEBUG, "%s: parent process <%d> waiting for child process "
		"<%d>", __FUNCTION__, getpid(), (int)pid );
        while( ( retval = waitpid( pid, &status, 0 ) ) == -1 )  
        {
            if( errno == EINTR ) { 
                continue;
            } else if ( errno == ECHILD )
            {
                /* Something else reaped our child? I guess we have to assume succcess */
                retval = 0;
            }
            else
                slog( SLOG_DEBUG, "%s: waitpid failed, errno <%d>", __FUNCTION__, errno );
            break;
        }
        slog( SLOG_DEBUG, "%s: child process returned with value <%d>", 
		__FUNCTION__, retval );
#endif
    }

EXIT:
        if( retval == 0 ) {
                return DB2SEC_PLUGIN_OK;
        } else {
            slog( SLOG_EXTEND, "%s: Failed authentication attempt for user "
                       "<%s>, error <%d>", __FUNCTION__, username, retval );
            switch ( retval )    
            {
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
            }
            return( retval );
        }
} 

int vas_db2_plugin_auth_user(char *username, char *password) {
    int   retval   = 0;
    int   status   = 0;
    pid_t pid      = 0;
    int stdin_fds[] = { -1, -1 };
    int stdout_fds[] = { -1, -1 };
    char prog_path[MAX_C_BUFF];
    char prog_file[MAX_C_BUFF];
    char *cptr = NULL;
    struct passwd *pwd = NULL;
    struct passwd p;
    char buf[2048];
    
    func_start();

    errno = 0;


    if ( pipe( stdin_fds ) != 0 ) { 
        retval = errno;
        if( !retval ) retval = -1;
        slog( SLOG_CRIT, "%s: Pipe on stdin_fds failed, errno <%d>", __FUNCTION__, errno );
        goto EXIT;
    }
        
    if ( pipe( stdout_fds ) != 0 ) { 
        retval = errno;
        if( !retval ) retval = -1;
        slog( SLOG_CRIT, "%s: Pipe on stdout_fds failed, errno <%d>", __FUNCTION__, errno );
        goto EXIT;
    }

    if( ( cptr = getenv( "DB2INSTANCE" ) ) == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: Unable to obtain DB2INSTANCE environment"
       " variable, trying uid <%d>", __FUNCTION__, getuid() );
        getpwuid_r( getuid(), &p, buf, 2048, &pwd );
    }
    else
    { 
        getpwnam_r( cptr, &p, buf, 2048, &pwd );
    }

    if( pwd == NULL || pwd->pw_dir == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: unable to obtain running user information",
        __FUNCTION__ );
        retval = -1;
        goto EXIT;
    }
    
    cptr = pwd->pw_dir; 
    
    strncpy( prog_path, cptr, MAX_C_BUFF - 1);

    strcat( prog_path, "/sqllib/security" );
#ifdef __64BIT__
    strcat( prog_path, "64/plugin/sys-auth" );
#else    
    strcat( prog_path, "32/plugin/sys-auth" );
#endif
    strcpy( prog_file, "sys-auth" );

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
        
        /* On AIX 5.1 lets test out LAM there. */
#ifdef AIX51
        strcat( prog_path, "/lamAuth" );
#else
        strcat( prog_path, "/pamAuth" );
#endif
        
        if( access( prog_path, X_OK ) != 0 )
        {
#ifdef AIX
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
           "in current directory, trying LAM", __FUNCTION__, prog_path );
            /* Clear off the previous look for the Pam version so we can stick
             * on the Lam version.
            */
            cptr = strrchr( prog_path, '/' );
            if( cptr )
                *cptr = '\0';
            
            strcat( prog_path, "/lamAuth" );

            if( access( prog_path, X_OK ) != 0 )
            {
                slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
                        "in current directory", __FUNCTION__, prog_path );
                retval = -1;
                goto EXIT;
            }
#else
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
           "in current directory", __FUNCTION__, prog_path );
            retval = -1;
            goto EXIT;
#endif
        }
    }

    if( ( pid = fork() ) == 0 ) /* Child Process */
    {
        close( stdin_fds[1] );
        stdin_fds[1] = -1;
        if( dup2( stdin_fds[0], STDIN_FILENO ) != STDIN_FILENO )
        {
            slog( SLOG_CRIT, "%s: dup2 failed, errno <%d>", __FUNCTION__, errno );
            _exit( errno ? errno : ECHILD );
        }
        close( stdin_fds[0] );
        stdin_fds[0] = -1;

        close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( dup2( stdout_fds[1], STDOUT_FILENO ) != STDOUT_FILENO )
        {
            slog( SLOG_CRIT, "%s: dup2 failed, errno <%d>", __FUNCTION__, errno );
            _exit( errno ? errno : ECHILD );
        }
        close( stdout_fds[1] );
        stdout_fds[1] = -1;
        
        close_fds();

        if( execl( prog_path, prog_file, username, NULL ) == -1 ) 
        {
            slog( SLOG_NORMAL, "%s: execl failed executing <%s><%s> with errno <%d>", __FUNCTION__, prog_file, prog_path, errno ? errno : ECHILD );
            _exit( errno ? errno : ECHILD );
        }
    } 
    else if ( pid < 0 ) /* Fork failed */
    {        
    	slog( SLOG_CRIT, "%s: Fork Failed, errno <%d>", __FUNCTION__, errno );
    	retval = -1;
    	goto EXIT;
    } 
    else  /* Parent Process */
    {
        FILE *stream = NULL;
        int r = 0;
        int result = 0;
        char buf[4] = { -1, 0, 0, 0 };

        slog( SLOG_DEBUG, "%s: child process pid: <%d> <sys-auth>", __FUNCTION__, (int)pid );
        r = close( stdin_fds[0] );
        stdin_fds[0] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s: close failed, pipe hosed<%d><%d><%d>", __FUNCTION__, r, errno, stdin_fds[0] );

        r = close( stdout_fds[1] );
        stdout_fds[1] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s: close failed, pipe hosed<%d><%d><%d>", __FUNCTION__, r, errno, stdout_fds[1] );

        slog( SLOG_ALL, "%s: sending password to child process", __FUNCTION__ );
        stream = fdopen (stdin_fds[1], "w");
        if( stream == NULL )
            slog( SLOG_CRIT, "%s: fdopen of <%d> failed <%d>", __FUNCTION__, stdin_fds[0], errno );
        fprintf( stream, "%s%c", password, '\0' );
        r = fclose( stream );
        if( r != 0 )
            slog( SLOG_CRIT, "%s: fclose of <%d> failed <%d>", __FUNCTION__, stdin_fds[1], errno );

        slog( SLOG_ALL, "%s: password sent", __FUNCTION__ );

READ:
        errno = 0;
        if( ( result = read( stdout_fds[0], (void*)buf, 4 ) ) <= 0 )
        {
            if( result == -1 && errno == EINTR )
                goto READ;
            slog( SLOG_EXTEND, "%s: error reading output from sys-auth for user: <%s>, errno: <%d>", __FUNCTION__,  username, errno );
            retval = EIO;
        }
        else
        {
            if( isdigit( (int)buf[0] ) )
                retval = atoi( buf );
            else 
                retval = DB2SEC_PLUGIN_UNKNOWNERROR;
            slog( SLOG_EXTEND, "%s: got result <%d> from reading child", __FUNCTION__, (int)buf[0] );
        }
        r = close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s: second close failed, pipe hosed<%d><%d><%d>", __FUNCTION__,  r, errno, stdout_fds[0] );

        /* Just in case DB2 didn't snag it, try to reap our child. */
        /* 10ms delay */
        util_usleep( 10000 );
        waitpid( pid, &status, 0 );
#if 0 
        slog( SLOG_DEBUG, "%s: parent process <%d> waiting for child process " "<%d>", __FUNCTION__, getpid(), (int)pid );
        while( ( retval = waitpid( pid, &status, 0 ) ) == -1 )  
        {
            if( errno == EINTR ) { 
                slog( SLOG_DEBUG, "%s: EINTR <%d>", __FUNCTION__, retval );
                continue;
            } else if ( errno == ECHILD )
            {
                /* Something else reaped our child? I guess we have to assume succcess */
                slog( SLOG_DEBUG, "%s: ECHILD <%d>", __FUNCTION__, retval );
            }
            else
                slog( SLOG_DEBUG, "%s: waitpid failed, errno <%d>", __FUNCTION__, errno );
            break;
        }
        slog( SLOG_DEBUG, "%s: child process returned with value <%d>", __FUNCTION__, retval );
#endif
    }

EXIT:
    if( retval == 0 ) {
        return DB2SEC_PLUGIN_OK;
    } else {
        slog( SLOG_EXTEND, "%s: Failed authentication attempt for user "
                "<%s>, error <%d>", __FUNCTION__, username, retval );
        switch ( retval )
        {
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
        }
        return( retval );
    }
}

int vas_db2_plugin_outcall_getgroups( const char *username, char groups[], int *ngroups ) {
    int   retval   = 0;
    int   status   = 0;
    pid_t pid      = 0;
    int stdout_fds[] = { -1, -1 };
    char prog_path[MAX_C_BUFF];
    char prog_file[MAX_C_BUFF];
    char *cptr = NULL;
    char cuid[11];
    struct passwd *pwd = NULL;
    struct passwd p;
    char buf[2048];
    char group_back[MAX_LINE_LENGTH + 2];
    
    func_start();

    errno = 0;

    if ( pipe( stdout_fds ) != 0 ) { 
        retval = errno;
        if( !retval ) retval = -1;
        slog( SLOG_CRIT, "%s: Pipe failed, errno <%d>", __FUNCTION__, errno );
        goto EXIT;
    }

    if( ( cptr = getenv( "DB2INSTANCE" ) ) == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: Unable to obtain DB2INSTANCE environment"
       " variable, trying uid <%d>", __FUNCTION__, getuid() );
        getpwuid_r( getuid(), &p, buf, 2048, &pwd );
    }
    else
    { 
        getpwnam_r( cptr, &p, buf, 2048, &pwd );
    }

    if( pwd == NULL || pwd->pw_dir == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: unable to obtain running user information", __FUNCTION__ );
        retval = -1;
        goto EXIT;
    }
    
    cptr = pwd->pw_dir; 
    
    strncpy( prog_path, cptr, MAX_C_BUFF - 1);

    strcat( prog_path, "/sqllib/security" );
#ifdef __64BIT__
    strcat( prog_path, "64/plugin/sys-nss" );
#else    
    strcat( prog_path, "32/plugin/sys-nss" );
#endif
    strcpy( prog_file, "sys-nss" );

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
        
        strcat( prog_path, "/sys-nss" );
        
        if( access( prog_path, X_OK ) != 0 )
        {
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
           "in current directory", __FUNCTION__, prog_path );
            retval = -1;
            goto EXIT;
        }
    }
    if( ( pid = fork() ) == 0 ) /* Child Process */
    {
        
        close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( dup2( stdout_fds[1], STDOUT_FILENO ) != STDOUT_FILENO )
        {
            slog( SLOG_CRIT, "%s: dup2 failed, errno <%d>", __FUNCTION__, errno );
            _exit( errno ? errno : ECHILD );
        }
        close( stdout_fds[1] );
        stdout_fds[1] = -1;

        close_fds();

        if( execl( prog_path, prog_file, "4", username, NULL ) == -1 ) 
        {
            slog( SLOG_NORMAL, "%s: execl failed executing <%s><%s> with errno <%d>", __FUNCTION__, prog_file, prog_path, errno ? errno : ECHILD );
            _exit( errno ? errno : ECHILD );
        }
    } 
    else if ( pid < 0 ) /* Fork failed */
    {        
	    slog( SLOG_NORMAL, "%s: Fork Failed!", __FUNCTION__ );
    	retval = -1;
    	goto EXIT;
    } 
    else  /* Parent Process */
    {
        FILE *stream;
        int result = 0;
        int r = 0;
        slog( SLOG_DEBUG, "%s: child process pid: <%d> <sys-nss><4><%s>", __FUNCTION__, (int)pid, username );

        r = close( stdout_fds[1] );
        stdout_fds[1] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s: close failed, pipe hosed<%d><%d><%d>", __FUNCTION__, r, errno, stdout_fds[1] );

        slog( SLOG_ALL, "%s: reading groups from child process", __FUNCTION__  );
READ:
        errno = 0;
        if( ( result = read( stdout_fds[0], (void*)group_back, MAX_LINE_LENGTH + 1 ) ) <= 0 )
        { 
            if( result == -1 && errno == EINTR )
                goto READ;
            slog( SLOG_EXTEND, "%s: error reading groups from sys-nss for user: <%s>, errno: <%d> fd:<%d>", __FUNCTION__,  username, errno, stdout_fds[0] );
            retval = EIO;
        }

        slog( SLOG_DEBUG, "%s: parent process <%d> waiting for child process " "<%d>", __FUNCTION__,  getpid(), (int)pid );
        /* 10ms delay */
        util_usleep( 10000 );
        waitpid( pid, &status, 0 );
        if( (unsigned char)group_back[0] > 200 )
            retval = (unsigned char)group_back[0] - 200;
        else
            retval = 0;
#if 0
        while( ( retval = waitpid( pid, &status, 0 ) ) == -1 )  
        {
            if( errno == EINTR ) { 
                continue;
            } else if ( errno == ECHILD )
            {
                /* Something else reaped our child? I guess we have to assume succcess */
                retval = 0;
            }
            else
                slog( SLOG_DEBUG, "%s: waitpid failed, errno <%d>", __FUNCTION__,  errno );
            break;
        }
#endif
        r = close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s: second close failed, pipe hosed<%d><%d><%d>", __FUNCTION__,  r, errno, stdout_fds[0] );
        slog( SLOG_DEBUG, "%s: child process returned with value <%d>", __FUNCTION__, retval );
    }

EXIT:
    if( retval == 0 ) {
        char *ptr;
        int groupsize = 0;
        int group_count = 0;
        groupsize = (int)group_back[1];
        ptr = &group_back[2];

        *ngroups = (unsigned char)group_back[0];
        memcpy( groups, &group_back[1], MAX_LINE_LENGTH );

        do {
            int oldsize = groupsize;
            groupsize = (int)ptr[oldsize];
            ptr[ oldsize ] = ',';
            ptr = &ptr[oldsize + 1];
        } while ( groupsize != 0 && ++group_count <= *ngroups );
        ptr[groupsize - 1] = '\0';
        slog( SLOG_EXTEND, "%s: groups for user <%s>: <%s>", __FUNCTION__, username, &group_back[2] );
        
        return DB2SEC_PLUGIN_OK;
    } else {
        slog( SLOG_EXTEND, "%s: Failed reading groups for user <%s>, error <%d>", __FUNCTION__, username, retval );
        switch ( retval )
        {
            case 2:
                retval = DB2SEC_PLUGIN_BADUSER;
                break;
            default:
                retval = DB2SEC_PLUGIN_UNKNOWNERROR;
        }
        return( retval );
    }
}

int vas_db2_plugin_outcall_getuser( uid_t uid, char username[] ) {
    int   retval   = 0;
    int   status   = 0;
    pid_t pid      = 0;
    int stdout_fds[] = { -1, -1 };
    char prog_path[MAX_C_BUFF];
    char prog_file[MAX_C_BUFF];
    char *cptr = NULL;
    char cuid[11];
    struct passwd *pwd = NULL;
    struct passwd p;
    char buf[2048];
    
    func_start();

    errno = 0;

    if ( pipe( stdout_fds ) != 0 ) { 
        retval = errno;
        if( !retval ) retval = -1;
        slog( SLOG_CRIT, "%s: Pipe failed, errno <%d>", __FUNCTION__, errno );
        goto EXIT;
    }

    if( ( cptr = getenv( "DB2INSTANCE" ) ) == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: Unable to obtain DB2INSTANCE environment"
       " variable, trying uid <%d>", __FUNCTION__, getuid() );
        getpwuid_r( getuid(), &p, buf, 2048, &pwd );
    }
    else
    { 
        getpwnam_r( cptr, &p, buf, 2048, &pwd );
    }

    if( pwd == NULL || pwd->pw_dir == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: unable to obtain running user information",
        __FUNCTION__ );
        retval = -1;
        goto EXIT;
    }
    
    cptr = pwd->pw_dir; 
    
    strncpy( prog_path, cptr, MAX_C_BUFF - 1);

    strcat( prog_path, "/sqllib/security" );
#ifdef __64BIT__
    strcat( prog_path, "64/plugin/sys-nss" );
#else    
    strcat( prog_path, "32/plugin/sys-nss" );
#endif
    strcpy( prog_file, "sys-nss" );

    if( access( prog_path, X_OK ) != 0 )
    {
        slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s>, "
        "trying sys-nss in the current directory",
        __FUNCTION__, prog_path );
        memset( prog_path, 0, MAX_C_BUFF);
        if( getcwd( prog_path, MAX_C_BUFF) == NULL )
        {
            slog( SLOG_NORMAL,
        "%s: getcwd FAILED with errno <%d> string <%s>. Trying .",
        __FUNCTION__, errno, strerror( errno ) );
            strcpy( prog_path, "." );
        }
        
        strcat( prog_path, "/sys-nss" );
        
        if( access( prog_path, X_OK ) != 0 )
        {
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
           "in current directory", __FUNCTION__, prog_path );
            retval = -1;
            goto EXIT;
        }
    }

    sprintf( cuid, "%u\0", uid );
    
    if( ( pid = fork() ) == 0 ) /* Child Process */
    {
        close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( dup2( stdout_fds[1], STDOUT_FILENO ) != STDOUT_FILENO )
        {
            slog( SLOG_CRIT, "%s: dup2 failed, errno <%d>", __FUNCTION__, errno );
            retval = errno;
            if( !retval ) retval = 1;
            goto EXIT;
        }
        close( stdout_fds[1] );
        stdout_fds[1] = -1;


        close_fds();

        if( execl( prog_path, prog_file, "1", cuid, NULL ) == -1 ) 
        {
            slog( SLOG_NORMAL, "%s: execl failed executing <%s><%s> with errno <%d>", __FUNCTION__, prog_file, prog_path, errno ? errno : ECHILD );
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
        int result = 0;
        int got_name = 0;

        slog( SLOG_DEBUG, "%s: child process pid: <%d> <sys-nss><1><%s>", __FUNCTION__, (int)pid, cuid );
        close( stdout_fds[1] );
        stdout_fds[1] = -1;
        slog( SLOG_ALL, "%s: reading name from child process", __FUNCTION__ );
READ:        
        if( ( result = read( stdout_fds[0], (void*)username, SQL_AUTHID_SZ ) ) <= 0 )
        { 
            if( result == -1 && errno == EINTR )
                goto READ;
            slog( SLOG_EXTEND, "%s: error reading name from sys-nss for user with uid <%u>, errno <%d>", __FUNCTION__, uid, errno );
            retval = EIO;
        }
        else
        {
            slog( SLOG_EXTEND, "%s: read name from sys-nss for user with uid <%u>, bytes: <%d> name: <%s><%u>", __FUNCTION__, uid, result, username, (unsigned char)username[0] );
        }

        slog( SLOG_DEBUG, "%s: parent process <%d> waiting for child process "
		"<%d>", __FUNCTION__, getpid(), (int)pid );
        /* 10ms delay */
        util_usleep( 10000 );
        waitpid( pid, &status, 0 );
        if( (unsigned char)username[0] > 200 )
            retval = (unsigned char)username[0] - 200;
        else
            retval = 0;

#if 0
        while( ( retval = waitpid( pid, &status, 0 ) ) == -1 )  
        {
            if( errno == EINTR ) { 
                continue;
            } else if ( errno == ECHILD )
            {
                /* Something else reaped our child? I guess we have to assume succcess */
                retval = 0;
            }
            else
                slog( SLOG_CRIT, "%s: waitpid failed, errno <%d>", __FUNCTION__, errno );
            break;
        }
#endif

        close( stdout_fds[0] );
        stdout_fds[0] = -1;
        slog( SLOG_DEBUG, "%s: child process returned with value <%d>", __FUNCTION__, retval );
    }

EXIT:
    if( retval == 0 ) {
        slog( SLOG_EXTEND, "%s: read username for user with uid <%u>, name <%s>", __FUNCTION__, uid, username, retval );
        return DB2SEC_PLUGIN_OK;
    } else {
        slog( SLOG_EXTEND, "%s: Failed reading username for user with uid <%u>, error <%d>", __FUNCTION__, uid, retval );
        switch ( retval )
        {
            case 2:
                retval = DB2SEC_PLUGIN_BADUSER;
                break;
            default:
                retval = DB2SEC_PLUGIN_UNKNOWNERROR;
        }
        return( retval );
    }

}

int vas_db2_plugin_outcall_check_user( const char *username ) {
    int   retval   = 0;
    int   status   = 0;
    pid_t pid      = 0;
    int stdout_fds[] = { -1, -1 };
    char prog_path[MAX_C_BUFF];
    char prog_file[MAX_C_BUFF];
    char *cptr = NULL;
    char cuid[11];
    struct passwd *pwd = NULL;
    struct passwd p;
    char buf[2048];
    
    func_start();

    errno = 0;

    if ( pipe( stdout_fds ) != 0 ) {
        retval = errno;
        if( !retval ) retval = -1;
        slog( SLOG_CRIT, "%s: Pipe failed, errno <%d>", __FUNCTION__, errno );
        goto EXIT;
    }

    if( ( cptr = getenv( "DB2INSTANCE" ) ) == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: Unable to obtain DB2INSTANCE environment"
       " variable, trying uid <%d>", __FUNCTION__, getuid() );
        getpwuid_r( getuid(), &p, buf, 2048, &pwd );
    }
    else
    { 
        getpwnam_r( cptr, &p, buf, 2048, &pwd );
    }

    if( pwd == NULL || pwd->pw_dir == NULL ) 
    {
        slog( SLOG_NORMAL, "%s: unable to obtain running user information",
        __FUNCTION__ );
        retval = -1;
        goto EXIT;
    }
    
    cptr = pwd->pw_dir; 
    
    strncpy( prog_path, cptr, MAX_C_BUFF - 1);

    strcat( prog_path, "/sqllib/security" );
#ifdef __64BIT__
    strcat( prog_path, "64/plugin/sys-nss" );
#else    
    strcat( prog_path, "32/plugin/sys-nss" );
#endif
    strcpy( prog_file, "sys-nss" );

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
        
        strcat( prog_path, "/sys-nss" );
        
        if( access( prog_path, X_OK ) != 0 )
        {
            slog( SLOG_NORMAL, "%s: FAILED finding auth program <%s> "
           "in current directory", __FUNCTION__, prog_path );
            retval = -1;
            goto EXIT;
        }
    }
        

    if( ( pid = fork() ) == 0 ) /* Child Process */
    {
        close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( dup2( stdout_fds[1], STDOUT_FILENO ) != STDOUT_FILENO )
        {
            slog( SLOG_CRIT, "%s: dup2 failed, errno <%d>", __FUNCTION__, errno );
            retval = errno;
            if( !retval ) retval = 1;
            goto EXIT;
        }
        close( stdout_fds[1] );
        stdout_fds[1] = -1;
        

        close_fds();

        if( execl( prog_path, prog_file, "2", username, NULL ) == -1 ) 
        {
            slog( SLOG_NORMAL, "%s: execl failed executing <%s><%s> with errno <%d>", __FUNCTION__, prog_file, prog_path, errno ? errno : ECHILD );
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
        char buf[4] = { -1, 0, 0, 0 };
        int r = 0;
        int result = 0;
        slog( SLOG_DEBUG, "%s: child process pid: <%d> <sys-nss><2><%s>", __FUNCTION__, (int)pid, username );
        r = close( stdout_fds[1] );
        stdout_fds[1] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s: close failed, pipe hosed<%d><%d><%d>", __FUNCTION__, r, errno, stdout_fds[1] );

READ:
        errno = 0;
        if( ( result = read( stdout_fds[0], (void*)buf, 4 ) ) <= 0 )
        {
            if( result == -1 && errno == EINTR )
                goto READ;
            slog( SLOG_EXTEND, "%s: error reading output from sys-nss for user: <%s>, errno: <%d>", __FUNCTION__, username, errno );
            retval = EIO;
        }
        else
        {
            if( isdigit( (int)buf[0] ) )
                retval = atoi( buf );
            else
                retval = DB2SEC_PLUGIN_UNKNOWNERROR;
        }
        r = close( stdout_fds[0] );
        stdout_fds[0] = -1;
        if( r != 0 )
            slog( SLOG_CRIT, "%s: second close failed, pipe hosed<%d><%d><%d>", __FUNCTION__,  r, errno, stdout_fds[0] );

        /* 10ms delay */
        util_usleep( 10000 );
        waitpid( pid, &status, 0 );
    }

EXIT:
    if( retval == 0 ) {
        return DB2SEC_PLUGIN_OK;
    } else {
        slog( SLOG_EXTEND, "%s: Failed checking username <%s>, error <%d>", __FUNCTION__, username, retval );
        switch ( retval )
        {
            case 2:
                retval = DB2SEC_PLUGIN_BADUSER;
                break;
            default:
                retval = DB2SEC_PLUGIN_UNKNOWNERROR;
        }
        return( retval );
    }

}

/* Return the pgid so it doesn't have to be determined again. */
int vas_db2_plugin_check_user( const char* username ) {
    func_start();
    
    slog( SLOG_DEBUG, "%s: checking user <%s>", __FUNCTION__, username );
    if( vas_db2_plugin_outcall_check_user( username ) != 0 ) 
    {
        slog( SLOG_DEBUG, "%s: user <%s> not found.",
                          __FUNCTION__,
                          username );
        return FAILURE;
    }
FOUND:
    slog( SLOG_DEBUG, "%s: found user <%s>", __FUNCTION__, username );
    return SUCCESS;
}

int vas_db2_plugin_check_group( const char* groupname) {
//    struct group *grp= NULL;
    int retval = FAILURE;
    struct group grp;
    struct group *pgrp = NULL;
    char buf[8192];

    func_start();
    slog( SLOG_DEBUG, "%s: checking group <%s>", __FUNCTION__, groupname );
    if( ( getgrnam_r(groupname, &grp, buf, 1024, &pgrp) ) != 0 || !pgrp ) {
        slog( SLOG_EXTEND, "%s: group <%s> not found", __FUNCTION__, groupname);
        errno = ENOENT;
        return FAILURE;
    }
    slog( SLOG_DEBUG, "%s: found group <%s><%s>", __FUNCTION__, groupname,
	    pgrp->gr_name );
    return SUCCESS;
}

int vas_db2_plugin_is_user_in_group( const char* username, struct group *grp, gid_t pgid ) {
    int retval = FAILURE, d = 0;
    struct passwd *pwd = NULL;
    char **members = NULL;

    func_start_all();

    if( grp == NULL ) {
        slog( SLOG_ALL, "%s: this should never happen, but called with a NULL "
		"group struct. ", __FUNCTION__ );
        return FAILURE;
    }
    slog( SLOG_ALL, "%s: checking group <%s> for user <%s>", __FUNCTION__, 
	    grp->gr_name, username );

    if( grp->gr_mem == NULL ){
        slog( SLOG_ALL, "%s: group has no members", __FUNCTION__ );
        return FAILURE;
    }

    members = grp->gr_mem;

    while( *members && ( retval != SUCCESS ) ) 
    {
        if( strcasecmp(username, *members) == 0 )
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
        /*
        if( pgid == grp->gr_gid )
        {
        */
            /* User has GID membership. *//*
            slog( SLOG_DEBUG, "%s: user <%s> has group membership in <%s> "
		    "through implicit pgid->gid.", __FUNCTION__, username, 
		    grp->gr_name );
            retval = SUCCESS;
        }
        else*/
        {
            slog( SLOG_ALL, "%s: user <%s> is not in group <%s>", 
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
    char loc_groups[MAX_LINE_LENGTH];
    memset(userBuffer, '\0', MAX_LINE_LENGTH);
    func_start();

    if( !username || username[0] == '\0' ||
        !groups || !numgroups )
    {
        slog( SLOG_CRIT, "%s: called with an invalid paramater", 
		__FUNCTION__ );
        return DB2SEC_PLUGIN_BAD_INPUT_PARAMETERS;
    }

    vas_db2_plugin_outcall_getgroups( username, groups, numgroups );

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

    /*
    if( ( rc = vas_db2_plugin_check_user( user, NULL ) ) != SUCCESS ) {
        vas_db2_plugin_lower( user );
        if( ( rc = vas_db2_plugin_check_user( user, NULL ) ) != SUCCESS){
            rc = DB2SEC_PLUGIN_BADUSER;
            goto exit;
        }
    }*/

    rc = DB2SEC_PLUGIN_OK;

    /* Was a new password supplied? */
    /* If so, change it. This will test the validate 
     * the old password as well.
    */
    if( newPassword != NULL && 
        newPasswordLength > 0 &&
        password != NULL &&
        passwordLength > 0 )
    {
        int rval = DB2SEC_PLUGIN_BADPWD;
        char password_old[128];
        char password_new[128];
        
        memcpy(password_old, password, passwordLength);
        password_old[passwordLength] = '\0';
        
        memcpy(password_new, newPassword, newPasswordLength);
        password_new[newPasswordLength] = '\0';

        rc = vas_db2_plugin_change_password( user , password_old, password_new );
        goto exit;
    }
    /* Check the password, if supplied. */
    else if (password != NULL && passwordLength > 0)
    {
        char pwdBuf[128];
        memcpy(pwdBuf, password, passwordLength);
        pwdBuf[passwordLength] = '\0';
        rc = vas_db2_plugin_auth_user( user , pwdBuf );
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
 
    switch( rc ) 
    {
        case DB2SEC_PLUGIN_BADUSER:
            slog( SLOG_NORMAL, 
                  "%s: unknown user <%s>", 
                  __FUNCTION__, 
                  user );
            break;
        case DB2SEC_PLUGIN_BADPWD:
            slog( SLOG_NORMAL, 
                  "%s: failed authentication for user <%s>", 
            	  __FUNCTION__,
                  user );
            break;
        case DB2SEC_PLUGIN_BAD_NEWPASSWORD: 
            slog( SLOG_NORMAL, 
                  "%s: password change unsuccessful for user <%s>, bad new password",
                  __FUNCTION__, 
                  user );
            break;
        case DB2SEC_PLUGIN_PWD_EXPIRED: 
            slog( SLOG_NORMAL, 
                  "%s: password expired for user <%s>",
                  __FUNCTION__, 
                  user );
            break;
        case DB2SEC_PLUGIN_OK: 
            slog( SLOG_NORMAL, 
                  "%s: successful authentication for user <%s>", 
        		  __FUNCTION__, 
                  user );
            break;
        default:
            slog( SLOG_NORMAL, 
                  "%s: unknown error <%d> while trying to authenticate user"
	              " <%s>", 
                  __FUNCTION__, 
                  rc, 
                  user );
            break;
    }
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
    int rc = DB2SEC_PLUGIN_INVALIDUSERORGROUP;
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
        snprintf(msg, 512, "vas_db2_plugin_does_auth_id_exist: "
		"authID too long (%d bytes): %s... (truncated)",
		authIDLength, localAuthID);

        msg[511]='\0';            /* ensure NULL terminated */
        logFunc(DB2SEC_LOG_ERROR, msg, strlen(msg));

        *errorMessage = "vas_db2_plugin_does_auth_id_exist: authID too long";
        rc = DB2SEC_PLUGIN_INVALIDUSERORGROUP;
        goto FINISHED;
    }

    memcpy(localAuthID, authID, authIDLength);
    localAuthID[authIDLength] = '\0';


    if( ( rc = vas_db2_plugin_check_user( localAuthID ) ) != SUCCESS ) {
        rc = DB2SEC_PLUGIN_INVALIDUSERORGROUP;
        goto FINISHED;
    }
    rc = DB2SEC_PLUGIN_OK;

FINISHED:
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
    char user[SQL_AUTHID_SZ + 1];

    *errorMessage = NULL;
    *errorMessageLength = 0;

    authID[0] = '\0';
    *authIDLength = 0;
    userid[0] = '\0';
    *useridLength = 0;
    if( domain ) domain[0] = '\0';
    if( domainLength ) *domainLength = 0;
    if( domainType ) *domainType = DB2SEC_USER_NAMESPACE_UNDEFINED;
    int uid = 0;
    struct passwd *pwd = NULL; 
    func_start();
    memset( user, 0, sizeof(user) );

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
    if (DB2SEC_PLUGIN_REAL_USER_NAME == useridType) 
        uid = getuid(); 
    else 
        uid = geteuid(); 

    if( (rc = vas_db2_plugin_outcall_getuser( uid, user ) ) != DB2SEC_PLUGIN_OK  )
        goto exit;

    if( *user == '\0' )
    {
        rc=DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }
        
    /* Check the length */
    length = strlen(user);
    if (length > SQL_AUTHID_SZ)
    {
        *errorMessage = "user name too long";
        slog( SLOG_NORMAL, "%s: user name <%s> too long", 
        __FUNCTION__, user );
        rc = DB2SEC_PLUGIN_BADUSER;
        goto exit;
    }

    strcpy(authID, user);
    *authIDLength = length;
    strcpy(userid, user);
    *useridLength = length;

exit:
    if (*errorMessage != NULL)
    {
        *errorMessageLength = strlen(*errorMessage);
    }
    if( rc == DB2SEC_PLUGIN_BADUSER )
        slog(  SLOG_EXTEND, "%s: failed on user <%s>, uid <%d>", __FUNCTION__, 
		user ? user : "UNKNOWN", uid );
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
    int rc = DB2SEC_PLUGIN_BADUSER;
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
    
    rc = vas_db2_plugin_outcall_getgroups( localAuthID, *groupList, &ngroups );
    if( rc == 0 )
    rc = DB2SEC_PLUGIN_OK;    
//    slog( SLOG_DEBUG, "%s: vas_db2_plugin_find_groups_for_user for user <%s>"
//	   " returned groups <%s>", __FUNCTION__, localAuthID, 
//	   (ngroups > 0) ? (char *)*groupList : "None" );
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

    if (groupName == NULL)
    {
        *errorMessage = "NULL group name supplied";
        rc = DB2SEC_PLUGIN_INVALIDUSERORGROUP;
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
        rc = DB2SEC_PLUGIN_INVALIDUSERORGROUP;
        goto exit;
    }

    memcpy(localGroupName, groupName, groupNameLength);
    localGroupName[groupNameLength] = '\0';

    if ( vas_db2_plugin_check_group( localGroupName ) != SUCCESS )
    {
        vas_db2_plugin_lower( localGroupName );
        if( vas_db2_plugin_check_group( localGroupName ) != SUCCESS )
            rc = DB2SEC_PLUGIN_INVALIDUSERORGROUP;
    }


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
SQL_API_RC SQL_API_FN vas_db2_server_plugin_terminate(char **errorMessage,
                           db2int32 *errorMessageLength)
{
    *errorMessage = NULL;
    *errorMessageLength = 0;
    func_start();
    return(DB2SEC_PLUGIN_OK);
}

/* vas_db2_plugin_plugin_terminate()
 * There is no cleanup required when this plugin is unloaded.
 */
SQL_API_RC SQL_API_FN vas_db2_client_plugin_terminate(char **errorMessage,
                           db2int32 *errorMessageLength)
{
    *errorMessage = NULL;
    *errorMessageLength = 0;
    func_start();
    return(DB2SEC_PLUGIN_OK);
}

/* vas_db2_plugin_plugin_terminate()
 * There is no cleanup required when this plugin is unloaded.
 */
SQL_API_RC SQL_API_FN vas_db2_group_plugin_terminate(char **errorMessage,
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
    p->db2secValidatePassword = &vas_db2_plugin_check_password;
    p->db2secGetAuthIDs = vas_db2_plugin_get_auth_ids;
    p->db2secDoesAuthIDExist = vas_db2_plugin_does_auth_id_exist;
    p->db2secFreeToken = vas_db2_plugin_free_token;
    p->db2secFreeErrormsg = vas_db2_plugin_free_error_message;
    p->db2secServerAuthPluginTerm = vas_db2_server_plugin_terminate;

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
    p->db2secClientAuthPluginTerm = &vas_db2_client_plugin_terminate;

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
    p->db2secPluginTerm = &vas_db2_group_plugin_terminate;

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

