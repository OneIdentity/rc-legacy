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

#include "log.h"
#include <sys/types.h>
#include <sys/stat.h>

#ifndef ctime_r
#ifdef SOLARIS
/* This is for Solaris and their incomplete posix standard.
 * If we ever start defining _POSIX_C_SOURCE >= 199506L
 * then we need to use the posix function definition. */
    extern char* ctime_r(const time_t *clock, char *buf, int len);
#else
    extern char* ctime_r(const time_t *clock, char *buf);
#endif //SOLARIS
#endif //ctime_r
#define CTIMELEN 26
static int G_log_level = -1;
static int G_log_to_syslog = -1;
static time_t G_last_check_time = 0;
static char buf[MAX_LINE_LENGTH] = { 0 };
static char msg[MAX_LINE_LENGTH] = { 0 };
static char confFile[MAX_LINE_LENGTH] = { 0 };
static char DEFAULT_CONF_FILE[MAX_LINE_LENGTH] = "/etc/sys-auth.conf";

/* How often to check the conf file for the debug level, in seconds. */
#define CHECK_INTERVAL 60

/* From file filename, locate the value(s) for the
 * specified entry.
 * NULL if either the file is not 
*/
char* GetEntryFromFile( const char *filename, const char *entry )
{
    FILE *f;
    char *cptr = NULL;
    char *rval = NULL;

    if( !filename || !entry )
        return NULL;
    
    f = fopen( filename , "r" );
    if( !f )
        return NULL;
    memset( buf, 0, MAX_LINE_LENGTH );
    while( fgets( buf, MAX_LINE_LENGTH, f ) )
    {
        /* Find the sub string */
        if( ( cptr = strstr( buf, entry ) ) != NULL )
        {
            char *cptr2 = NULL;
            int len = strlen( buf );
            
            /* Test for a comment before the entry */
            if( ( cptr2 = strchr( buf, '#' ) ) != NULL && cptr2 <= cptr )
            {
                memset( buf, 0, MAX_LINE_LENGTH );
                continue;
            }

            /* locate the '=' */
            if( ( cptr2 = strchr( buf, '=' ) ) != NULL )
            {
                /* Make sure its after the substring */
                if( cptr - buf > cptr2 - buf )
                {   
                    memset( buf, 0, MAX_LINE_LENGTH );
                    continue;
                }

                /* Re-set, cptr to just after the '=', cptr2 to the '#' or end. */
                cptr = cptr2;
                if( ( cptr2 = strchr( cptr, '#' ) ) == NULL )
                    cptr2 = &buf[ len - 1 ];
                else
                    --cptr2;

                /* Trim off from the front, first ++ is to get past the '=' */ 
                while( isspace( *(++cptr) ) && cptr < cptr2 ) ;

                /* Trim off the back. */
                while( isspace( *cptr2 ) && cptr2 > cptr )
                {
                    *cptr2 = '\0';
                    --cptr2; 
                }

                /* If we overlap, then there is nothign here. */
                if( cptr > cptr2 )
                {
                    memset( buf, 0, MAX_LINE_LENGTH );
                    continue;
                }
                
                /* If there is one item, make sure its not a '\n' or empty*/
                if( *cptr == '\n' || *cptr == '\0' )
                {
                    memset( buf, 0, MAX_LINE_LENGTH );
                    continue;
                }
                    
                rval = cptr;
                break;
            }
        }
        memset( buf, 0, MAX_LINE_LENGTH );
    }

    fclose( f );
    return rval ? rval : NULL;
}

/* Try and figure out what conf file to use. 
 * First, the instance owners, then the default. 
*/
void setConfFile( )
{
    char *user = NULL;
    struct passwd *pwd = NULL;

    user = getenv("DB2INSTANCE");
    if( user == NULL )
    {
        /* Hmm.. This should always be set. So try the uid next, then the default. 
        */
        pwd = getpwuid( getuid( ) );
    }
    else
    {
        pwd = getpwnam( user );
    }
    
    if( !pwd )
    {
        /* Didn't get anything, which should never happen, but just in case. */
        strcpy( confFile, DEFAULT_CONF_FILE );
        return;
    }

    if( pwd->pw_dir )
    {
        strcpy( confFile, pwd->pw_dir );
        strcat( confFile, "/sys-auth.conf" );
    }
    else
    {
        /* No pwd->pw_dir, which should never happen, but just in case. */
        strcpy( confFile, DEFAULT_CONF_FILE );
        return;
    }

    if( access( confFile, R_OK ) == 0 )
    {
        return;
    }

    strcpy( confFile, DEFAULT_CONF_FILE );
    return;
}

static int do_dbg( void )
{
    time_t curr_time = time( NULL );
    char *value = NULL;

    if( ( G_log_level == -1 ) ||
            ( G_last_check_time > curr_time ||
              G_last_check_time == 0 ||
              curr_time - G_last_check_time > CHECK_INTERVAL ) )
    {
        G_last_check_time = curr_time;
    }
    else
        return( G_log_level );

    setConfFile();
    value = GetEntryFromFile( confFile, "debug-level" );
    
    if( !(value == NULL) && atoi( value ) > 1 )
        G_log_level = 1;
    else
        G_log_level = 0;

    return( G_log_level );
}
#define FILE_OUT "/tmp/sys-auth.debug"
void slog( int level, const char *format, ... )
{
    va_list ap;
    char*   tmp = NULL;
    time_t  curr_time = time( NULL );
    char    curr_time_str[CTIMELEN];
    FILE    *fd = NULL;

    if( !do_dbg() )
        return;

    va_start( ap, format );

    if( (fd = fopen( FILE_OUT, "a" )) == NULL )
        return;

    /* write a time stamp without the ending '\n' */
    memset( curr_time_str, 0, CTIMELEN );
#ifdef SOLARIS
    /* This is for Solaris and their incomplete posix standard.
     *    If we ever start defining _POSIX_C_SOURCE >= 199506L
     *       then we need to use the posix function definition. */
    tmp = ctime_r( &curr_time, curr_time_str, CTIMELEN );
#else
    tmp = ctime_r( &curr_time, curr_time_str );
#endif
    if( tmp )
    {
        if( (tmp = strchr( curr_time_str, '\n' )) )
            *tmp = '\0';
        fprintf( fd, "%s: (%u) ", curr_time_str, (unsigned int)getpid() );
    }
    else
        fprintf( fd, "<no time>: (%u) ", (unsigned int)getpid() );

    /* write the log message */
    vfprintf( fd, format, ap );
    fputc( '\n', fd);
    fflush( fd );
    fclose( fd );
    chmod( FILE_OUT, S_IRWXU | S_IRWXG | S_IRWXO );
}
