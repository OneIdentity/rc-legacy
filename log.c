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

static int G_log_level = -1;
static int G_log_to_syslog = -1;
static time_t G_last_check_time = 0;
static char buf[MAX_LINE_LENGTH];
static char msg[MAX_LINE_LENGTH];
static char confFile[MAX_LINE_LENGTH];
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



void slog_init( )
{
    char *value = NULL;
    time_t curr_time = time( NULL );
    
    /* Check bad entry, un-set entry, and too long. */
    /* Should only return if the curr and last only differ by less then interval.
    */
    if( G_last_check_time > curr_time || 
        G_last_check_time == 0 ||
        curr_time - G_last_check_time > CHECK_INTERVAL )
    {
        G_last_check_time = curr_time;
    }
    else
    {
        return;
    }
    
    setConfFile();
    value = GetEntryFromFile( confFile, "debug-level" );
    
    if( value == NULL )
    {
        G_log_level = SLOG_NORMAL;
        G_log_to_syslog = 1;
        goto FINISH;
    }
    else
    {
        int val = atoi( value );
        if( val > SLOG_ALL || val < SLOG_CRIT )
            G_log_level = SLOG_NORMAL;
        else
            G_log_level = val;
        G_log_to_syslog = 1;
    }
    


FINISH:
    if( G_log_to_syslog )
    {
        int lvl;
        strcpy( msg, "sys-auth" );

#ifdef VERSION
        strcat( msg, "_"VERSION );
#endif
        
#ifdef LINUX
        lvl = LOG_AUTHPRIV;
#else
        lvl = LOG_AUTH;
#endif    
        value = getenv("DB2INSTANCE");
        if( value && strlen(value) > 0 )
        {
            strcat( msg, " - " );
            strcat( msg, value );
        }
        openlog( msg, LOG_PID, lvl );
    }
}

void slog( int level, const char* format, ... )
{
    va_list ap;
    va_start( ap, format );
    slog_init();
    if( level > G_log_level )
        return;
#ifdef LINUX
    vsyslog( LOG_NOTICE | LOG_AUTHPRIV, format, ap );
#else
    vsyslog( LOG_NOTICE | LOG_AUTH, format, ap );
#endif    
    va_end( ap );
}
