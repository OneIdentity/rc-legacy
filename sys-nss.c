/********************************************************************
 * * (c) 2007 Quest Software, Inc. All rights reserved.
 * * All rights reserved.
 * *
 * * Author:  Seth Ellsworth
 * *
 * * Company: Quest Software, Inc.
 * *
 * * Purpose: Authenticate a username/password through PAM
 * *
 * * Notes:   Change to use the wanted serivce, uses sys-auth<bits> right now.
 * *          If you get a warning on line 71, probably means you need
 * *          to set the OS correctly in the Makefile.
 * *
 * * Legal:   This script is provided under the terms of the
 * *          "Resouce Central License" avaliable at
 * *          http://rc.vintela.com/topics/db2_sys-auth/license.php
 * *          or in the included LICENSE file.
 * ********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef AIX
#include <usersec.h>
#endif

#include "log.h"

static int debug = 0;

static const char *arg = NULL;

void usage(void)
{
        fprintf( stderr,
                "Usage: %s <cmd> <info>\n"
                "       Commands:\n"
                "                1: getpwuid\n"
                "                2: getpwnam\n"
                "                3: getgrnam\n"
                "                4: get groups\n",
                arg);
        exit ( 1 );
}

int pwuid( const char *in )
{
    uid_t uid = atoi( in );
    struct passwd *pwd = NULL;
    if( (uid == 0) && 
        ( ( strlen( in ) != 1 ) || 
          ( *in != '0' ) ) )
    {
        fprintf( stderr, "Input <%s> not parsed\n", in );
        return 3;
    }

    if( (pwd = (struct passwd*)getpwuid( uid ) ) == NULL )
    {
        return ENOENT;
    }

    fprintf( stdout, "%s", pwd->pw_name );
    fflush( stdout );
    
    return 0;
}

int _pwnam( const char *username, gid_t *pgid )
{
    struct passwd *pwd = NULL;
    int retval = 3;

    if( ( pwd = (struct passwd*)getpwnam(username) ) == NULL ) 
    {
        if( errno == 0 )
        {
            /* pthreads sets a 'different' errno, so assume ENOENT. */
            errno = ENOENT;
        }
#if defined( AIX )
        /* Since this process might have a setauthdb restictionon it, un-set. */
        setauthdb( NULL, NULL );
        if( ( pwd = (struct passwd*)getpwnam(username) ) != NULL )
        {
            if( pgid )
                *pgid = pwd->pw_gid;
            return 0;
        }
#endif
        return ENOENT;
    }
    if( pgid )
        *pgid = pwd->pw_gid;
    return 0;
}

int _grnam( const char *groupname )
{
    struct group *grp = NULL;
    int retval = 3;

    if( ( grp = (struct group*)getgrnam(groupname) ) == NULL ) 
    {
        if( errno == 0 )
        {
            /* pthreads sets a 'different' errno, so assume ENOENT. */
            errno = ENOENT;
        }
#if defined( AIX )
        /* Since this process might have a setauthdb restictionon it, un-set. */
        setauthdb( NULL, NULL );
        if( ( grp = (struct group*)getgrnam(groupname) ) != NULL )
            return 0;
#endif
        return ENOENT;
    }
    return 0;
}

void _lower( char *name ) {
    char * cptr = NULL;
    int count = 0;
    while( name[count] != '\0' ) {
        name[count] = tolower(name[count]);
        ++count;
    }
}

void _upper( char *name ) {
    char * cptr = NULL;
    int count = 0;
    while( name[count] != '\0' ) {
        name[count] = toupper(name[count]);
        ++count;
    }
}

int pwnam( const char *username, gid_t *pgid )
{
    char userBuffer[MAX_LINE_LENGTH];
    int rval = 3;
    memset(userBuffer, '\0', MAX_LINE_LENGTH);
    strcpy( userBuffer, username );
    _lower( userBuffer );
    if( ( rval = _pwnam( userBuffer, pgid ) ) != 0 )
    {
        rval = _pwnam( username, pgid );
    }
    if( !rval )
        fprintf( stdout, "0%c", '\0' );
    return rval;
}

int _is_user_in_group( const char* username, struct group *grp, gid_t pgid ) {
    int retval = 0, d = 0;
    struct passwd *pwd = NULL;
    char **members = NULL;

    if( grp->gr_mem == NULL ){
        return 0;
    }

    members = grp->gr_mem;

    while( *members && ( retval != 1 ) )
    {
        if( strcasecmp(username, *members) == 0 )
            retval = 1;
        ++members;
    }

    if( retval != 1 )
    {/* Add check for user-gid == group gid. */
        if( pgid == grp->gr_gid )
        {
            /* User has GID membership. */
            retval = 1;
        }
    }
    return retval;
}


int grnam( const char *groupname )
{
    char groupBuffer[MAX_LINE_LENGTH];
    int rval = 3;
    memset(groupBuffer, '\0', MAX_LINE_LENGTH);
    strcpy( groupBuffer, groupname );
    if( ( rval = _grnam( groupBuffer ) ) != 0 )
    {
        _lower( groupBuffer );
        rval = _grnam( groupBuffer );
    }
    return rval;
}

int _get_groups( const char* username, char *groups, int *numgroups ) {
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

    if( !username || username[0] == '\0' ||
            !groups || !numgroups )
    {
        return 3;
    }

    strcpy( userBuffer, username );

    _lower( userBuffer );
    if( ( rval = _pwnam( userBuffer, &pgid) ) != 0 )
    {
        if( ( rval = _pwnam( username, &pgid ) ) != 0 )
        {
            return ENOENT;
        }
        else
            _upper( userBuffer );
    }
#ifdef AIX
    /* Since we are on AIX, we can use getgrset. Get that, tokenize the
     * result, and add to the buffer as the group resolves to names.
     */
    /* New: Fall through to the other function, this combines the groups
     * so local groups are also considered.
     */
    if( ( grset = getgrset( userBuffer ) ) == NULL ) {
        return ENOENT;
    }
    cptr = groups;
    gr = strtok( grset, delims );
    while( gr != NULL ) {
        if( ( grp = getgrgid( atoi( gr ) ) ) != NULL )
        {
            length = strlen( grp->gr_name );
            if( length + (cptr - groups ) < MAX_LINE_LENGTH )
            {
                *((unsigned char*)cptr) = (unsigned char)length;
                ++cptr;
                memcpy(cptr, grp->gr_name, length );
                cptr += length;
                ++groupcount;
            }
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
                if( (length + (cptr - groups )) < MAX_LINE_LENGTH )
                {
                    *((unsigned char*)cptr) = (unsigned char)length;
                    ++cptr;
                    memcpy(cptr, gr, length );
                    cptr += length;
                    ++groupcount;
                }
            }

            while( *gr != '\0' )
                ++gr;
            ++gr;
        }
    }
    /* Add LDAP specific groups, checking for duplicates. */
    /* Uses the SEC_LIST attribute:
     *  The format of the attribute is a series of concatenated strings,
     *  each null-terminated. The last string in the series is terminated
     *  by two successive null characters.
     */
    /* Now this really isnt' the way to do it, but it gets the job done for now.
     */
    /* TODO: Refactor this whole thing to more intelligently gather all possible
     * group memberships. Maybe there is a way to find out all possible DB's,
     * and make sure to qury them. At least query the users back-end */
    if( setauthdb( "LDAP", NULL ) == 0 &&
            getuserattr( userBuffer, S_GROUPS, (void*)&grset, SEC_LIST ) == 0 )
    {
        gr = grset;
        while( *gr != '\0' )
        {
            if( strstr( groups, gr ) == NULL )
            {
                length = strlen( gr );
                if( (length + (cptr - groups )) < MAX_LINE_LENGTH )
                {
                    *((unsigned char*)cptr) = (unsigned char)length;
                    ++cptr;
                    memcpy(cptr, gr, length );
                    cptr += length;
                    ++groupcount;
                }
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
    while( ( grp = getgrent() ) != NULL ) {
        if( ( _is_user_in_group( userBuffer, grp, pgid ) ) == 1 ) 
        {
            length = strlen( grp->gr_name );
            if( ( length + (cptr - groups ) ) < MAX_LINE_LENGTH )
            {
                *((unsigned char*)cptr) = (unsigned char)length;
                ++cptr;
                memcpy(cptr, grp->gr_name, length );
                cptr += length;
                ++groupcount;
            }
        }
    }
    *cptr = '\0';
    endgrent();

    *numgroups = groupcount;
    return 0;
}

int get_groups( const char *username )
{
    int rval = 3;
    int ngroups = 0;
    char groups[MAX_LINE_LENGTH];
    memset( &groups[0], 0, MAX_LINE_LENGTH );

    if( (rval = _get_groups( username, &groups[0], &ngroups ) ) )
    {
        return rval;
    }

    fprintf( stdout, "%c%s%c", (unsigned char)ngroups, groups, '\0' );
    fflush( stdout );

    return rval;
}

int main(int argc, char* argv[])
{
    int retval = 4;

    arg = argv[0];

    /* Check usage */
    if( ( argc != 3 ) || 
        ( strlen( argv[1] ) != 1 ) || 
        ( *argv[1] < '1' ) || 
        ( *argv[1] > '4' ) )
    {
        usage();
    }

    switch( *argv[1] )
    { 
        case '1':
            retval = pwuid( argv[2] );
            break;
        case '2':
            retval = pwnam( argv[2], NULL );
            break;
        case '3':
            retval = grnam( argv[2] );
            break;
        case '4':
            retval = get_groups( argv[2] );
            break;
    }

    if( retval )
        fprintf( stdout, "%c%c", (unsigned char)(retval + 200), '\0' );

    exit( retval );
}

