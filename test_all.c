/* (c) 2007 Quest Software, Inc. All rights reserved. */
#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include<sys/wait.h>
#include "db2secPlugin.h"
#include "csuite.h"
#include "log.h"

#define GOOD_VALUE "GOOD_VALUE"
char test_conf[512] = "./test.conf";


void vas_db2_plugin_sig_handle( int signo ) {
    int status = 0;
    while( waitpid( 0, &status, 0 ) != -1 )
        continue; 
    return;
}


void *handle = NULL;
#ifdef __64BIT__
char filename[512] = "./sys-auth64.so."VERSION;
#else
char filename[512] = "./sys-auth32.so."VERSION;
#endif
char *funcNameClient = "db2secClientAuthPluginInit";
char *funcNameServer = "db2secServerAuthPluginInit";
char *funcNameGroup = "db2secGroupPluginInit";
char *funcNameVersion = "vas_db2_plugin_get_version";
int  do_version = 0;

SQL_API_RC SQL_API_FN( *ClientInit )(
                       db2int32,
                       void*,
                       db2secLogMessage*,
                       char**,
                       db2int32* ); 

SQL_API_RC SQL_API_FN( *ServerInit )(
                       db2int32,
                       void*,
                       db2secGetConDetails*,
                       db2secLogMessage*,
                       char**,
                       db2int32* ); 

SQL_API_RC SQL_API_FN( *GroupInit )(
                       db2int32,
                       void *,
                       db2secLogMessage *,
                       char     **,
                       db2int32 *);

const char *( *GetVersion)( );

struct userid_password_client_auth_functions_1 fnsC;

struct userid_password_server_auth_functions_1 fnsS;

struct group_functions_1 fnsG;


void testOpen( Test *pTest )
{
    struct stat stb;
    if( stat( filename, &stb ) != 0 )
    {
        fprintf( stderr, 
                 "%s: unable to find file <%s>, exiting.\n", 
                 __FUNCTION__, 
                 filename ? filename : "<EMPTY>" );
        exit( 1 );
    }

    handle = dlopen( filename, RTLD_LAZY );
    ct_test( pTest, handle != NULL );
    if( handle == NULL )
    {
        fprintf( stderr, 
                 "%s: unable to open file <%s>, exiting.\n", 
                 __FUNCTION__, 
                 filename ? filename : "<EMPTY>" );
        exit( 1 );
    }
}

void testLoadC( Test *pTest )
{
    char *err = NULL;
    if( handle )
    {
        ClientInit = dlsym( handle, funcNameClient );
        ct_test( pTest, ( ( err = dlerror( ) ) == NULL ) );
        if( err != NULL )
            fprintf( stderr, "%s: dlsym error <%s>\n", __FUNCTION__, err );
    }
}

void testLoadS( Test *pTest )
{
    char *err = NULL;
    if( handle )
    {
        ServerInit = dlsym( handle, funcNameServer );
        ct_test( pTest, ( ( err = dlerror( ) ) == NULL ) );
        if( err != NULL )
            fprintf( stderr, "%s: dlsym error <%s>\n", __FUNCTION__, err );

    }
}

void testLoadG( Test *pTest )
{
    char *err = NULL;
    if( handle )
    {
        GroupInit = dlsym( handle, funcNameGroup );
        ct_test( pTest, ( ( err = dlerror( ) ) == NULL ) );
        if( err != NULL )
            fprintf( stderr, "%s: dlsym error <%s>\n", __FUNCTION__, err );
    }
}

void testLoadV( Test *pTest )
{
    char *err = NULL;
    if( handle )
    {
        GetVersion = dlsym( handle, funcNameVersion );
        ct_test( pTest, ( ( err = dlerror( ) ) == NULL ) );
        if( err != NULL )
            fprintf( stderr, "%s: dlsym error <%s>\n", __FUNCTION__, err );
        else
            do_version = 0;
    }
}

void testCheckV( Test *pTest )
{
    const char *ptr = NULL;
    if( do_version )
        ptr = GetVersion();
    else
        ptr = NULL; 
    ct_test( pTest, !ptr || strcmp( ptr, VERSION ) == 0 );
}

void testFillfnsC( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    ClientInit( version, (void*)&fnsC, NULL, &errMsg, &msgLen );
    ct_test( pTest, msgLen == 0 );
}

void testFillfnsS( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    ServerInit( version, (void*)&fnsS, NULL, NULL, &errMsg, &msgLen );
    ct_test( pTest, msgLen == 0 );
}

void testFillfnsG( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    GroupInit( version, (void*)&fnsG, NULL, &errMsg, &msgLen );
    ct_test( pTest, msgLen == 0 );
}

void testAuthBadPW( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    rval = fnsS.db2secValidatePassword( "root", 4, NULL, 0, 0, "bad", 3, 
	    NULL, 0, NULL, 0, 0, NULL, &errMsg, &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADPWD );
}

void testAuthBadUser( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    rval = fnsS.db2secValidatePassword( "%123", 4, NULL, 0, 0, "bad", 3, 
	    NULL, 0, NULL, 0, 0, NULL, &errMsg, &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADUSER );
}

void testAuthNoPWBAD( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    uint uid = getuid();
    char *username = NULL;
    struct passwd *pwd = getpwuid( uid );
    if( pwd )
        username = strdup( pwd->pw_name );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADPWD );
    if( username ) free( username );
}

void testAuthNoBinary( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    char *password = (char*)GetEntryFromFile( test_conf, "password" );
    if( password )
        password = (char *)strdup( password );
    rename( "./pamAuth", "./pamAuth.save" );
//    system( "echo one; ls -al ./pamAuth*; mv ./pamAuth ./pamAuth.save ; echo ; ls -la ./pamAuth*; if [ -f ./lamAuth ] ; then mv ./lamAuth ./lamAuth.save ; fi" );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    //system( "echo two; ls -la pamAuth* ; mv ./pamAuth.save ./pamAuth ; echo ; ls -la pamAuth*; if [ -f ./lamAuth.save ] ; then mv ./lamAuth.save ./lamAuth; fi" );
    rename( "./pamAuth.save", "./pamAuth" );
    ct_test( pTest, rval == DB2SEC_PLUGIN_UNKNOWNERROR );
    if( username ) free( username );
    if( password ) free( password );
}

void testAuthNoPW( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    uint uid = getuid();
    char *username = NULL;
    struct passwd *pwd = getpwuid( uid );
    if( pwd )
        username = strdup( pwd->pw_name );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       DB2SEC_USERID_FROM_OS, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    if( username ) free( username );
}

void testAuthGood( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    char *password = (char*)GetEntryFromFile( test_conf, "password" );
    if( password )
        password = (char *)strdup( password );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    if( username ) free( username );
    if( password ) free( password );
}

void testAuthBad( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       "bad", 
                                       3, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADPWD );
    if( username ) free( username );
}

void testAuthGoodUpper( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
    {
        username = (char *)strdup( username );
        username[0] = toupper( username[0] );
    }

    char *password = (char*)GetEntryFromFile( test_conf, "password" );
    if( password )
        password = (char *)strdup( password );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    if( username ) free( username );
    if( password ) free( password );
}

void testAuthGoodMustChange( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "user_must_change_pwd" );
    if( username )
        username = (char *)strdup( username );
    char *password = (char*)GetEntryFromFile( test_conf, "password" );
    if( password )
        password = (char *)strdup( password );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_PWD_EXPIRED );
    if( username ) free( username );
    if( password ) free( password );
}

void testAuthGoodChPwBadOldPwd( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       "bad", 
                                       3, 
                                       "1", 
                                       1, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADPWD );
    if( username ) free( username );
}

void testAuthGoodChPwBadNewPwd( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "user_must_change_pwd" );
    if( username )
        username = (char *)strdup( username );
    char *password = (char*)GetEntryFromFile( test_conf, "password" );
    if( password )
        password = (char *)strdup( password );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       "1", 
                                       1, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BAD_NEWPASSWORD );
    if( username ) free( username );
    if( password ) free( password );
}

void testAuthGoodChPw( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "user_must_change_pwd" );
    char *tmp_passwd = "Go0dPasSw0rd";
    if( username )
        username = (char *)strdup( username );
    char *password = (char*)GetEntryFromFile( test_conf, "password" );
    if( password )
        password = (char *)strdup( password );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       tmp_passwd, 
                                       strlen(tmp_passwd), 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       tmp_passwd, 
                                       strlen( tmp_passwd), 
                                       NULL,
                                       0,
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       tmp_passwd, 
                                       strlen( tmp_passwd), 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       NULL, 
                                       0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    if( username ) free( username );
    if( password ) free( password );
}

void testAuthGoodCantChange( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *username = (char*)GetEntryFromFile( test_conf, "username-cant-change-pwd" );
    char *tmp_passwd = "Go0dPasSw0rd";
    if( username )
        username = (char *)strdup( username );
    char *password = (char*)GetEntryFromFile( test_conf, "password" );
    if( password )
        password = (char *)strdup( password );
    rval = fnsS.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):3, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):3, 
                                       tmp_passwd, 
                                       strlen( tmp_passwd), 
                                       NULL, 
                                       0, 
                                       0, 
                                       NULL, 
                                       &errMsg, 
                                       &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BAD_NEWPASSWORD );
    if( username ) free( username );
    if( password ) free( password );
}

void testUserExists( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int free_user = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *user = (char*)GetEntryFromFile( test_conf, "username" );
    if( user ) 
    {
        free_user = 1;
        user = (char *)strdup( user );
    }
    rval = fnsS.db2secDoesAuthIDExist( user?user:"baduser",
                                       user?strlen(user):7,
                                       &errMsg,
                                       &msgLen );
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    if( free_user ) free( user );                                  
}

void testBadUserExists( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int free_user = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *user = (char*)GetEntryFromFile( test_conf, "bad_user" );
    if( user ) 
    {
        free_user = 1;
        user = (char *)strdup( user );
    }
    rval = fnsS.db2secDoesAuthIDExist( user?user:"baduser",
                                       user?strlen(user):7,
                                       &errMsg,
                                       &msgLen );
    ct_test( pTest, rval == DB2SEC_PLUGIN_INVALIDUSERORGROUP );
    if( free_user ) free( user );                                  
}

void testGetAuthIDs( Test *pTest )
{
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char authID[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 authIDLength = 0;
    char sauthID[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 sauthIDLength = 0;
    char userid[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 useridLength = 0;
    db2int32 sessionType = 0;
    char *name = "bobSmith";
    int len = strlen( name );
    rval = fnsS.db2secGetAuthIDs( name,
                                  len,
                                  "",
                                  0,
                                  0,
                                  "",
                                  0,
                                  NULL,
                                  authID,
                                  &authIDLength,
                                  sauthID,
                                  &sauthIDLength,
                                  userid,
                                  &useridLength,
                                  &sessionType,
                                  &errMsg,
                                  &msgLen );
                               
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK && 
	    !strncmp( name, authID, len ) && 
	    !strncmp( name, sauthID, len ) && 
	    !strncmp( name, userid, len ) );
}

void testGetAuthIDsBAD( Test *pTest )
{
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char authID[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 authIDLength = 0;
    char sauthID[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 sauthIDLength = 0;
    char userid[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 useridLength = 0;
    db2int32 sessionType = 0;
    /*
     * What makes this bad is a username longer then allowed, so it 
     * should return BADUSER  */
    char *name = "ReallyLongUserNameLongerThen128CharReallyLongUserNameLongerThen128CharReallyLongUserNameLongerThen128CharReallyLongUserNameLongerThen128Char";
    rval = fnsS.db2secGetAuthIDs( name,
                                  strlen( name ),
                                  "",
                                  0,
                                  0,
                                  "",
                                  0,
                                  NULL,
                                  authID,
                                  &authIDLength,
                                  sauthID,
                                  &sauthIDLength,
                                  userid,
                                  &useridLength,
                                  &sessionType,
                                  &errMsg,
                                  &msgLen );
                               
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADUSER );
}

void testUserUpperExists( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *user = "Root";

    rval = fnsS.db2secDoesAuthIDExist( user?user:"baduser",
                                       user?strlen(user):7,
                                       &errMsg,
                                       &msgLen );
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
}

void testGetLoginContextBadUser( Test *pTest )
{
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    struct passwd *pwd= NULL;
    char authID[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 authIDLength = 0;
    char userid[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 useridLength = 0;
    int rval = 0;
#ifdef HPUX
        setresuid( -1, 999999, -1 );
#else
        seteuid( 999999 );
#endif


    if( ( pwd = getpwuid(geteuid()) ) != NULL )
    {
        ct_test( pTest, /* FAILED to set uid to bad uid*/ 0 );
        return;
    }

    rval = fnsC.db2secGetDefaultLoginContext( authID,
                                              &authIDLength,
                                              userid,
                                              &useridLength,
                                              DB2SEC_PLUGIN_EFFECTIVE_USER_NAME,
                                              NULL, /* domain */
                                              NULL, /* domain length */
                                              NULL, /* domain type */
                                              NULL, /* database name */
                                              0 , /* database name length */
                                              NULL, /* token */
                                              &errMsg,
                                              &msgLen );
#ifdef HPUX
    setresuid( -1, 0, -1 );
#else
    seteuid( 0 );
#endif
    setuid( 0 );
    ct_test( pTest, ( rval == DB2SEC_PLUGIN_BADUSER ) );

}

void testGetLoginContextEffictive( Test *pTest )
{
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    struct passwd *pwd= NULL;
    char authID[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 authIDLength = 0;
    char userid[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 useridLength = 0;
    int rval = 0;

    if( ( pwd = getpwuid(geteuid()) ) == NULL )
    {
        ct_test( pTest, /* FAILED to get euid */ 0 );
        return;
    }

    rval = fnsC.db2secGetDefaultLoginContext( authID,
                                              &authIDLength,
                                              userid,
                                              &useridLength,
                                              DB2SEC_PLUGIN_EFFECTIVE_USER_NAME,
                                              NULL, /* domain */
                                              NULL, /* domain length */
                                              NULL, /* domain type */
                                              NULL, /* database name */
                                              0 , /* database name length */
                                              NULL, /* token */
                                              &errMsg,
                                              &msgLen );
    ct_test( pTest, ( rval == DB2SEC_PLUGIN_OK ) );
    ct_test( pTest, strcmp( authID, pwd->pw_name ) == 0 );
    if( strcmp( authID, pwd->pw_name ) != 0 )
        fprintf( stderr, "%s: authid: <%s> pw_name: <%s>\n", __FUNCTION__, authID, pwd->pw_name );

	ct_test( pTest, strcmp( userid, pwd->pw_name ) == 0 );

}

void testGetLoginContextReal( Test *pTest )
{
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    struct passwd *pwd= NULL;
    char authID[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 authIDLength = 0;
    char userid[32]; /* Going off of SQL_AUTHID_SZ limit */
    db2int32 useridLength = 0;
    int rval = 0;

    if( ( pwd = getpwuid(getuid()) ) == NULL )
    {
        ct_test( pTest, /* FAILED to get euid */ 0 );
        return;
    }

    rval = fnsC.db2secGetDefaultLoginContext( authID,
                                              &authIDLength,
                                              userid,
                                              &useridLength,
                                              DB2SEC_PLUGIN_REAL_USER_NAME,
                                              NULL, /* domain */
                                              NULL, /* domain length */
                                              NULL, /* domain type */
                                              NULL, /* database name */
                                              0 , /* database name length */
                                              NULL, /* token */
                                              &errMsg,
                                              &msgLen );
    ct_test( pTest, ( rval == DB2SEC_PLUGIN_OK ) );
	ct_test( pTest, strcmp( authID, pwd->pw_name ) == 0 );
	ct_test( pTest, strcmp( userid, pwd->pw_name ) == 0 );

}

void testGroupExists( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int free_group = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *group = (char*)GetEntryFromFile( test_conf, "user_in_group" );
    if( group ) 
    {
        free_group = 1;
        group = (char *)strdup( group );
    }
    rval = fnsG.db2secDoesGroupExist( group?group:"badgroup",
                                      group?strlen(group):8,
                                      &errMsg,
                                      &msgLen );
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    if( free_group ) free( group );                                  
}

void testGroupUpperExists( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int free_group = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *group = (char*)GetEntryFromFile( test_conf, "local_group_upper" );
    if( group ) 
    {
        free_group = 1;
        group = (char *)strdup( group );
    }
    rval = fnsG.db2secDoesGroupExist( group?group:"badgroup",
                                      group?strlen(group):8,
                                      &errMsg,
                                      &msgLen );
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    if( free_group ) free( group );                                  
}

void testGroupExistsBad( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int free_group = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *group = (char*)GetEntryFromFile( test_conf, "bad_group" );
    if( group ) 
    {
        free_group = 1;
        group = (char *)strdup( group );
    }
    rval = fnsG.db2secDoesGroupExist( group?group:"badgroup",
                                      group?strlen(group):8,
                                      &errMsg,
                                      &msgLen );
    ct_test( pTest, rval == DB2SEC_PLUGIN_INVALIDUSERORGROUP );
    if( free_group ) free( group );                                  
}

void testGroupMemberPGid( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int in_group = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *groupList = NULL;
    db2int32 numGroups = 0;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    char *group = (char*)GetEntryFromFile( test_conf, "user_in_group_pgid" );
    if( group ) 
        group = (char *)strdup( group );
    else
        group = "bad";

    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):3, //authidlen
                                        NULL, //userid
                                        0, //useridlen
                                        NULL, //usernamespace
                                        0, //usernamespacelen
                                        0, //usernamespacetype
                                        NULL, //dbname
                                        0, //dbnamlen
                                        NULL, //token
                                        0, //tokentype
                                        0, //location
                                        NULL, //authpluginname
                                        0, //authpluginnamelen
                                        (void **)&groupList,
                                        &numGroups,
                                        &errMsg, 
                                        &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );

    /* See if we should print out the group list received. */
    if( rval == DB2SEC_PLUGIN_OK &&
        groupList &&
        groupList[0] != '\0' )
    {
        char *ptr; 
        int groupsize = 0;
        groupsize = (int)groupList[0];
        ptr = &groupList[1];
        do 
        {   
            /*
	     * Need to store off the next groups size first, 
	     * before we overwrite with '\0'
	     */
            int oldsize = groupsize;
            groupsize = (int)ptr[oldsize];
            ptr[ oldsize ] = '\0';
            if( strcmp( group, ptr ) == 0 )
            {
                in_group = 1;
                break; 
            }
            ptr = &ptr[oldsize + 1];
        } while ( groupsize != 0 );
    }

    if( username ) free( username );
    if( group ) free( group );

    fnsG.db2secFreeGroupListMemory( groupList,
                                    &errMsg,
                                    &msgLen );
    ct_test( pTest, in_group == 1 );
}

void testGroupMember( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int in_group = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *groupList = NULL;
    db2int32 numGroups = 0;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    char *group = (char*)GetEntryFromFile( test_conf, "user_in_group" );
    if( group ) 
        group = (char *)strdup( group );
    else
        group = "bad";
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):3, //authidlen
                                        NULL, //userid
                                        0, //useridlen
                                        NULL, //usernamespace
                                        0, //usernamespacelen
                                        0, //usernamespacetype
                                        NULL, //dbname
                                        0, //dbnamlen
                                        NULL, //token
                                        0, //tokentype
                                        0, //location
                                        NULL, //authpluginname
                                        0, //authpluginnamelen
                                        (void **)&groupList,
                                        &numGroups,
                                        &errMsg, 
                                        &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );

    /* See if we should print out the group list received. */
    if( rval == DB2SEC_PLUGIN_OK &&
        groupList &&
        groupList[0] != '\0' )
    {
        char *ptr; 
        int groupsize = 0;
        groupsize = (int)groupList[0];
        ptr = &groupList[1];
        do 
        {   
            /*
	     * Need to store off the next groups size first, 
	     * before we overwrite with '\0'
	     */
            int oldsize = groupsize;
            groupsize = (int)ptr[oldsize];
            ptr[ oldsize ] = '\0';
            if( strcmp( group, ptr ) == 0 )
            {
                in_group = 1;
                break; 
            }
            ptr = &ptr[oldsize + 1];
        } while ( groupsize != 0 );
    }

    if( username ) free( username );
    if( group ) free( group );

    fnsG.db2secFreeGroupListMemory( groupList,
                                    &errMsg,
                                    &msgLen );
    ct_test( pTest, in_group == 1 );
}

void testGroupNotMember( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    int in_group = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *groupList = NULL;
    db2int32 numGroups = 0;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    char *group = (char*)GetEntryFromFile( test_conf, "user_not_in_group" );
    if( group ) 
        group = (char *)strdup( group );
    else
        group = "bad";
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):3, //authidlen
                                        NULL, //userid
                                        0, //useridlen
                                        NULL, //usernamespace
                                        0, //usernamespacelen
                                        0, //usernamespacetype
                                        NULL, //dbname
                                        0, //dbnamlen
                                        NULL, //token
                                        0, //tokentype
                                        0, //location
                                        NULL, //authpluginname
                                        0, //authpluginnamelen
                                        (void **)&groupList,
                                        &numGroups,
                                        &errMsg, 
                                        &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );

    /* See if we should print out the group list received. */
    if( rval == DB2SEC_PLUGIN_OK &&
        groupList &&
        groupList[0] != '\0' )
    {
        char *ptr; 
        int groupsize = 0;
        groupsize = (int)groupList[0];
        ptr = &groupList[1];
        do 
        {   
	    /*
             * Need to store off the next groups size first, 
	     * before we overwrite with '\0'
	     */
            int oldsize = groupsize;
            groupsize = (int)ptr[oldsize];
            ptr[ oldsize ] = '\0';
            if( strcmp( group, ptr ) == 0 )
            {
                in_group = 1;
                break; 
            }
            ptr = &ptr[oldsize + 1];
        } while ( groupsize != 0 );
    }

    if( username ) free( username );
    if( group ) free( group );

    fnsG.db2secFreeGroupListMemory( groupList,
                                    &errMsg,
                                    &msgLen );
    ct_test( pTest, in_group == 0 );
}

void testGroupsForUser( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *groupList = NULL;
    db2int32 numGroups = 0;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    char *show_groups = NULL;
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):3, //authidlen
                                        NULL, //userid
                                        0, //useridlen
                                        NULL, //usernamespace
                                        0, //usernamespacelen
                                        0, //usernamespacetype
                                        NULL, //dbname
                                        0, //dbnamlen
                                        NULL, //token
                                        0, //tokentype
                                        0, //location
                                        NULL, //authpluginname
                                        0, //authpluginnamelen
                                        (void **)&groupList,
                                        &numGroups,
                                        &errMsg, 
                                        &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );

    /* See if we should print out the group list received. */
    if( rval == DB2SEC_PLUGIN_OK &&
        groupList &&
        groupList[0] != '\0' &&
        ( show_groups = (char*)GetEntryFromFile( test_conf, "show_groups" ) ) &&
        show_groups[0] != '\0' &&
        ( rval = strcmp( show_groups, "true" ) ) == 0 )
    {
        char *ptr; 
        int groupsize = 0;
        groupsize = (int)groupList[0];
        ptr = &groupList[1];
        fprintf( stdout, "User <%s> is in the following groups:\n", 
		username?username:"bad" );
        do 
        {   
	    /*
             * Need to store off the next groups size first, 
	     * before we overwrite with '\0'
	     */
            int oldsize = groupsize;
            groupsize = (int)ptr[oldsize];
            ptr[ oldsize ] = '\0';
            fprintf( stdout, "\tGroup: <%s>\n", ptr );
            ptr = &ptr[oldsize + 1];
        } while ( groupsize != 0 );
    }

    if( username ) free( username );

    fnsG.db2secFreeGroupListMemory( groupList,
                                    &errMsg,
                                    &msgLen );
}

void testGroupLimits( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *groupList = NULL;
    db2int32 numGroups = 0;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
        username = (char *)strdup( username );
    char *show_groups = NULL;
    char cmd[1024];
    int is_in_group_1 = 0,
        is_in_group_150 = 0;

    snprintf( cmd, 1024, "cp /etc/group /etc/group.save && echo | awk 'BEGIN {for (i=1; i<=150; ++i) print \"group_\" i \":x:\" i+10000 \":%s\" }' >> /etc/group", username );
    system( cmd );
    
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):3, //authidlen
                                        NULL, //userid
                                        0, //useridlen
                                        NULL, //usernamespace
                                        0, //usernamespacelen
                                        0, //usernamespacetype
                                        NULL, //dbname
                                        0, //dbnamlen
                                        NULL, //token
                                        0, //tokentype
                                        0, //location
                                        NULL, //authpluginname
                                        0, //authpluginnamelen
                                        (void **)&groupList,
                                        &numGroups,
                                        &errMsg, 
                                        &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    system( "mv /etc/group.save /etc/group && chmod 644 /etc/group" );

    /* See if we should print out the group list received. */
    if( rval == DB2SEC_PLUGIN_OK &&
        groupList &&
        groupList[0] != '\0' )
    {
        char *ptr; 
        int groupsize = 0;
        groupsize = (int)groupList[0];
        ptr = &groupList[1];
        do 
        {   
	    /* Need to store off the next groups size first, 
	     * before we overwrite with '\0'
	     */
            int oldsize = groupsize;
            groupsize = (int)ptr[oldsize];
            ptr[ oldsize ] = '\0';
            if( strcmp( "group_1", ptr ) == 0 )
                is_in_group_1 = 1;
            if( strcmp( "group_150", ptr ) == 0 )
                is_in_group_150 = 1;
            ptr = &ptr[oldsize + 1];
        } while ( groupsize != 0 );
    }

    if( username ) free( username );

    ct_test( pTest, is_in_group_1 == 1 );
    ct_test( pTest, is_in_group_150 == 0 );
    fnsG.db2secFreeGroupListMemory( groupList,
                                    &errMsg,
                                    &msgLen );
}

void testGroupsForUserBadUser( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *groupList = NULL;
    db2int32 numGroups = 0;
    char *username = (char*)GetEntryFromFile( test_conf, "bad_user" );
    if( username )
        username = (char *)strdup( username );
    char *show_groups = NULL;
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):3, //authidlen
                                        NULL, //userid
                                        0, //useridlen
                                        NULL, //usernamespace
                                        0, //usernamespacelen
                                        0, //usernamespacetype
                                        NULL, //dbname
                                        0, //dbnamlen
                                        NULL, //token
                                        0, //tokentype
                                        0, //location
                                        NULL, //authpluginname
                                        0, //authpluginnamelen
                                        (void **)&groupList,
                                        &numGroups,
                                        &errMsg, 
                                        &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADUSER );
    fnsG.db2secFreeGroupListMemory( groupList,
                                    &errMsg,
                                    &msgLen );

    if( username ) free( username );
}

void testGroupsForUserUpper( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *groupList = NULL;
    db2int32 numGroups = 0;
    char *username = (char*)GetEntryFromFile( test_conf, "username" );
    if( username )
    {
        username = (char *)strdup( username );
        username[0] = toupper( username[0] );
    }
    char *show_groups = NULL;
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):3, //authidlen
                                        NULL, //userid
                                        0, //useridlen
                                        NULL, //usernamespace
                                        0, //usernamespacelen
                                        0, //usernamespacetype
                                        NULL, //dbname
                                        0, //dbnamlen
                                        NULL, //token
                                        0, //tokentype
                                        0, //location
                                        NULL, //authpluginname
                                        0, //authpluginnamelen
                                        (void **)&groupList,
                                        &numGroups,
                                        &errMsg, 
                                        &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
    fnsG.db2secFreeGroupListMemory( groupList,
                                    &errMsg,
                                    &msgLen );

    if( username ) free( username );
}

void testCloseLib( Test *pTest )
{
    int rc = 0;
    if( handle )
    {
        rc = dlclose( handle );
        ct_test( pTest, rc == 0 );
        if( rc )
            fprintf( stderr, "%s: dlclose error <%s>\n", __FUNCTION__, 
		    dlerror() );
    }
    else
        ct_test( pTest, /* NO HANDLE */ 0 );
}

void testCloseServer( Test *pTest )
{
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    fnsS.db2secServerAuthPluginTerm( &errMsg,
                                     &msgLen );
    ct_test( pTest, msgLen == 0 );
}

void testCloseClient( Test *pTest )
{
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    fnsC.db2secClientAuthPluginTerm( &errMsg,
                                     &msgLen );
    ct_test( pTest, msgLen == 0 );
}

void testCloseGroup( Test *pTest )
{
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    fnsG.db2secPluginTerm( &errMsg,
                           &msgLen );
    ct_test( pTest, msgLen == 0 );
}

void testConfMissing( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "missing" );
    ct_test( pTest, err == NULL );
}

void testConfBackwards( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "backwards" );
    ct_test( pTest, err == NULL );
}

void testConfEmpty( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "empty" );
    ct_test( pTest, err == NULL );
}

void testConfWSEmpty( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "WSEmpty" );
    ct_test( pTest, err == NULL );
}

void testConfWSFront( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "WSFront" );
    ct_test( pTest, strcmp( GOOD_VALUE, err?err:"" ) == 0 );
}

void testConfWSEnd( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "WSEnd" );
    ct_test( pTest, strcmp( GOOD_VALUE, err?err:"" ) == 0 );
}

void testConfWSComment( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "WSComment" );
    ct_test( pTest, strcmp( GOOD_VALUE, err?err:"" ) == 0 );
}

void testConfWSCommentEmpty( Test *pTest )
{
    char *err = NULL;
    err = (char*)GetEntryFromFile( test_conf, "WSCommentEmpty" );
    ct_test( pTest, err == NULL );
}

Test *GetLogTests()
{
    Test* pTest = ct_create( "Logging", NULL );
    bool rc;
    rc = ct_addTestFun( pTest, testConfMissing );
    rc = ct_addTestFun( pTest, testConfBackwards );
    rc = ct_addTestFun( pTest, testConfEmpty );
    rc = ct_addTestFun( pTest, testConfWSEmpty );
    rc = ct_addTestFun( pTest, testConfWSFront );
    rc = ct_addTestFun( pTest, testConfWSEnd );
    rc = ct_addTestFun( pTest, testConfWSComment );
    rc = ct_addTestFun( pTest, testConfWSCommentEmpty );
    assert( rc );
    return pTest;
}

Test *GetStartTests()
{
    Test* pTest = ct_create( "Library loading tests", NULL );
    bool rc = ct_addTestFun( pTest, testOpen );
    rc = ct_addTestFun( pTest, testLoadS );
    rc = ct_addTestFun( pTest, testLoadC );
    rc = ct_addTestFun( pTest, testLoadG );
    rc = ct_addTestFun( pTest, testLoadV );
    rc = ct_addTestFun( pTest, testFillfnsS );
    rc = ct_addTestFun( pTest, testFillfnsC );
    rc = ct_addTestFun( pTest, testFillfnsG );
    rc = ct_addTestFun( pTest, testCheckV );
    assert( rc );
    return pTest;
}

Test *GetServerTests()
{
    Test* pTest = ct_create( "Sys-auth library Server", NULL );
    bool rc = ct_addTestFun( pTest, testAuthBadPW );
    rc = ct_addTestFun( pTest, testAuthBadUser );
    rc = ct_addTestFun( pTest, testAuthNoPW );
    rc = ct_addTestFun( pTest, testAuthNoPWBAD );
    rc = ct_addTestFun( pTest, testAuthGood );
    rc = ct_addTestFun( pTest, testAuthBad );
//    rc = ct_addTestFun( pTest, testAuthNoBinary );
    rc = ct_addTestFun( pTest, testAuthGoodUpper );
    rc = ct_addTestFun( pTest, testAuthGoodMustChange );
    rc = ct_addTestFun( pTest, testAuthGoodCantChange );
    rc = ct_addTestFun( pTest, testAuthGoodChPwBadOldPwd );
    rc = ct_addTestFun( pTest, testAuthGoodChPwBadNewPwd );
    rc = ct_addTestFun( pTest, testAuthGoodChPw );
    rc = ct_addTestFun( pTest, testUserExists );
    rc = ct_addTestFun( pTest, testBadUserExists );
    rc = ct_addTestFun( pTest, testUserUpperExists );
    rc = ct_addTestFun( pTest, testGetAuthIDs );
    rc = ct_addTestFun( pTest, testGetAuthIDsBAD );
    assert( rc );
    return pTest;
}

/* Client only really has Validate password and GetDefaultNamingContext, and we
 * already test validate password in Server ( same function ), so just the one
 * explicite test. 
*/
Test *GetClientTests()
{
    Test* pTest = ct_create( "Sys-auth library Client", NULL );
    bool rc = ct_addTestFun( pTest, testGetLoginContextEffictive );
    rc = ct_addTestFun( pTest, testGetLoginContextReal );   
    rc = ct_addTestFun( pTest, testGetLoginContextBadUser );   
    assert( rc );
    return pTest;
}
    
Test *GetGroupTests()
{
    Test* pTest = ct_create( "Sys-auth library Group", NULL );
    bool rc = ct_addTestFun( pTest, testGroupExists );
    rc = ct_addTestFun( pTest, testGroupExistsBad);
    rc = ct_addTestFun( pTest, testGroupUpperExists);
    rc = ct_addTestFun( pTest, testGroupsForUser);
    rc = ct_addTestFun( pTest, testGroupsForUserBadUser );
    rc = ct_addTestFun( pTest, testGroupsForUserUpper );
    rc = ct_addTestFun( pTest, testGroupMember );
    rc = ct_addTestFun( pTest, testGroupMemberPGid );
    rc = ct_addTestFun( pTest, testGroupNotMember );
    rc = ct_addTestFun( pTest, testGroupLimits );
    assert( rc );
    return pTest;
}

Test *GetCloseTests()
{
    Test* pTest = ct_create( "Cleanup", NULL );
    bool rc = ct_addTestFun( pTest, testCloseServer );
    rc = ct_addTestFun( pTest, testCloseClient );
    rc = ct_addTestFun( pTest, testCloseGroup );
    rc = ct_addTestFun( pTest, testCloseLib );
    assert( rc );
    return pTest;
}

int main(int argc, char **argv) {
    int rc = 0;
    struct sigaction sigact;
    struct sigaction osigact;

    memset(&sigact, 0, sizeof(sigact));
    memset(&osigact, 0, sizeof(osigact));

    sigact.sa_handler = vas_db2_plugin_sig_handle;

    sigaction(SIGCHLD, &sigact, &osigact);
    
    if( argc > 2)
    {
        fprintf( stderr, "usage: %s <library to load>\n", argv[0] );
        exit( EINVAL );
    }
    else if ( argc == 2 )
    {
        strcpy( filename, argv[1]);
    }

    if( access( filename, R_OK ) != 0 )
    {
        fprintf( stderr, "Unable to access file %s\n", filename );
        exit( EINVAL );
    }

    /* Test for my personal test file, then the build test files, and if found use the first one found. */
    if( access( "./test3.conf", R_OK ) == 0 )
        strcpy( test_conf, "./test3.conf" );
    else
        if( access( "./test2.conf", R_OK ) == 0 )
            strcpy( test_conf, "./test2.conf" );

    Suite* s = cs_create( "Sys-auth" );
    cs_setStream( s, stderr );
    cs_addTest( s, GetStartTests() );
    cs_addTest( s, GetLogTests() );
    cs_addTest( s, GetServerTests() );
    cs_addTest( s, GetClientTests() );
    cs_addTest( s, GetGroupTests() );
    cs_addTest( s, GetCloseTests() );
    cs_run( s );
    rc = cs_report( s );
    cs_destroy( s, TRUE );

    sigaction(SIGCHLD, &osigact, NULL);
    
    return( rc );
}
