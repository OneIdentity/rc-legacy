#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>
#include <pwd.h>
#include "db2secPlugin.h"
#include "csuite.h"
#include "log.h"

#define GOOD_VALUE "GOOD_VALUE"
const char* test_conf = "./test.conf";


void *handle = NULL;
char filename[512] = "./sys-auth32.so";
char *funcNameAuth = "db2secServerAuthPluginInit";
char *funcNameGroup = "db2secGroupPluginInit";

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

struct userid_password_server_auth_functions_1 fnsA;

struct group_functions_1 fnsG;


void testOpen( Test *pTest )
{
    handle = dlopen( filename, RTLD_LAZY );
    ct_test( pTest, handle != NULL );
}

void testLoadA( Test *pTest )
{
    char *err = NULL;
    if( handle )
    {
        ServerInit = dlsym( handle, funcNameAuth );
        ct_test( pTest, ( ( err = dlerror( ) ) == NULL ) );
    }
    putenv( "DB2AUTHPATH='./pamAuth32'" );
}

void testLoadG( Test *pTest )
{
    char *err = NULL;
    if( handle )
    {
        GroupInit = dlsym( handle, funcNameGroup );
        ct_test( pTest, ( ( err = dlerror( ) ) == NULL ) );
    }
}

void testFillfnsA( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    ServerInit( version, (void*)&fnsA, NULL, NULL, &errMsg, &msgLen );
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
    rval = fnsA.db2secValidatePassword( "root", 5, NULL, 0, 0, "", 8, NULL, 0, NULL, 0, 0, NULL, &errMsg, &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADPWD );
}

void testAuthBadUser( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    rval = fnsA.db2secValidatePassword( "%123", 4, NULL, 0, 0, "", 0, NULL, 0, NULL, 0, 0, NULL, &errMsg, &msgLen);
    ct_test( pTest, rval == DB2SEC_PLUGIN_BADUSER  || rval == DB2SEC_PLUGIN_UNKNOWNERROR );
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
    rval = fnsA.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):0, 
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
    rval = fnsA.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):0, 
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
    rval = fnsA.db2secValidatePassword( username?username:"bad", 
                                       username?strlen(username):0, 
                                       NULL, 
                                       0, 
                                       0, 
                                       password?password:"bad", 
                                       password?strlen(password):0, 
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

void testGroupExists( Test *pTest )
{
    db2int32 version = 1;
    int rval = 0;
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    char *group = (char*)GetEntryFromFile( test_conf, "user_in_group" );
    if( group ) 
        group = (char *)strdup( group );
    rval = fnsG.db2secDoesGroupExist( group?group:"badgroup",
                                      group?strlen(group):0,
                                      &errMsg,
                                      &msgLen );
    ct_test( pTest, rval == DB2SEC_PLUGIN_OK );
                                      
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
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):0, //authidlen
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
            // Need to store off the next groups size first, before we overwrite with '\0'
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
    rval = fnsG.db2secGetGroupsForUser( username?username:"bad", //authid
                                        username?strlen(username):0, //authidlen
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
            // Need to store off the next groups size first, before we overwrite with '\0'
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

void testGroupMemberList( Test *pTest )
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
                                        username?strlen(username):0, //authidlen
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
        fprintf( stdout, "User <%s> is in the following groups:\n", username?username:"bad" );
        do 
        {   
            // Need to store off the next groups size first, before we overwrite with '\0'
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

void testCloseLib( Test *pTest )
{
    char *err = NULL;
    dlclose( handle );
    ct_test( pTest, ( ( err = dlerror( ) ) == NULL ) );
}

void testCloseAuth( Test *pTest )
{
    db2int32 msgLen = 0;
    char *errMsg = NULL;
    fnsA.db2secServerAuthPluginTerm( &errMsg,
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
    Test* pTest = ct_create( "library loading tests", NULL );
    bool rc = ct_addTestFun( pTest, testOpen );
    rc = ct_addTestFun( pTest, testLoadA );
    rc = ct_addTestFun( pTest, testLoadG );
    rc = ct_addTestFun( pTest, testFillfnsA );
    rc = ct_addTestFun( pTest, testFillfnsG );
    assert( rc );
    return pTest;
}

Test *GetAuthTests()
{
    Test* pTest = ct_create( "Sys-auth library authentications", NULL );
    bool rc = ct_addTestFun( pTest, testAuthBadPW );
    rc = ct_addTestFun( pTest, testAuthBadUser );
    rc = ct_addTestFun( pTest, testAuthNoPW );
    rc = ct_addTestFun( pTest, testAuthNoPWBAD );
    rc = ct_addTestFun( pTest, testAuthGood );
    assert( rc );
    return pTest;
}

Test *GetGroupTests()
{
    Test* pTest = ct_create( "Sys-auth library group functions", NULL );
    bool rc = ct_addTestFun( pTest, testGroupExists );
    rc = ct_addTestFun( pTest, testGroupMemberList );
    rc = ct_addTestFun( pTest, testGroupMember );
    rc = ct_addTestFun( pTest, testGroupNotMember );
    assert( rc );
    return pTest;
}

Test *GetCloseTests()
{
    Test* pTest = ct_create( "cleanup", NULL );
    bool rc = ct_addTestFun( pTest, testCloseAuth );
    rc = ct_addTestFun( pTest, testCloseGroup );
    rc = ct_addTestFun( pTest, testCloseLib );
    assert( rc );
    return pTest;
}



int main(int argc, char **argv) {
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

    Suite* s = cs_create( "Sys-auth" );
    cs_setStream( s, stderr );
    cs_addTest( s, GetStartTests() );
    cs_addTest( s, GetLogTests() );
    cs_addTest( s, GetAuthTests() );
    cs_addTest( s, GetGroupTests() );
    cs_addTest( s, GetCloseTests() );
    cs_run( s );
    cs_report( s );
    cs_destroy( s, TRUE );
    
    return 0;
}
