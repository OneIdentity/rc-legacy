/**********************************************************************
*
*  Source File Name = db2secPlugin.h
*
*  (C) COPYRIGHT International Business Machines Corp. 1991, 2003
*  All Rights Reserved
*  Licensed Materials - Property of IBM
*
*  US Government Users Restricted Rights - Use, duplication or
*  disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
*
*  Function = This files includes:
*             1. define for all the API return codes
*             2. maximum size used in the API parameter
*             3. defines used for some of the API parameter
*             4. structures and function used in the API parameter
*             5. initialization API for group, client and server plugins
*             6. structures that returns the API function pointers
*
*             Please consult the ADG client volumne for more details.
*
*  Operating System = All platforms that DB2 supported
*
***********************************************************************/
/**********************************************************************
* Modified by Seth Ellsworth <seth.ellsworth@quest.com> for building 
* the VAS DB2 plugin. Namely, trimming out unneeded files/declarations. 
* (c) 2007 Quest Software, Inc. All rights reserved.
***********************************************************************/


#ifndef _DB2SECPLUGIN_H
#define _DB2SECPLUGIN_H


/* Start modifications by Seth */
//#include "gssapi_krb5.h"
//#include "db2ApiDf.h"
//#include "gssapiDB2.h" 
/* End modifications by Seth */

#ifdef __cplusplus
extern "C" {
#endif

/* Start modifications by Seth */
#ifdef __64BIT__
#define db2Is64bit
    typedef int             sqlint32;
    typedef unsigned int    sqluint32;
#else
    typedef long            sqlint32;
    typedef unsigned long   sqluint32;
#endif

#define SQL_API_RC      int
typedef sqlint32        db2int32;
typedef sqluint32       db2Uint32;       
#define SQL_API_FN    
#define SQL_AUTHID_SZ          30
/* End modifications by Seth */

#define DB2SEC_API_VERSION_1 1
#define DB2SEC_API_VERSION DB2SEC_API_VERSION_1

/**********************************************************************
*
* Error Code To be Returned by the plugin 
*
***********************************************************************/

#define DB2SEC_PLUGIN_OK 0
#define DB2SEC_PLUGIN_UNKNOWNERROR -1

#define DB2SEC_PLUGIN_BADUSER -2

/* Other than DB2SEC_PLUGIN_OK, */
/* the following three error return codes are for */
/* db2secDoesAuthIDExist and db2secDoesGroupExist API */
#define DB2SEC_PLUGIN_INVALIDUSERORGROUP -3
#define DB2SEC_PLUGIN_USERSTATUSNOTKNOWN -4
#define DB2SEC_PLUGIN_GROUPSTATUSNOTKNOWN -5

#define DB2SEC_PLUGIN_UID_EXPIRED  -6
#define DB2SEC_PLUGIN_PWD_EXPIRED -7
#define DB2SEC_PLUGIN_USER_REVOKED -8
#define DB2SEC_PLUGIN_USER_SUSPENDED -9

#define DB2SEC_PLUGIN_BADPWD -10
#define DB2SEC_PLUGIN_BAD_NEWPASSWORD -11
#define DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED -12

#define DB2SEC_PLUGIN_NOMEM -13
#define DB2SEC_PLUGIN_DISKERROR -14
#define DB2SEC_PLUGIN_NOPERM -15
#define DB2SEC_PLUGIN_NETWORKERROR -16
#define DB2SEC_PLUGIN_CANTLOADLIBRARY -17
#define DB2SEC_PLUGIN_CANT_OPEN_FILE -18
#define DB2SEC_PLUGIN_FILENOTFOUND -19

#define DB2SEC_PLUGIN_CONNECTION_DISALLOWED -20

#define DB2SEC_PLUGIN_NO_CRED -21
#define DB2SEC_PLUGIN_CRED_EXPIRED -22
#define DB2SEC_PLUGIN_BAD_PRINCIPAL_NAME -23

/* DB2SEC_PLUGIN_NO_CON_DETAILS can be returned by the plugin callback */
/* to DB2 for connecting details i.e. db2secGetConDetails */
#define DB2SEC_PLUGIN_NO_CON_DETAILS -24

#define DB2SEC_PLUGIN_BAD_INPUT_PARAMETERS -25
#define DB2SEC_PLUGIN_INCOMPATIBLE_VER -26

#define DB2SEC_PLUGIN_PROCESS_LIMIT -27
#define DB2SEC_PLUGIN_NO_LICENSES -28

/**********************************************************************
*
* Parameter limit -
* The maximum size of authid, userid, namespace, password, principal name,
*                     and database name to be used for plugin.
* Internally DB2 supports a smaller size for some of them. Refer to
* SQL reference for the SQL limits.
*
***********************************************************************/

#define DB2SEC_MAX_AUTHID_LENGTH 255
#define DB2SEC_MAX_USERID_LENGTH 255
#define DB2SEC_MAX_USERNAMESPACE_LENGTH 255
#define DB2SEC_MAX_PASSWORD_LENGTH 255
#define DB2SEC_MAX_PRINCIPAL_NAME_LENGTH 255

#define DB2SEC_MAX_DBNAME_LENGTH 128

/**********************************************************************
*
* Userid type - Used as input by DB2 to the client side plugin
*               on db2secGetDefaultLoginContext API call.
* Real User or Effective User
*
***********************************************************************/

#define DB2SEC_PLUGIN_REAL_USER_NAME 0
#define DB2SEC_PLUGIN_EFFECTIVE_USER_NAME 1

/**********************************************************************
*
* Connection details bitmap -
* Used in db2secGetConDetails (pConDetails = db2sec_con_details_1)
* and db2secValidatePassword (connection_details)
* indicates whether the userid is get from default login context
* indicates whether the connection is local to the server
* indicates the validate password is currently called on the server
*
***********************************************************************/

#define DB2SEC_USERID_FROM_OS 0x00000001
#define DB2SEC_CONNECTION_ISLOCAL 0x00000002
#define DB2SEC_VALIDATING_ON_SERVER_SIDE 0x0000004

/**********************************************************************
*
* Plugin Type
*
***********************************************************************/

#define DB2SEC_PLUGIN_TYPE_USERID_PASSWORD 0
#define DB2SEC_PLUGIN_TYPE_GSSAPI 1
#define DB2SEC_PLUGIN_TYPE_KERBEROS 2
#define DB2SEC_PLUGIN_TYPE_GROUP 3

/**********************************************************************
*
* Namespace Type -
* DB2SEC_NAMESPACE_SAM_COMPATIBLE is of format torolab\username
* DB2SEC_NAMESPACE_USER_PRINCIPAL is of format username@torolab.ibm.com
* where torolab is the domain name
*
***********************************************************************/

#define DB2SEC_USER_NAMESPACE_UNDEFINED 0
#define DB2SEC_NAMESPACE_SAM_COMPATIBLE 1
#define DB2SEC_NAMESPACE_USER_PRINCIPAL 2

/**********************************************************************
*
* Token Type -
* Indicate the type of token whether is a token from userid/password
* plugin or GSS-API (including kerberos) plugin.
* Used in the tokentype parameter for db2secGetGroupsForUser API (group
* plugin)
*
***********************************************************************/

#define DB2SEC_GENERIC 0
#define DB2SEC_GSSAPI_CTX_HANDLE 1

/**********************************************************************
*
* Location -
* Indicate the location where the API is called (either on the client
* or on the server)
* Used in the location parameter for db2secGetGroupsForUser API (group
* plugin)
*
***********************************************************************/

#define DB2SEC_SERVER_SIDE 0
#define DB2SEC_CLIENT_SIDE 1

/**********************************************************************
*
* Initial Session Authid Type
*
***********************************************************************/

#define DB2SEC_ID_TYPE_AUTHID 0
#define DB2SEC_ID_TYPE_ROLE   1

/**********************************************************************
*
* Log Message Level
* Used in level parameter for db2secLogMessage API
* This indicates the severity of the message to be logged
*
***********************************************************************/

#define DB2SEC_LOG_NONE     0
#define DB2SEC_LOG_CRITICAL 1
#define DB2SEC_LOG_ERROR    2
#define DB2SEC_LOG_WARNING  3
#define DB2SEC_LOG_INFO     4

/* Connection details structure used in pConDetails parameter for */
/* db2secGetConDetails callback API */
typedef struct db2sec_con_details_1
{
  db2int32  clientProtocol;     /* See SQL_PROTOCOL_ in sqlenv.h */
  db2Uint32 clientIPAddress;    /* Set if protocol is tcpip */
  db2Uint32 connect_info_bitmap;
  db2int32  dbnameLen;
  char dbname[DB2SEC_MAX_DBNAME_LENGTH + 1];
} db2sec_con_details_1;

/* The following two API are provided by DB2 to the plugin */
typedef SQL_API_RC (SQL_API_FN db2secGetConDetails)
                              ( db2int32 conDetailsVersion, 
                                void * pConDetails );

typedef SQL_API_RC (SQL_API_FN db2secLogMessage)
                              ( db2int32 level,
                                void * data,
                                db2int32 length);

/* Client side plugin initialization API */
SQL_API_RC SQL_API_FN db2secClientAuthPluginInit 
                              ( db2int32  version,
                                void     *client_fns,
                                db2secLogMessage *logMessage_fn,
                                char    **errormsg,
                                db2int32 *errormsglen );

/* Server side plugin initialization API */
SQL_API_RC SQL_API_FN db2secServerAuthPluginInit
                              ( db2int32              version,
                                void                 *server_fns,
                                db2secGetConDetails  *getConDetails_fn,
                                db2secLogMessage     *logMessage_fn,
                                char                **errormsg,
                                db2int32             *errormsglen );

/* Group side plugin initialization API */
SQL_API_RC SQL_API_FN db2secGroupPluginInit
                              ( db2int32   version,
                                void      *group_fns,
                                db2secLogMessage *logMessage_fn,
                                char     **errormsg,
                                db2int32  *errormsglen );

/* Group plugin function pointer structure to be returned during init */
typedef struct group_functions_1
{
     db2int32 version;
     db2int32 plugintype;

     SQL_API_RC ( SQL_API_FN *db2secGetGroupsForUser) 
                           ( const char *authid,
                             db2int32    authidlen,
                             const char *userid,
                             db2int32    useridlen,
                             const char *usernamespace,
                             db2int32    usernamespacelen,
                             db2int32    usernamespacetype,
                             const char *dbname,
                             db2int32    dbnamelen,
                             void       *token,
                             db2int32    tokentype,
                             db2int32    location,
                             const char *authpluginname,
                             db2int32    authpluginnamelen,
                             void      **grouplist,
                             db2int32   *numgroups,
                             char      **errormsg,
                             db2int32   *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secDoesGroupExist) 
                           ( const char *groupname,
                             db2int32    groupnamelen,
                             char      **errormsg,
                             db2int32   *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secFreeGroupListMemory) 
                           ( void       *ptr,
                             char      **errormsg,
                             db2int32   *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secFreeErrormsg) 
                           ( char *msgtofree );

     SQL_API_RC ( SQL_API_FN *db2secPluginTerm)
                           ( char      **errormsg,
                             db2int32   *errormsglen );
} db2secGroupFunction_1;

/* Client userid-password plugin function pointer structure to be */
/* returned during init */
typedef struct userid_password_client_auth_functions_1
{
     db2int32 version;
     db2int32 plugintype;

     /* db2secRemapUserid is an optional API */
     SQL_API_RC ( SQL_API_FN *db2secRemapUserid)
                           ( char        userid[DB2SEC_MAX_USERID_LENGTH], 
                             db2int32   *useridlen,
                             char        usernamespace[DB2SEC_MAX_USERNAMESPACE_LENGTH],
                             db2int32   *usernamespacelen,
                             db2int32   *usernamespacetype,
                             char        password[DB2SEC_MAX_PASSWORD_LENGTH],
                             db2int32   *passwordlen,
                             char        newpasswd[DB2SEC_MAX_PASSWORD_LENGTH],
                             db2int32   *newpasswdlen,
                             const char *dbname,
                             db2int32    dbnamelen,
                             char      **errormsg,
                             db2int32   *errormsglen);

     SQL_API_RC ( SQL_API_FN *db2secGetDefaultLoginContext)
                           ( char       authid[DB2SEC_MAX_AUTHID_LENGTH],
                             db2int32  *authidlen,
                             char       userid[DB2SEC_MAX_USERID_LENGTH],
                             db2int32  *useridlen,
                             db2int32   useridtype,
                             char       usernamespace[DB2SEC_MAX_USERNAMESPACE_LENGTH],
                             db2int32  *usernamespacelen,
                             db2int32  *usernamespacetype,
                             const char *dbname,
                             db2int32   dbnamelen,
                             void     **token,
                             char     **errormsg,
                             db2int32  *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secValidatePassword) 
                           ( const char *userid,
                             db2int32    useridlen,
                             const char *usernamespace,
                             db2int32    usernamespacelen,
                             db2int32    usernamespacetype,
                             const char *password,
                             db2int32    passwordlen,
                             const char *newpasswd,
                             db2int32    newpasswdlen,
                             const char *dbname,
                             db2int32    dbnamelen,
                             db2Uint32   connection_details,
                             void      **token,
                             char      **errormsg,
                             db2int32   *errormsglen);

     SQL_API_RC ( SQL_API_FN *db2secFreeToken) 
                           ( void       *token,
                             char      **errormsg,
                             db2int32   *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secFreeErrormsg) 
                           ( char *errormsg );

     SQL_API_RC ( SQL_API_FN *db2secClientAuthPluginTerm) 
                           ( char     **errormsg,
                             db2int32  *errormsglen );

} db2secUseridPasswordClientAuthFunctions_1;

/* Server userid-password plugin function pointer structure to be */
/* returned during init */
typedef struct userid_password_server_auth_functions_1
{
     db2int32 version;
     db2int32 plugintype;
     SQL_API_RC ( SQL_API_FN *db2secValidatePassword) 
                           ( const char *userid,
                             db2int32    useridlen,
                             const char *usernamespace,
                             db2int32    usernamespacelen,
                             db2int32    usernamespacetype,
                             const char *password,
                             db2int32    passwordlen,
                             const char *newpasswd,
                             db2int32    newpasswdlen,
                             const char *dbname,
                             db2int32    dbnamelen,
                             db2Uint32   connection_details,
                             void      **token,
                             char      **errormsg,
                             db2int32   *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secGetAuthIDs)
                           ( const char *userid,
                             db2int32    useridlen,
                             const char *usernamespace,
                             db2int32    usernamespacelen,
                             db2int32    usernamespacetype,
                             const char *dbname,
                             db2int32    dbnamelen,
                             void      **token,
                             char        SystemAuthID[DB2SEC_MAX_AUTHID_LENGTH],
                             db2int32   *SystemAuthIDlen,
                             char        InitialSessionAuthID[DB2SEC_MAX_AUTHID_LENGTH],
                             db2int32   *InitialSessionAuthIDlen,
                             char        username[DB2SEC_MAX_USERID_LENGTH],
                             db2int32   *usernamelen,
                             db2int32   *initsessionidtype,
                             char      **errormsg,
                             db2int32   *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secDoesAuthIDExist) 
                           ( const char *authid,
                             db2int32    authidlen,
                             char      **errormsg,
                             db2int32   *errormsglen);

     SQL_API_RC ( SQL_API_FN *db2secFreeToken) 
                           ( void        *token,
                             char       **errormsg,
                             db2int32    *errormsglen );

     SQL_API_RC ( SQL_API_FN *db2secFreeErrormsg) 
                           ( char *errormsg );

     SQL_API_RC ( SQL_API_FN *db2secServerAuthPluginTerm) 
                           ( char     **errormsg,
                             db2int32  *errormsglen );

} db2secUseridPasswordServerAuthFunctions_1;

#ifdef __cplusplus
}
#endif

#endif


