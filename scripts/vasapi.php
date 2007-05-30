<?php

/**
 * Vintela Authentication Service (VAS) API
 *
 * VAS API Version 4.0
 *
 * Copyright (c) 2006 and 2007 Quest Software, Inc. All Rights Reserved.
 *
 * This header file is distributed as part of the Vintela Authentication
 * Services (VAS) distribution governed by the Vintela Authentication
 * Services (VAS) Software End User License Agreement (the "EULA").
 * This header file is part of the "Licensed Software" licensed to a
 * Licensee under the EULA. The Licensee may use information learned
 * from this file to develop software applications that use the libvas
 * library of VAS as permitted by the EULA, and for no other purpose.
 * If you are not the Licensee under the EULA, then you do not have any
 * license to use this file or any information in it.
 *
 **/

/* NOTE:  This header file contains comment markups that are used with
 *        the Doxygen (generated) documentation system
 */


/** @file
 * Provides functions for interacting with Microsoft domain controllers
 * including Active Directory LDAP access, Kerberos authentication, and user
 * logon functionality.
 *
 * The VAS API provides simplified interfaces for using Kerberos to
 * authenticate against Active Directory, and using LDAP to access
 * information. All of the complexity of discovering Active Directory
 * domain controllers, LDAP SASL binds, processing LDAP results, and
 * Kerberos/GSSAPI function calls are hidden from the caller. The LDAP
 * and Kerberos version 5 implementations are in libvas.so. There is no
 * need to link in a separate LDAP or Kerberos library. This version
 * of libvas is not binary compatible with the libvas from the VAS
 * 2.x product series.
 *
 **/

/****************************************************************************
 *                                                                          *
 *                        CONSTANTS AND FLAGS                               *
 *                                                                          *
 ****************************************************************************/


/** Credential cache is kept in memory (not in a file).
 * VAS_ID_FLAG_USE_MEMORY_CCACHE is useful in situations where a credential
 * cache should not outlive the process or whenever the
 * credentials should not be stored in the file credential cache for the
 * process owner. This flag may be used in calls to
 * vas_id_establish_cred_password() and vas_id_establish_cred_keytab().
 */
define('VAS_ID_FLAG_USE_MEMORY_CCACHE', (1 << 0));

/** Keep a copy of the password or keytab so that it can be used later.
 * For example, VAS_ID_FLAG_KEEP_COPY_OF_CRED is  useful when a daemon
 * needs to setuid() to a non-privileged user that no longer has access
 * to the keytab. The use of this flag affects the behavior of the
 * following functions: vas_id_establish_cred_password(),
 * vas_id_establish_cred_keytab(), vas_id_renew_cred().
 */
define('VAS_ID_FLAG_KEEP_COPY_OF_CRED', (1 << 1));

/** Use the default keytab name.
 * When calling vas_id_establish_cred_keytab() using a NULL keytab
 * argument, the keytab name is derived from the principal name.
 * Use VAS_ID_FLAG_DO_NOT_DERIVE_KEYTAB to force use of the default
 * keytab (usually /etc/opt/quest/vas/host.keytab).
 */
define('VAS_ID_FLAG_DO_NOT_DERIVE_KEYTAB', (1 << 2))

/** Do not request a TGT.
 * Used in server applications that only need to validate service tickets
 * using a keytab. When passed as a flag to vas_id_establish_cred_keytab()
 * the ::vas_id_t will be associated with a keytab with out the overhead of
 * requesting a TGT.
 */
define('VAS_ID_FLAG_NO_INITIAL_TGT',       (1 << 3));

/** Request renewable tickets.
 * This flag may be used in calls to vas_id_establish_cred_password()
 * and vas_id_establish_cred_keytab().
 */
define('VAS_ID_CRED_FLAG_RENEWABLE',       (1 << 4));


/** Do not use cached information when resolving identity names.
 * May be used in calls to vas_name_to_dn().
 */
define('VAS_NAME_FLAG_NO_CACHE',           (1 << 0));

/** Do not use LDAP when resolving identity names.
 * May be used in calls to vas_name_to_dn().
 */
define('VAS_NAME_FLAG_NO_LDAP',            (1 << 1));

/** Do not expand the Microsoft implicit principal name.
 * May be used in calls to vas_name_to_principal().
 */
define('VAS_NAME_FLAG_NO_IMPLICIT',        (1 << 2));

/** Do not expand host names to fully qualified domain names.
 * May be used in calls to vas_name_to_principal().
 */
define('VAS_NAME_FLAG_NO_DNS_EXPAND',      (1 << 3));

/** Search the entire forest missing domain name components.
 * By default only the current domain will be searched. May be used in
 * calls to vas_name_to_dn().
 */
define('VAS_NAME_FLAG_FOREST_SCOPE',       (1 << 4));


/****************************************************************************
 *                                                                          *
 *                        ENUMERATED TYPES                                  *
 *                                                                          *
 ****************************************************************************/

/** vas_err_t error codes
 * All VAS API functions return a vas_err_t type. More information about
 * the specific VAS error conditions that may result can be found in the
 * documentation for each VAS API function.
 **/
enum vas_err_t
{
    VAS_ERR_BAD_ERR       = -1,
    VAS_ERR_SUCCESS       =  0,
    VAS_ERR_FAILURE       =  1,
    VAS_ERR_KRB5          =  2,
    VAS_ERR_KPASSWD       =  3,
    VAS_ERR_LDAP          =  4,
    VAS_ERR_INVALID_PARAM =  5,
    VAS_ERR_NO_MEMORY     =  6,
    VAS_ERR_ACCESS        =  7,
    VAS_ERR_NOT_FOUND     =  8,
    VAS_ERR_THREAD        =  9,
    VAS_ERR_CONFIG        =  10,
    VAS_ERR_INTERNAL      =  11,
    VAS_ERR_EXISTS        =  12,
    VAS_ERR_DNS           =  13,
    VAS_ERR_CRED_EXPIRED  =  14,
    VAS_ERR_CRED_NEEDED   =  15,
    VAS_ERR_MORE_VALS     =  16,
    VAS_ERR_TIMEDOUT      =  17,
    VAS_ERR_INCOMPLETE    =  18
};


/** Enumerates the types of errors that can be described by an
 * vas_err_info_t.
 **/
enum vas_err_type_t
{
   VAS_ERR_TYPE_VAS     = 1,    /* VAS Specific errors */
   VAS_ERR_TYPE_SYS     = 2,    /* System errors */
   VAS_ERR_TYPE_KRB5    = 3,    /* Kerberos errors */
   VAS_ERR_TYPE_KPASSWD = 4,    /* Kerberos passwd protocol errors */
   VAS_ERR_TYPE_LDAP    = 5     /* LDAP errors */
};


/** Enumeration of options that may be passed when calling
 * vas_ctx_get_option() and vas_ctx_set_option().
 *
 * @see vas_ctx_get_option(), vas_ctx_set_option().
 **/
enum vas_ctx_opt_t
{
    VAS_CTX_OPTION_DEFAULT_REALM                     =  1,
    VAS_CTX_OPTION_SITE_AND_FOREST_ROOT              =  2,
    VAS_CTX_OPTION_ADD_SERVER                        =  3,
    VAS_CTX_OPTION_USE_TCP_ONLY                      =  4,
    VAS_CTX_OPTION_USE_GSSAPI_AUTHZ                  =  5,
    VAS_CTX_OPTION_USE_SRVINFO_CACHE                 =  6,
    VAS_CTX_OPTION_USE_DNSSRV                        =  7,
    VAS_CTX_OPTION_USE_VASCACHE                      =  8,
    VAS_CTX_OPTION_USE_VASCACHE_IPC                  =  9,
    VAS_CTX_OPTION_USE_SERVER_REFERRALS              =  10,
    VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING =  11,
    VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND   =  12,
    VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT             =  13,
    VAS_CTX_OPTION_DOMAIN_NAMING_CONTEXT             =  14,
    VAS_CTX_OPTION_USE_SRVINFO_CONF                  =  15
};


/** Enumeration of options that may be passed when calling
 * vas_attrs_get_option() and vas_attrs_set_option().
 *
 * @see vas_get_option(), vas_attrs_set_option().
 **/
enum vas_attrs_opt_t
{
    VAS_ATTRS_OPTION_SEARCH_TIMEOUT    = 1,
    VAS_ATTRS_OPTION_LDAP_PAGESIZE     = 2,
    VAS_ATTRS_B64_ENCODE_ATTRS         = 3
};


/** Server types that may be used when calling vas_info_servers().
 */
enum vas_srvinfo_type_t
{
    VAS_SRVINFO_TYPE_ANY = 0, /* Any server */
    VAS_SRVINFO_TYPE_DC  = 1, /* Microsoft Domain Controller */
    VAS_SRVINFO_TYPE_PDC = 2, /* Microsoft Primary Domain Controller emulator */
    VAS_SRVINFO_TYPE_GC  = 3  /* Microsoft Active Directory Global Catalog */
};


/** Enumerates the types of names that are use in and returned from
 * various VAS API calls.
 **/
enum vas_name_type_t
{
    VAS_NAME_TYPE_UNKNOWN = 0,
    VAS_NAME_TYPE_USER    = 1, /* A a pw_name or a Kerberos UPN */
    VAS_NAME_TYPE_GROUP   = 2, /* A gr_name */
    VAS_NAME_TYPE_SERVICE = 3, /* Kerberos SPN */
    VAS_NAME_TYPE_HOST    = 4, /* A DNS hostname */
    VAS_NAME_TYPE_DN      = 5, /* An LDAP distinguished name */
    VAS_NAME_TYPE_SID     = 6  /* A Security Identifier */
};



/****************************************************************************
 *                                                                          *
 *                        STRUCTURAL TYPES                                  *
 *                                                                          *
 ****************************************************************************/

/** VAS error information type used to describe the details of an error
 * condition. For more information see documentation about error handling
 * and error handling functions such as: vas_err_get_info().
 */
class CVAS_err_info
{
   var $code;     /*!< Error code */
   var $type;     /*!< Type of error -- vas_err_type_t */
   var $cause;    /*!< An array to CVAS_err_info structures w/o `cause' members */
   var $message;  /*!< Error message string */
};

/** The main VAS API context type
 *
 * Every call to VAS API requires the use of a vas_ctx_t. A vas_ctx_t is
 * created with a call to vas_ctx_alloc(). For most programs it is usually
 * sufficient to allocate one vas_ctx_t per process. When writing threaded
 * applications, you should use one vas_ctx_t per thread.
 *
 * The vas_ctx_t is opaque to the caller. The internal structure of a vas_ctx_t
 * is not documented and may change at any time. Developers must not write code
 * that makes assumptions about the internal structure of a vas_ctx_t.
 **/
typedef struct vas_ctx vas_ctx_t;


/** The VAS identity type
 *
 * A vas_id_t represents an identity. A VAS identity is a Kerberos
 * principal which could be a user, a service, or a computer.
 * The vas_id_t also encapsulates credentials (such as a keytab, or
 * credential cache) that may be associated with a security principal.
 *
 * The vas_id_t is created by calling vas_id_alloc(). Credentials are
 * associated with a vas_id_t by calling vas_id_establish_cred_password() and
 * vas_id_establish_cred_keytab().
 *
 * The vas_id_t is opaque to the caller. The internal structure of the
 * vas_id_t type is not documented and may change at any time.
 * Developers must not write code that makes assumptions about the
 * internal structure of a vas_id_t.
 **/
typedef struct vas_id vas_id_t;


/** Abstraction for authentication data
 *
 * A vas_auth_t is created by a successful call to vas_auth() and
 * vas_auth_with_password().
 *
 * A vas_auth_t contains authentication data (i.e. the Microsoft
 * PAC) that can be used by subsequent authorization calls such as
 * vas_auth_check_client_membership().
 *
 * The vas_auth_t is opaque to the caller. The internal structure of a
 * vas_auth_t is not documented and may change at any time. Developers
 * must not write code that makes assumptions about the internal
 * structure of a vas_auth_t.
 **/
typedef struct vas_auth vas_auth_t;


/** A vas_attrs_t is used to obtain attribute of objects in Active Directory.
 *
 * A vas_attrs_t is created by calling vas_attrs_alloc(). LDAP searches are
 * performed by calling vas_attrs_find() and vas_attrs_find_continue().
 *
 * The vas_attrs_t type is opaque to the caller. The internal structure of the
 * vas_attrs_t type is not documented and may change at any time. Developers
 * must not write code that makes assumptions about the internal structure of a
 * vas_attrs_t.
 **/
typedef struct vas_attrs vas_attrs_t;


/**
 * The vas_user_t type is used to retrieve information about an
 * Active Directory user object.
 *
 * A vas_user_t is created by calling vas_user_init(). It is only possible to
 * create a vas_user_t for a user that already exists in Active Directory.
 * Attributes of the user object may be accessed by one or more function calls,
 * e.g. vas_user_get_dn() to return the distinguished name of the user object.
 *
 * The vas_user_t type is opaque to the caller. The internal structure of the
 * vas_user_t type is not documented and may change at any time. Developers
 * must not write code that makes assumptions about the internal structure of a
 * vas_user_t.
 *
 * @see ::vas_group_t
 **/
typedef struct vas_user vas_user_t;

/**
 * The vas_group_t type is used to retrieve information about an
 * Active Directory group object.
 *
 * A vas_group_t is created by calling vas_group_init(). It is only possible to
 * create a vas_group_t for a group that already exists in Active Directory.
 * Attributes of the group object may be accessed by one or more function
 * calls, e.g. vas_group_get_dn() to return the distinguished name of the group
 * object.
 *
 * The vas_group_t type is opaque to the caller. The internal structure of the
 * vas_group_t type is not documented and may change at any time. Developers
 * must not write code that makes assumptions about the internal structure of a
 * vas_group_t.
 *
 * @see ::vas_user_t
 **/
typedef struct vas_group vas_group_t;

/**
 * The vas_computer_t type is used to retrieve information about an
 * Active Directory computer object.
 *
 * A vas_computer_t is created by calling vas_computer_init(). It is only
 * possible to create a vas_computer_t that already exists in Active Directory.
 * Attributes of the computer object may be accessed by one or more function
 * calls, e.g. vas_computer_get_dn() to return the distinguished name of the
 * computer object.
 *
 * The vas_computer_t type is opaque to the caller. The internal structure of
 * the vas_computer_t type is not documented and may change at any time.
 * Developers must not write code that makes assumptions about the internal
 * structure of a vas_computer_t.
 *
 * @see ::vas_user_t, ::vas_service_t
 **/
typedef struct vas_computer vas_computer_t;

/**
 * The vas_service_t type is used to retrieve information about an
 * Active Directory service account object.
 *
 * A service account is a special user account created by VAS to hold
 * credentials for a Kerberized service (e.g. an HTTP server supporting
 * Kerberos authentication).
 *
 * A vas_service_t is created by calling vas_service_init(). It is only
 * possible to create a vas_service_t for a service account that already exists
 * in Active Directory. Attributes of the service account object may be
 * accessed by one or more function calls, e.g.: vas_service_get_spns() to
 * return the list of Service Principal Names (SPNs) associated with this
 * service account.
 *
 * The vas_service_t type is opaque to the caller. The internal structure of
 * the vas_service_t type is not documented and may change at any time.
 * Developers must not write code that makes assumptions about the internal
 * structure of a vas_service_t.
 *
 * @see ::vas_user_t, ::vas_computer_t
 **/
typedef struct vas_service vas_service_t;

/**
 * The CVAS_passwd class is used by vas_user_get_pwinfo to
 * return password information from the underlying system.
 **/
class CVAS_passwd
{
  var $pw_name;       /*!< Username.*/
  var $pw_passwd;     /*!< Password.*/
  var $pw_uid;        /*!< User ID.*/
  var $pw_gid;        /*!< Group ID.*/
  var $pw_gecos;      /*!< Real name.*/
  var $pw_dir;        /*!< Home directory.*/
  var $pw_shell;      /*!< Shell program.*/
};


/****************************************************************************
 *                                                                          *
 *                        VAS CONTEXT FUNCTIONS                             *
 *                                                                          *
 ****************************************************************************/

/** Allocates and initializes a ::vas_ctx_t.
 *
 * Every call to the VAS API requires the use of a ::vas_ctx_t. For most
 * programs it is usually sufficient to allocate one ::vas_ctx_t per
 * process.
 *
 * @return vas_ctx_t
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 **/
function vas_ctx_alloc();


/** Set options that change VAS environmental behavior.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param option    The option to set. The following options are defined:
 *                  - VAS_CTX_OPTION_DEFAULT_REALM - set the default realm
 *                    for this vas_ctx_t. The argument is a single char * realm
 *                    name string. Setting the default realm using
 *                    this option overrides the default_realm setting in
 *                    vas.conf or allows the VAS API to operate without the
 *                    default_realm setting in vas.conf. <b>However, this
 *                    operation should not be attempted as it might damage
 *                    VAS.</b>
 *                  - VAS_CTX_OPTION_SITE_AND_FOREST_ROOT - Specify the
 *                    site and forest root. The arguments are: char *site,
 *                    char *forest_root. Either argument may be NULL.
 *                    <b>However, this operation should not be attempted as it
 *                    might damage VAS.</b>
 *                  - VAS_CTX_OPTION_ADD_SERVER - Specify a server that will be
 *                    used for Kerberos and LDAP traffic. The arguments are:
 *                    char *host, char *domain, char *site,
 *                    ::vas_srvinfo_type_t *srvinfo. The DNS host name name is
 *                    required, domain and site may be NULL.
 *                  - VAS_CTX_OPTION_USE_SRVINFO_CACHE - Specify whether or
 *                    not to use the server information cache (maintained by
 *                    vasd) to locate domain controllers. The argument is:
 *                    a single int where 1 turns on use of srvinfo cache (the
 *                    usual vas.conf default) and 0 turns off use of srvinfo
 *                    cache.
 *                  - VAS_CTX_OPTION_USE_DNSSRV - Specify whether or not to use
 *                    DNS SRV lookups to locate domain controllers. The
 *                    argument is a single int where 1 turns on use of DNS
 *                    lookup (the usual vas.conf default) and 0, turns off use
 *                    of DNS lookup.
 *                  - VAS_CTX_OPTION_USE_TCP_ONLY - Specify the exclusive use
 *                    of TCP for communication with servers. The argument is a
 *                    single int value. If value is 1, the library will use TCP
 *                    only. If value is 0 the library will use UDP with
 *                    failover to TCP (the usual vas.conf default).
 *                  - VAS_CTX_OPTION_USE_GSSAPI_AUTHZ - Specify whether or not
 *                    authorization checking will occur for GSSAPI acceptors.
 *                    The argument is a single integer where 1 turns on
 *                    authorization checking and 0 (the usual vas.conf default)
 *                    turns it off.
 *                  - VAS_CTX_OPTION_USE_SERVER_REFERRALS - Specify whether or
 *                    not to use Kerberos server referrals. The argument is a
 *                    single integer where 1 turns on server referrals on
 *                    and 0 (the usual vas.conf default) turns it off.
 *                  - VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING -
 *                    Specify the string to be used to separate error message
 *                    phrases when printed or logged. The default is the
 *                    newline, but syslog will not accept that value which
 *                    truncates the string. With this option, the newline can
 *                    be changed to any string containing between 1 and 15
 *                    characters (null-terminated). A longer string passed to
 *                    this function will be truncated and no error will issue.
 *                  - VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND - Setting
 *                    this option to 1 will ensure that any VAS API call that
 *                    does domain controller detection will stop and return
 *                    the necessary servers as soon as it finds them. Some API
 *                    calls (vas_info_servers for example) have a default
 *                    behavior which involves detecting ALL servers every time
 *                    it is called. This is especially unecessary on any
 *                    subsequent call of a function that performs detection as
 *                    the initial call will have stored the entire result set
 *                    of the server detection inside the VAS context handle.
 *                    Setting this option to zero will return any API call to
 *                    its default behavior.
 *                  - VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT - If this option is
 *                    to set to a value greater than 0, then the internal VAS
 *                    code that deals with DNS resolution will track how long
 *                    DNS failures take, and error out if any failures take
 *                    longer then the set amount of time. This setting is 0 by
 *                    default. This will be most useful for callers that need
 *                    to fail over to alternative forms of authentication
 *                    quickly if Active Directory is not reachable. The
 *                    supplied option must be a time_t value that specifies the
 *                    number of seconds after which DNS lookup attempts should
 *                    be abandoned.
 *                  - VAS_CTX_OPTION_USE_SRVINFO_CONF - Setting to control if
 *                    the VAS API should load srvinfo information from the
 *                    vas.conf file. This is really only ever used in a
 *                    bootstrap scenario (i.e.: join) where there may be an
 *                    existing vas.conf that has srvinfo specified, and the new
 *                    join shouldn't use them.
 *                  - VAS_CTX_OPTION_USE_VASCACHE - The argument is
 *                    int (Boolean). Setting to control whether or not the
 *                    VAS API should look up items in the cache (i.e.: misc
 *                    entries, user/group entries, etc.).
 *                  - VAS_CTX_OPTION_USE_VASCACHE_IPC - The argument is
 *                    int (Boolean). Setting to control whether or not
 *                    the VAS API should send IPC requests during user/group
 *                    lookups. vasd should be the only process that needs to
 *                    set this value.
 *                  - VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND - The
 *                    argument is time_t. Setting used within the
 *                    VAS API when looking for server information. If one
 *                    server that matches the query is found, it will not
 *                    continue loading the srvinfo list with all available
 *                    servers.
 *                  - VAS_CTX_OPTION_DOMAIN_NAMING_CONTEXT - The arguments are
 *                    char *domain and char **value. Used to set the default
 *                    naming context for the given domain. This is mainly set
 *                    or retrieved from within the VAS API. If a
 *                    search base was not set and a domain was used,
 *                    vas_attrs_find() queries the default naming context for
 *                    the domain from the DC (or if stored in the ctx handle).
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *                  - VAS_ERR_SUCCESS on success or one of the following error
 *                    codes:
 *                  - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *                  - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *
 * @code
 *
 * // EXAMPLE:
 * {
 *     ...
 *
 *     if( vas_ctx_set_option( ctx, VAS_CTX_OPTION_USE_SRVINFO_CACHE, 1 ) )
 *         print( "Unable to set context option VAS_CTX_OPTION_USE_SRVINFO_CACHE!\n" );
 *
 *     if( vas_ctx_set_option( ctx, VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING, "\r\n" ) )
 *         print( "Unable to prescribe separator to be used in syslog messages to \"\\r\\n\"!\n" );
 *     ...
 * }
 *
 * @endcode

 **/
function vas_ctx_set_option( $ctx, $option, ... );


/** Get options indicative of VAS environmental behavior.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param option    The option to get. See vas_ctx_set_option() for the meaning
 *                  of returned values in each of these cases. Just as for
 *                  vas_ctx_set_option(), the values for the following
 *                  options are returned as output arguments, pointers for
 *                  which the caller provides storage. The types are as
 *                  follows. Unless otherwise noted these take int *value
 *                  and the value returned is to be treated as Boolean (see
 *                  the sample code below).
 *                  - VAS_CTX_OPTION_USE_SRVINFO_CACHE
 *                  - VAS_CTX_OPTION_USE_DNSSRV
 *                  - VAS_CTX_OPTION_USE_TCP_ONLY
 *                  - VAS_CTX_OPTION_USE_GSSAPI_AUTHZ
 *                  - VAS_CTX_OPTION_USE_SERVER_REFERRALS
 *                  - VAS_CTX_OPTION_USE_SRVINFO_CONF
 *                  - VAS_CTX_OPTION_USE_VASCACHE
 *                  - VAS_CTX_OPTION_USE_VASCACHE_IPC
 *                  - VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND
 *                  - VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING - The
 *                    argument is char *separator, pointing to storage at least
 *                    16 bytes. (This option is one rather more "set" than
 *                    "got.")
 *                  - VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT - The argument is
 *                    time_t *timeout pointing to a valid time_t variable.
 *                  - VAS_CTX_OPTION_DOMAIN_NAMING_CONTEXT - The arguments are
 *                    char *domain (input: name of domain) and char **value
 *                    (output argument).
 *
 * @return  the value of the option.
 *
 * On return vas_err() is set as follows:
 *          -VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *
 * @code
 *
 * // EXAMPLE:
 * {
 *     $use_srvinfo_cache = 0;
 *     $errmsg_separator[16];
 *     ...
 *
 *     $use_srvinfo_cache = vas_ctx_get_option( ctx, VAS_CTX_OPTION_USE_SRVINFO_CACHE );
 *
 *     $errmsg_separator = vas_ctx_get_option( ctx, VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING );
 *
 *     ...
 *
 *     if( $user_srvinfo_cache )
 *         ...
 * }
 *
 * @endcode
 *

 **/
function vas_ctx_get_option( $ctx, $option );



/****************************************************************************
 *                                                                          *
 *                     IDENTITY AND CREDENTIAL FUNCTIONS                    *
 *                                                                          *
 ****************************************************************************/

/** Allocates and initializes a ::vas_id_t
 *
 * A ::vas_id_t represents an identity. A VAS identity is a Kerberos
 * principal which could be a user, a service, or a computer.
 * The ::vas_id_t also encapsulates credentials (such as a keytab, or
 * credential cache) that may be associated with a security principal.
 *
 * @param ctx    ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param name   The name of the identity that will be associated with
 *               the newly created ::vas_id_t. If name is NULL then the
 *               ::vas_id_t will be associated with the owner of the
 *               current credential cache. If a credential cache does not
 *               exist, the ::vas_id_t will be generated from the pw_name
 *               returned by getpwuid(). If not NULL, name should be a
 *               fully qualified Kerberos principal name such as:
 *                  - "bill@EXAMPLE.COM"
 *                  - "host/mybox.example.com@EXAMPLE.COM".
 *               For convenience you may use simple names that
 *               will be expanded to full Kerberos principal names by
 *               the library. The following are examples of simple names
 *               and their expansion:
 *               \verbatim
 *                  bill        ---> bill@EXAMPLE.COM
 *                  host/       ---> host/mybox.example.com@EXAMPLE.COM
 *                  http/x.com  ---> http/x.com@EXAMPLE.COM
 *               \endverbatim
 *               Rules for principal name expansion are fairly simple.
 *               If a '/' is found in the name it is treated as a
 *               service principal name and defaults for the missing
 *               components (the DNS host name and/or the realm name)
 *               are filled in based on the values established when the
 *               machine was joined to the domain. If no '/' is found
 *               then the name is treated as a user principal name and
 *               the default for the missing realm component is filled in.
 *
 * @return vas_id_t
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5            - Kerberos specific error
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_CONFIG          - Unable to determine default_realm.
 */
function vas_id_alloc( $ctx, $name );


/** Obtains the name of the file being use to store cached credentials.
 *
 * @param ctx   ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id    The ::vas_id_t to get the ccache name for
 *
 * @return string  Returns the name of the Kerberos ticket cache.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5            - Kerberos specific error
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_CRED_NEEDED     - Credential cache not established
 **/
function vas_id_get_ccache_name( $ctx, $id );


/** Obtains the name of the keytab file associated with a ::vas_id_t
 *
 * @param ctx   ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id    The ::vas_id_t to get the keytab name for
 *
 * @return string  Returns the name of the Kerberos keytab.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5            - Kerberos specific error
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_NOT_FOUND       - Keytab not found or established
 **/
function vas_id_get_keytab_name( $ctx, $id );


/** Obtain the identity name
 *
 * Used to obtain a string representation of the principal associated
 * with the specified identity.
 *
 * @param ctx     ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id      The ::vas_id_t to get the name information for
 *
 * @param &princ  Return the Kerberos principal name.
 *
 * @param &dn     Returns the DN.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5            - Kerberos specific error
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_NOT_FOUND       - Distinguished name not found
 **/
function vas_id_get_name( $ctx, $id, &$princ, &$dn );


/** Obtain a ::vas_user_t for this ::vas_id_t
 *
 * Convenience function that eliminates the need to call vas_user_init()
 * when you already have a ::vas_id_t.
 *
 * @param ctx    ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id     The ::vas_id_t to get the name information for
 *
 * @return vas_user_t   Returns the ::vas_user_t for the identity.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Could not locate a user account
 *                                      with the given name.
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_id_get_user( $ctx, $id );


/** Check to see if initial credential needs to be established
 *
 * Check to see if credentials need to be established for the
 * specified identity. There are several ways that credentials
 * could be established already (eliminating the need to call
 * vas_id_establish_cred_password() or vas_id_establish_cred_keytab():
 *
 *   1) vas_id_establish_cred_password() or vas_id_establish_cred_keytab()
 *      have already been called for the specified identity
 *
 *   2) The specified identity is the "current user" that logged
 *      on using the VAS PAM module and a credential cache has already
 *      been established
 *
 *   3) The specified identity is the result of a delegated
 *      SPNEGO or GSSAPI authentication.
 *
 * @param ctx   ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id    The ::vas_id_t for whom the credentials might have
 *              been established.
 *
 * @return  vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5          - Kerberos error
 *          - VAS_ERR_CRED_NEEDED   - Credentials are NOT established
 *          - VAS_ERR_CRED_EXPIRED  - Credentials are expired.
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 **/
function vas_id_is_cred_established( $ctx, $id );


/** Establish initial password credentials
 *
 * Establish the initial credentials that will be associated with the
 * specified identity. Since an initial credential may have been
 * established already it is a good idea to check for established
 * credentials (with a call to vas_id_is_cred_established())
 *
 * Calls to vas_id_establish_cred_password() may generate DNS, and
 * Kerberos network traffic
 *
 * @param ctx       ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        The ::vas_id_t to establish credentials for.
 *
 * @param credflags The following flags are recognized:
 *                  - VAS_ID_FLAG_USE_MEMORY_CCACHE - Credential cache
 *                  is kept in memory so that it will not outlive the
 *                  process.
 *                  - VAS_ID_FLAG_KEEP_COPY_OF_CRED - Keep a copy of the
 *                  "clear text credential" so that it can be used
 *                  later.
 *
 * @param password  The clear-text password for the specified identity.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5     - Kerberos error. Use ::vas_err_t functions
 *                               to obtain Kerberos error details
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 **/
function vas_id_establish_cred_password( $ctx, $id, $credflags, $password );


/** Establish initial keytab credentials
 *
 * Establish the initial credentials that will be associated with the
 * specified identity. Since an initial credential may have been
 * established already it is a good idea to check for established
 * credentials (with a call to vas_id_is_cred_established())
 *
 * Calls to vas_id_establish_cred_keytab() may generate DNS, and
 * Kerberos network traffic
 *
 * @param ctx       ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        The ::vas_id_t to establish credentials for
 *
 * @param credflags The following flags are recognized:
 *                  - VAS_ID_FLAG_USE_MEMORY_CCACHE - Credential cache
 *                    is kept in memory so that it will not outlive the
 *                    process.
 *                  - VAS_ID_FLAG_KEEP_COPY_OF_CRED - Keep a copy of the
 *                    "clear text credential" so that it can be used later.
 *                    This may be useful when a daemon needs to setuid() to
 *                    a non-privileged user that no longer has access
 *                    to the keytab.
 *                  - VAS_ID_FLAG_DO_NOT_DERIVE_KEYTAB - If this flag is
 *                    used and keytab is NULL, the default_keytab setting from
 *                    vas.conf is used as the keytab name.
 *                  - VAS_ID_FLAG_NO_INITIAL_TGT - Do not request an inital
 *                    TGT. A TGT is not necessary for server applications
 *                    that only need to call vas_id_extablish_cred_keytab()
 *                    before calling vas_auth().
 *
 * @param keytab    The path to the keytab file. Pass in NULL to use a
 *                  keytab filename that is derived by VAS from
 *                  the identity name. The derivation of keytab filename
 *                  matches the keytab created when using vastool to
 *                  join the machine to the domain or when using vastool
 *                  to create service principals in Active Directory
 *
 *                  The derivation rules are fairly simple. The service
 *                  is used with a .keytab extension along with the
 *                  /etc/opt/quest/vas directory.
 *
 *                  "http/web.vintela.com" --> /etc/opt/quest/vas/http.keytab
 *                  "host/"                --> /etc/opt/quest/vas/host.keytab
 *
 *                  If the VAS_ID_FLAG_DO_NOT_DERIVE_KEYTAB is used then
 *                  the default_keytab setting from vas.conf is used as
 *                  the keytab filename.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t
 *                                    functions to obtain Kerberos error
 *                                    details
 */
function vas_id_establish_cred_keytab( $ctx, $id, $credflags, $keytab );


/** Renew credentials
 *
 * Renew previously established credentials.
 *
 * @param ctx        ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id         The ::vas_id_t to renew credentials for
 *
 * @param credflags  No flags currently defined. Must be set to zero.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5         - Kerberos error. Use ::vas_err_t functions
 *                                   to obtain Kerberos error details
 *          - VAS_ERR_CRED_NEEDED  - Credentials to not exist
 *          - VAS_ERR_CRED_EXPIRED - Credentials are expired.
 */
function vas_id_renew_cred( $ctx, $id, $credflags );



/****************************************************************************
 *                                                                          *
 *                      AUTHENTICATION FUNCTIONS                            *
 *                                                                          *
 ****************************************************************************/

/** Used by a server to authenticate a client.
 *
 * This function is most often used used by a server to authenticate a
 * client, but may be used by any two identities (with established
 * credentials). The vas_auth_with_password() function may be
 * used as a convenience when username and password credentials are used for
 * authentication.
 *
 * @param ctx    ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param client The ::vas_id_t of the "client" to be authenticated. The
 *               client ::vas_id_t must have been used in a previously
 *
 * @param server The ::vas_id_t of the "server" that is authenticating
 *               the client. The server ::vas_id_t must have been used in a
 *               previously successful call to vas_id_establish_cred_keytab().
 *
 * @return vas_auth_t   Returns a ::vas_auth_t that may be used in subsequent
 *               authorization calls.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_KRB5          - Kerberos error. Use ::vas_err_t functions
 *                                    to obtain Kerberos error details
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_CRED_NEEDED   - Credentials not established for client
 *                                    or server ::vas_id_t
 *          - VAS_ERR_CRED_EXPIRED  - Client credentials are expired.
 **/
function vas_auth( $ctx, $client, $server );


/** Used by a server to authenticate a client with username and
 * password credentials.
 *
 * This is a convenience function that may used instead of vas_auth()
 * when the client's username and password credentials are available.
 * The same functionality can be realized (with more flexibility) by
 * calling vas_auth() directly, but in many cases calling
 * vas_auth_with_password() is more convenient because there is no
 * need to allocate a client ::vas_id_t.
 *
 *
 * @param ctx           ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param clientname    The client principal name. Similar to the string that
 *                      would be passed to vas_id_alloc().
 *
 * @param clientpasswd  The clear-text client password string.
 *
 * @param server        The ::vas_id_t of the "server" that is authenticating
 *                      the client. The server ::vas_id_t must have been used
 *                      in a previously successful call to
 *                      vas_id_establish_cred_keytab().
 *
 * @return vas_auth_t   Returns a ::vas_auth_t that may be used in subsequent
 *                      authorization calls.
 *
 *
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_KRB5          - Kerberos error. Use ::vas_err_t functions
 *                                    to obtain Kerberos error details
 *          - VAS_ERR_CRED_NEEDED   - Credentials not established for client
 *                                    or server ::vas_id_t
 *          - VAS_ERR_CRED_EXPIRED  - Client credentials are expired.
 **/
function vas_auth_with_password( $ctx, $clientname, $clientpasswd, $server);


/** Used by server application to determine whether the authenticated client
 * is a member of a specified group.
 *
 * A ::vas_auth_t contains information about the client user's group membership
 * dervied from the Microsoft PAC information that is found in the Kerberos
 * service ticket used by the vas_auth() functions. After calling vas_auth() or
 * vas_auth_with_password(), developers can call this function to efficiently
 * determine whether or not a user is a member of a particular group. If there
 * is not a ::vas_auth_t available, the vas_user_is_member() and
 * vas_group_has_member() functions can be used. However, these functions are
 * less efficient since additional LDAP searches must be performed in order
 * to determine the user's group membership.
 *
 * @param ctx   ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id    A ::vas_id_t that may be used to resolve the groups. If
 *              NULL is passed then the groups will only be resolved
 *              against the VAS cache and no LDAP searches will be performed.
 *
 * @param auth  The ::vas_auth_t obtained previously with a call to vas_auth()
 *              or vas_auth_with_password().
 *
 * @param group The name of the group to check. May be a simple group name,
 *              the group's distinguished name, or the group's sid string.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS if the client is a member of the group, or one of
 *          the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Client is NOT a member of the group
 *          - VAS_ERR_EXISTS        - The group does not exist
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 */
function vas_auth_check_client_membership( $ctx, $id, $auth, $group );


/**
 * Used by server application obtain the list of groups of which the
 * authenticated client is a member.
 *
 * A ::vas_auth_t contains information (the Microsoft PAC) about the groups
 * of which a user is a member. After calling vas_auth() or
 * vas_auth_password() developers should call vas_auth_get_client_groups()
 * as the most efficient way of obtaining a list of the groups member of which
 * a user is a member. If the ::vas_auth_t necessary for calling
 * this function can not be obtained, the much less efficient
 * vas_user_get_groups() may be used to get group membership.
 *
 * @param ctx    ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id     A ::vas_id_t that may be used to resolve the groups. If
 *               NULL is passed then the groups will only be resolved
 *               against the VAS cache and no LDAP searches will be performed.
 *
 * @param auth   The ::vas_auth_t obtained previously with a call to
 *               vas_auth() or vas_auth_password().
 *
 * @return vas_group_t[]    Used to return the groups of which the user is a
 *                          member.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Client is not a member of any groups
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 */
function vas_auth_get_client_groups( $ctx, $id, $auth );


/****************************************************************************
 *                                                                          *
 *                       ATTRIBUTE/VALUE FUNCTIONS                          *
 *                                                                          *
 ****************************************************************************/

/** Allocate a ::vas_attrs_t.
 *
 * The newly allocated ::vas_attrs_t is used in subsequent calls to
 * vas_attrs_find() and vas_attrs_find_continue() to obtain the attributes of
 * objects in Active Directory via LDAP searches.
 *
 * @param ctx       ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        The identity that will be used to authenticate
 *                  to the server. The id MUST have established
 *                  credentials. Pass in NULL to perform anonymous
 *                  LDAP searches.
 *
 * @return vas_attr_t.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_NOT_FOUND     - Client is NOT a member of group
 **/
function vas_attrs_alloc( $ctx, $id );


/** Execute an LDAP search and process the results.
 *
 * The vas_attrs_find() and vas_attrs_find_continue() functions are wrappers
 * for several LDAP API functions that may make it easier to perform and
 * process the results of LDAP searches. vas_attrs_find() is called first to
 * initiate and obtain the first result of an LDAP search.
 *
 * vas_attrs_find_continue() is used to iterate through the remaining search
 * result. The idea is that a successful call to vas_attrs_find() is followed
 * by calls to vas_attrs_find_continue() until no more results are available
 * (VAS_ERR_NOT_FOUND is returned in this situation).
 *
 * @code
 *
 * {
 *     $anames = array { "cn", NULL };
 *     ...
 *
 *     // Typical vas_attrs_find() loop
 *     // (searches defaultNamingContext of DC in default_realm domain).
 *     if( ($rval = vas_attrs_find( $ctx,
 *                                  $attrs,
 *                                  "DC://",
 *                                  "sub",
 *                                   NULL,
 *                                  "(objectClass=*)",
 *                                  $anames )) )
 *     while( $rval == VAS_ERR_SUCCESS )
 *     {
 *        ...
 *
 *        // display or record attribute values
 *
 *        ...
 *
 *     } while( ( rval = vas_attrs_find_continue( ctx, attrs ) ) )
 *
 *     ...
 * }
 * @endcode
 *
 * Calls to vas_attrs_find() may generate DNS, Kerberos, and LDAP network
 * traffic.
 *
 * @param ctx      A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs    A ::vas_attrs_t obtained from call to vas_attrs_alloc().
 *
 * @param uri      The URI that identifies the server to which it will be bound.
 *                 For more details on URI format see: vas_ldap_init_and_bind().
 *
 * @param scope    Optional LDAP search scope. May one of the following
 *                 strings: "base" for LDAP_SCOPE_BASE, "sub" for
 *                 LDAP_SCOPE_SUBTREE, or "one" for LDAP_SCOPE_ONELEVEL.
 *                 If not set, LDAP_SCOPE_SUBTREE will be used
 *
 * @param base     Optional search base for the LDAP search. The search
 *                 base is specified as a distinguished name
 *                 (OU=myou,DC=foo,DC=com). Pass in NULL to use the
 *                 defaultNamingContext LDAP search base. When using the GC,
 *                 pass in an empty string "" to search the entire global
 *                 catalog.
 *
 * @param filter   Required LDAP search filter that specifies search
 *                 conditions.
 *
 * @param anames   Optional list attributes to obtain. Use an array of
 *                 strings to specify attributes. Use NULL if none.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Matching entry doesn't exist
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_KRB5          - Kerberos error. Use ::vas_err_t functions
 *                                    to obtain Kerberos error details
 *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
 *                                    to obtain LDAP error details
 **/
function vas_attrs_find( $ctx, $attrs, $uri, $scope, $base, $filter, $anames );


/** Continues a previous vas_attrs_find()  Used to get the rest of the
 * results of an LDAP search. vas_attrs_find_continue() should be
 * called until it returns VAS_ERR_NOT_FOUND.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t obtained from vas_attrs_alloc().
 *
 *
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - No more matching entries
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_NOT_FOUND     - Client is NOT a member of group
 *          - VAS_ERR_KRB5          - Kerberos error. Use ::vas_err_t functions
 *                                    to obtain Kerberos error details
 *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
 *                                    to obtain LDAP error details
 **/
function vas_attrs_find_continue( $ctx, $attrs );


/** Set options that change vas_attrs behavior.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t obtained from vas_attrs_alloc().
 *
 * @param option    The option to set. The following options are defined:
 *                  - VAS_ATTRS_B64_ENCODE_ATTRS - List of attributes
 *                    whose values will be base64 encoded when returned
 *                    from calls to vas_vals_get_string().
 *                    Three possible value types:
 *                     - "attribute1,attribute2,..." : String of comma
 *                       seperated attribute names that should be base64
 *                       encoded. This will overwrite the vas.conf settings.
 *                     - "" (Empty string) : This will disable all base64
 *                       encoding.
 *                     - NULL : This will reset the attribute to the vas.conf
 *                       base64-encoded-attrs entry.
 *                    The vas.conf setting can be obtained by calling
 *                    vas_attrs_get_option on this option before any
 *                    set call, or after a NULL set call. Argument is
 *                    either a string or a NULL.
 *                  - VAS_ATTRS_OPTION_SEARCH_TIMEOUT - Number of seconds
 *                    vas_attrs_find() and vas_attrs_find_continue() will
 *                    block before returning VAS_ERR_TIMEDOUT. Argument
 *                    is an integer that is set to the new timeout value.
 *                  - VAS_ATTRS_OPTION_LDAP_PAGESIZE - adjusts the size
 *                    of paged results. Argument is an integer.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 **/
function vas_attrs_set_option( $ctx,
                               $attrs,
                               $option,
                               ... );

/** Get options that change ::vas_attrs_t behavior.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t obtained from vas_attrs_alloc().
 *
 * @param option    The option to get. The following options are defined:
 *                  - VAS_ATTRS_B64_ENCODE_ATTRS - The return value is
 *                    a string. See vas_attrs_set_option for the meaning
 *                    of returned values
 *                  - VAS_ATTRS_OPTION_SEARCH_TIMEOUT - The return value is
 *                    an integer. See vas_attrs_set_option for the meaning
 *                    of returned values
 *                  - VAS_ATTRS_OPTION_LDAP_PAGESIZE - The return value is
 *                    an integer. See vas_attrs_set_option for the meaning
 *                    of returned values
 *
 * @return The option value as indicated above.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 **/
function vas_attrs_get_option( $ctx, $attrs, $option );


/** Obtain string values of an attribute.
 *
 * Note that when requesting the string values for a binary attribute, the
 * resulting string may not be valid. The function will attempt to base-64
 * encode known binary values in order to avoid returning invalid strings. The
 * list of known binary attributes is controlled through the vas.conf file and
 * the base64-encoded-attrs option, or with the VAS_ATTRS_B64_ENCODE_ATTRS
 * ::vas_attrs_opt_t value for the vas_attrs_set_option() function.
 *
 * By default this list is userCertificate, objectGuid, objectSid,
 * userParameters, logonHours, and vintela-sidBL. See the vas.conf
 * man page documenatation or vas_attrs_set_option() for more details.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t used in a call to vas_attrs_find(),
 *                  or vas_attrs_find_continue().
 *
 * @param aname     The name of the attribute to get values for.
 *
 * @return string[] An array of string values.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERROR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Values for the requested attribute
 *                                    were not found in result entry.
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_MORE_VALS     - Indicates that there are more
 *                                    attribute values. This will happen
 *                                    when multi-valued attributes have
 *                                    more than 1500 values (for Windows
 *                                    2003 servers) or 1000 values (for
 *                                    Windows 2000 servers). The attribute
 *                                    values will be returned in sets of
 *                                    1000 or 1500 as they are obtained
 *                                    from Active Directory using
 *                                    Incremental Retrieval of Multi-Valued
                                      Attributes. To obtain the next range
 *                                    of values the caller should call
 *                                    vas_vals_get_string() again using
 *                                    the same vas_attrs_t and aname as the
 *                                    previous call. Continue calling
 *                                    vas_vals_get_string(), until
 *                                    VAS_ERR_MORE_VALS is no longer
 *                                    returned.
 *          - VAS_ERR_LDAP          - LDAP error. Use vas_err_t functions
 *                                    to obtain LDAP error details
 */
function vas_vals_get_string( $ctx, $attrs, $aname );


/** Obtain integer values of an attribute
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t used in a call to vas_attrs_find(),
 *                  or vas_attrs_find_continue().
 *
 * @param aname     The name of the attribute to get values for.
 *
 * @return integer[]   Array of integer values.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Values for the requested attribute
 *                                    were not found in result entry.
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_MORE_VALS     - Indicates that there are more
 *                                    attribute values. This will happen
 *                                    when multi-valued attributes have
 *                                    more than 1500 values (for Windows
 *                                    2003 servers) or 1000 values (for
 *                                    Windows 2000 servers). The attribute
 *                                    values will be returned in sets of
 *                                    1000 or 1500 as they are obtained
 *                                    from Active Directory using
 *                                    Incremental Retrieval of Multi-Valued
                                      Attributes. To obtain the next range
 *                                    of values the caller should call
 *                                    vas_vals_get_integer() again using
 *                                    the same vas_attrs_t and aname as the
 *                                    previous call. Continue calling
 *                                    vas_vals_get_integer(), until
 *                                    VAS_ERR_MORE_VALS is no longer
 *                                    returned.
 *          - VAS_ERR_LDAP          - LDAP error. Use vas_err_t functions
 *                                    to obtain LDAP error details
 */
function vas_vals_get_integer( $ctx, $attrs, $aname );


/** Obtain binary values of an attribute
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t used in a call to vas_attrs_find(),
 *                  or vas_attrs_find_continue().
 *
 * @param aname     The name of the attribute to get values for.
 *
 * @return string[] A array of binary values stored as strings. (PHP
 *                  strings allow binary values).
 *
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Values for the requested attribute
 *                                    were not found in result entry.
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_MORE_VALS     - Indicates that there are more
 *                                    attribute values. This will happen
 *                                    when multi-valued attributes have
 *                                    more than 1500 values (for Windows
 *                                    2003 servers) or 1000 values (for
 *                                    Windows 2000 servers). The attribute
 *                                    values will be returned in sets of
 *                                    1000 or 1500 as they are obtained
 *                                    from Active Directory using
 *                                    Incremental Retrieval of Multi-Valued
                                      Attributes. To obtain the next range
 *                                    of values the caller should call
 *                                    vas_vals_get_binary() again using
 *                                    the same vas_attrs_t and aname as the
 *                                    previous call. Continue calling
 *                                    vas_vals_get_binary(), until
 *                                    VAS_ERR_MORE_VALS is no longer
 *                                    returned.
 *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
 *                                    to obtain LDAP error details
 **/
function vas_vals_get_binary( $ctx, $attrs, $aname );


/** Obtain names of attributes with values.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t used in a call to vas_attrs_find(),
 *                  or vas_attrs_find_continue().
 *
 * @return string[] Array of string values.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Values for the requested attribute
 *                                    were not found in result entry.
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
 *                                    to obtain LDAP error details
 */
function vas_vals_get_anames( $ctx, $attrs );


/** Obtain the distinguished name (DN) from the results of a
 * vas_attrs_find() operation.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param attrs     A ::vas_attrs_t used in a call to vas_attrs_find(),
 *                  or vas_attrs_find_continue().
 *
 * @return string
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - Values for the requested attribute
 *                                    were not found in result entry.
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
 *                                    to obtain LDAP error details
 */
function vas_vals_get_dn( $ctx, $attrs );


/****************************************************************************
 *                                                                          *
 *                          NAME FUNCTIONS                                  *
 *                                                                          *
 ****************************************************************************/

/** Expand a simple user, service, or computer name to a full Kerberos
 * principal name.
 *
 * @param ctx     ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param name    The name to be expanded
 *
 * @param hint    Optional. The type of name being expanded. Recognized
 *                hint values include:
 *                - VAS_NAME_TYPE_USER
 *                - VAS_NAME_TYPE_SERVICE
 *                - VAS_NAME_TYPE_HOST
 *                - VAS_NAME_TYPE_GROUP
 *                - VAS_NAME_TYPE_UNKNOWN
 *                - VAS_NAME_TYPE_SID
 *                - VAS_NAME_TYPE_DN
 *                \verbatim
 *                Providing hint will result in more accurate expansion.
 *                For example, if you were expanding the name "ethan",
 *                the following outputs would be generated:
 *
 *                name="ethan", hint=0
 *                    --> nameout="ethan\@EXAMPLE.COM"
 *                name="ethan", hint=VAS_NAME_TYPE_USER
 *                    --> nameout="ethan\@EXAMPLE.COM"
 *                name="ethan", hint=VAS_NAME_TYPE_SERVICE
 *                    --> nameout="ethan/myhost.example.com\@EXAMPLE.COM"
 *                name="ethan", hint=VAS_NAME_TYPE_HOST
 *                    --> nameout="host/ethan.example.com\@EXAMPLE.COM"
 *
 *                Using the hints VAS_NAME_TYPE_USER, VAS_NAME_TYPE_SERVICE,
 *                VAS_NAME_TYPE_HOST or VAS_NAME_TYPE_GROUP will restrict
 *                the search to only objects of the appropriate type.
 *
 *                If VAS_NAME_TYPE_UNKNOWN is used then vas_name_to_dn()
 *                will attempt to guess the type of object from the name
 *                passed. If VAS_NAME_TYPE_SID or VAS_NAME_TYPE_DN are
 *                passed the objects that match those SID or DNs exactly
 *                will be returned.
 *                \endverbatim
 *
 * @param flags   Flags that modify the expansion behavior:
 *                - VAS_NAME_FLAG_NO_IMPLICIT - Do not expand  the Microsoft
 *                  implicit principal name.
 *                  \verbatim
 *                  name="host/", hint=VAS_NAME_TYPE_HOST, flags=0
 *                     --> nameout="ETHAN$@EXAMPLE.COM"
 *                  name="host/", hint=VAS_NAME_TYPE_HOST, flags=_NO_IMPLICIT
 *                     --> nameout="host/ethan.example.com@EXAMPLE.COM"
 *                  \endverbatim
 *                - VAS_NAME_FLAG_NO_DNS_EXPAND - Do not expand hostname to a
 *                  fully qualified DNS name:
 *                  \verbatim
 *                  name="ethan", hint=HOST, flags=_NO_IMPLICIT | _NO_DNS_EXPAND
 *                   --> nameout="host/ethan@EXAMPLE.COM"
 *                  \endverbatim
 *                 - VAS_NAME_FLAG_FOREST_SCOPE - If a domain/realm part is not
 *                   specified, the entire forest is searched. By default only
 *                   the current realm will be searched.
 *
 * @return string
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 **/
function vas_name_to_principal( $ctx, $name, $hint, $flags );


/** Obtain the LDAP distinguished name for a simple user, group,
 * service, or computer name.
 *
 *
 * @param ctx     ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id      The identity that will be used to authenticate
 *                to the LDAP server. The id MUST have established
 *                credentials. Pass in NULL to perform anonymous
 *                LDAP searches.
 *
 * @param name    The name to obtain the distinguished name for.
 *
 * @param hint    Optional. The type of name being used. Recognized
 *                hint values include:
 *                - VAS_NAME_TYPE_UNKNOWN
 *                - VAS_NAME_TYPE_USER
 *                - VAS_NAME_TYPE_GROUP
 *                - VAS_NAME_TYPE_SERVICE
 *                - VAS_NAME_TYPE_HOST
 *
 * @param flags   Flags that modify the expansion behavior:
 *                - VAS_NAME_FLAG_NO_CACHE
 *                - VAS_NAME_FLAG_NO_LDAP
 *                - VAS_NAME_FLAG_FOREST_SCOPE - If a domain/realm part is
 *                                               not specified, the entire
 *                                               forest is searched. By
 *                                               default only the current
 *                                               realm will be searched.
 *
 * @param &nameout The resulting distinguished name.
 *
 * @param &domainout The Active Directory domain the object represented by
 *                   the name is located in.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND     - No distinguished name found
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_KRB5          - Kerberos error. Use ::vas_err_t functions
 *                                    to obtain Kerberos error details
 *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
 *                                    to obtain LDAP error details
 **/
function vas_name_to_dn( $ctx, $id, $name, $hint, $flags, &$nameout, &$domainout );


/**
 * Compare two names for equality.
 *
 * @param ctx     ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id      The identity that will be used to authenticate.
 *                to the LDAP server. The id MUST have established
 *                credentials. Pass in NULL to perform anonymous
 *                LDAP searches.
 *
 * @param name_a  First name to compare.
 *
 * @param name_b  Second name to compare.
 *
 * @param hint    Optional. The type of name being used. Recognized
 *                hint values include:
 *                - VAS_NAME_TYPE_UNKNOWN
 *                - VAS_NAME_TYPE_USER
 *                - VAS_NAME_TYPE_GROUP
 *                - VAS_NAME_TYPE_SERVICE
 *                - VAS_NAME_TYPE_HOST
 *
 * @param flags   Flags that modify the expansion behavior:
 *                - VAS_NAME_FLAG_NO_CACHE
 *                - VAS_NAME_FLAG_NO_LDAP
 *                - VAS_NAME_FLAG_FOREST_SCOPE - If a domain/realm part is
 *                                               not specified, the entire
 *                                               forest is searched. By
 *                                               default only the current
 *                                               realm will be searched.
 *
 * @return VAS_ERR_SUCCESS if the names match and VAS_ERR_FAILURE if they do
 *   not. In both cases the error code will not be attached to the ::vas_ctx_t
 *   (ie. a call to vas_err_get_code() will not return this error code. If
 *   an error occurs (for example because a name cannot be looked up), then
 *   this call may also return one of the following errors, which
 *   will be attached to the ::vas_ctx_t and
 *   returnable from vas_err_get_code().
 *
 *
 *          - VAS_ERR_NOT_FOUND     - No distinguished name found
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_KRB5          - Kerberos error. Use ::vas_err_t functions
 *                                    to obtain Kerberos error details
 *          - VAS_ERR_LDAP          - LDAP error. Use ::vas_err_t functions
 *                                    to obtain LDAP error details
 *
 **/
function vas_name_compare( $ctx, $id, $name_a, $name_b, $hint, $flags );


/****************************************************************************
 *                                                                          *
 *                        INFORMATION FUNCTIONS                             *
 *                                                                          *
 ****************************************************************************/

/** Obtains the name of the forest root domain
 *
 * @param ctx              A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param &forest_root     Will be set to the root domain of the forest.
 *
 * @param &forest_root_dn  Will be set to the forest root distinguished name
 *                         (DN).
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_CONFIG          - Unable to determine default_realm
 *          - VAS_ERR_DNS             - DNS SRV lookup failed
 *          - VAS_ERR_LDAP            - LDAP error. Use ::vas_err_t functions
 *                                      to obtain LDAP error details
 **/
function vas_info_forest_root( $ctx, &$forest_root, &$forest_root_dn );


/**
 * Obtains the name of the Active Directory domain to which the computer is
 * joined. This function may be used as a test to see if the computer is joined.
 *
 * @param ctx           A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param &domain[]     Will be set to the domain to which the computer is
 *                      joined.
 *
 * @param &domain_dn[]  Will be set to the domain DN to which the computer is
 *                      joined.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_CONFIG          - Unable to determine default_realm
 **/
function vas_info_joined_domain( $ctx, &$domain, &$domain_dn );


/**
 * Obtains the name of the current Active Directory site to which the host
 * belongs.
 *
 * @param ctx      A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @return string  Returns the site name to which the Unix host belongs.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Host does not belong to a site.
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_CONFIG          - Unable to determine default_realm
 *          - VAS_ERR_DNS             - DNS SRV lookup failed
 *          - VAS_ERR_LDAP            - LDAP error. Use ::vas_err_t functions
 *                                      to obtain LDAP error details
 **/
function vas_info_site( $ctx );


/**
 * Obtain names of Active Directory domain controllers in the specified domain.
 *
 * Calls to vas_info_domains() may generate DNS network traffic.
 *
 * @param ctx            A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id             The identity that will be used to search Active
 *                       Directory. The id must have established credentials.
 *                       Pass in NULL to *attempt* anonymous discovery of
 *                       domains -- which may fail depending on permissions set
 *                       in AD.
 *
 * @param &domains[]     Will be allocated and filled with domain name strings.
 *
 * @param &domains_dn[]  Will be allocated and filled with distinguished name
 *                      (DN) strings.
 *
 * @return vas_err().
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Host does not belong to a site.
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_CONFIG          - Unable to determine default_realm
 *          - VAS_ERR_DNS             - DNS SRV lookup failed
 *          - VAS_ERR_LDAP            - LDAP error. Use ::vas_err_t functions
 *                                      to obtain LDAP error details
 **/
function vas_info_domains( $ctx, $id, &$domains, &$domains_dn );


/** Obtain names of Active Directory domain controllers in the specified domain.
 *
 * Calls to vas_info_servers() may generate DNS network traffic.
 *
 * @param ctx     A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param domain  The name of the domain you want to get servers for.
 *                Pass in NULL to get servers for the domain to which the
 *                computer is joined. When obtaining global
 *                catalog servers, the domain parameter is ignored
 *                and the API automatically returns all Global
 *                catalogs in the specified site.
 *
 * @param site    The name of the site you want to get servers for. Pass NULL
 *                to get servers for the site to which the computer
 *                is joined. Pass in "*" to get servers for any
 *                site.
 *
 * @param type    The type of server you are looking for:
 *                - VAS_SRVINFO_TYPE_ANY - Any server
 *                - VAS_SRVINFO_TYPE_DC  - Windows Domain Controller
 *                - VAS_SRVINFO_TYPE_GC  - Windows Global Catalog
 *                - VAS_SRVINFO_TYPE_PDC - Windows Primary DC
 *
 * @return string[] Will be allocated and
 *                filled with server hostname strings that are in the same
 *                site as the Unix host.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Host does not belong to a site.
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_CONFIG          - Unable to determine default_realm
 *          - VAS_ERR_DNS             - DNS SRV lookup failed
 *          - VAS_ERR_LDAP            - LDAP error. Use ::vas_err_t functions
 *                                      to obtain LDAP error details
 **/
function vas_info_servers( $ctx, $domain, $site, $type );


/****************************************************************************
 *                                                                          *
 *                      MISC/UTILITY FUNCTIONS                              *
 *                                                                          *
 ****************************************************************************/

/** Obtain a password by prompting and reading input from the console
 *
 * @param ctx    A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param prompt The string that will be used as the credential prompt
 *
 * @param verify Optional verification prompt. Useful (for example)
 *               when prompting for a new password. Pass in NULL to skip
 *               verification prompt.
 *
 * @return string Returns the credential string.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_FAILURE         - Failed to read password from prompt
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 **/
function vas_prompt_for_cred_string( $ctx, $prompt, $verify );


/****************************************************************************
 *                                                                          *
 *                        ERROR FUNCTIONS                                   *
 *                                                                          *
 ****************************************************************************/

/**
 * Used to obtain the error code for the last error that occurred using the
 * specified ::vas_ctx_t.
 *
 * @param ctx         The ::vas_ctx_t to get the error code from
 *
 * @return vas_err_t The VAS error code (an integer).
 *                   The last error code or VAS_ERR_SUCCESS if no error.
 **/
function vas_err_get_code( $ctx );


/**
 * Used to obtain a formatted error string for the last error that
 * occurred using the specified ::vas_ctx_t.
 *
 * @param ctx         The ::vas_ctx_t to get the error string from
 *
 * @param with_cause  Pass in a non-zero value to include the cause as
 *                    part of the formatted error string
 *
 * @return string     The error string.

 *
 * On return vas_err() is set as follows:
 *          -           Pointer to error string.
 **/
function vas_err_get_string( $ctx, $with_cause );


/**
 * Clear the last error that occurred on the specified ::vas_ctx_t.
 *
 * @param ctx    The ::vas_ctx_t to clear the error for.
 *
 **/
function vas_err_clear( $ctx );


/**
 * Used to obtain information about the last error that occurred using the
 * specified ::vas_ctx_t.
 *
 * @param ctx    The ::vas_ctx_t to get error information from
 *
 * @return CVAS_err_info
 **/
function vas_err_get_info( $ctx );


/**
 * Used to obtain a formatted error string from the supplied ::vas_err_info_t.
 *
 * @param ctx         A ::vas_ctx_t from vas_ctx_alloc().
 *
 * @param info        CVAS_err_info to get error info from
 *
 * @param with_cause  Pass in non-zero to include the cause as part of the
 *                    formatted error string
 *
 * @return string The formatted string.
 * A NULL return indicates that it was not possible to
 *                    construct an error string
 **/
function vas_err_info_get_string( $ctx, $info, $with_cause );


/**
 * Get the first cause in the error chain which matches the given type.
 * This should be used for example to examine an underlying Kerberos or LDAP
 * error.
 *
 * @param ctx    The ::vas_ctx_t to get error information from
 *
 * @param type   The ::vas_err_type_t type to match
 *
 * @return CVAS_err_info  A NULL return indicated that it was not possible to construct the object.
 */
function vas_err_get_cause_by_type( $ctx, $type );


/****************************************************************************
 *                                                                          *
 *                            VAS USER FUNCTIONS                            *
 *                                                                          *
 ****************************************************************************/

/**
 * Lookup a user account and return a ::vas_user_t.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        The identity of user to perform Active Directory searches
 *                  (NULL to allow an anonymous search).
 *
 * @param name      The name of the user account to resolve. See
 *                  vas_name_to_dn() for details of the supported name formats.
 *
 * @param flags     The flags to pass to control searching behaviour. See
 *                  vas_name_to_dn() for supported flags and their behaviour.
 *
 * @return vas_user_t
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Could not locate a user account
 *                                      with the given name.
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_init( $ctx, $id, $name, $flags );


/**
 * Compare two ::vas_user_t objects for equality.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param user_a    First user to compare.
 * @param user_b    Second user to compare.
 *
 * @return VAS_ERR_SUCCESS if users are equal, VAS_ERR_FAILURE otherwise.
 */
function vas_user_compare( $ctx, $user_a, $user_b );


/**
 * Determine whether the given user account is a member of the given Active
 * Directory group.
 *
 * If the user is not a member, VAS_ERR_NOT_FOUND is returned, but this
 * error is not added to the ::vas_ctx_t passed in. Therefore you should
 * call this as follows:
 *
 * @code
 * switch ( vas_user_is_member( ctx, id, user, group ) )
 * {
 * case VAS_ERR_SUCCESS:
 *     // The user is a member
 *     ...
 * case VAS_ERR_NOT_FOUND:
 *     // The user is not a member
 *     ...
 *
 * default:
 *     // A different error has occurred
 *     err_str = vas_err_get_string( ctx, 1 );
 *     ...
 * }
 * @endcode
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user to perform Active Directory searches
 *                  (NULL to allow an anonymous search).
 *
 * @param user      A ::vas_user_t for the user account.
 *
 * @param group     A ::vas_group_t for the group to check membership of.
 *
 * @return the vas_err() code is returned.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS if the user is a member of the group, or one of
 *            the following error codes:
 *          - VAS_ERR_NOT_FOUND       - The user is not a member of the group
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 * @see vas_group_has_member().
 **/
function vas_user_is_member( $ctx, $id, $user, $group );

/**
 * Get the Active Directory groups of which a user is a member.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user to perform Active Directory searches
 *                  (NULL to allow an anonymous search).
 *
 * @param user      A ::vas_user_t for the user account.
 *
 * @return vas_groups_t[]   Used to return the groups of which the user is a
 *                          member.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 **/
function vas_user_get_groups( $ctx, $id, $user );


/**
 * Get arbitrary attributes from the Active Directory user object for this
 * ::vas_user_t.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param user      A ::vas_user_t for the user account.
 *
 * @param anames    Array of attribute names to retrieve.
 *
 * @return vas_attrs_t     The values for the
 *                  requested attributes can be obtained using this value with
 *                  the vas_vals_get* family of functions.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or on of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 **/
function vas_user_get_attrs( $ctx, $id, $user, $anames );


/**
 * Get the distinguished name (DN) for a user account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param user      A ::vas_user_t for the user account.
 *
 * @return string  Used to return the DN of the user account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_get_dn( $ctx, $id, $user );


/**
 * Get the Active Directory domain to which the given user belongs.
 *
 * @param ctx      A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id       Identity of user used to perform Active Directory searches.
 *                 Pass NULL to perform anonymous searches.
 *
 * @param user     A ::vas_user_t for the user account.
 *
 * @return string   Used to return the domain of the user account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 * @since 3.0.1
 **/
function vas_user_get_domain( $ctx, $id, $user );


/**
 * Get the SAM Account Name for a user.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 * @param user      A ::vas_user_t for the user account.
 *
 * @return string   Used to return the SAM account name of the user
 *                  object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_get_sam_account_name( $ctx, $id, $user );


/**
 * Get the SID for a user account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform an anonymous searches.
 *
 * @param user      A ::vas_user_t for the user account.
 *
 * @return string       Used to return the sid of the user account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or non-zero errno on error. The
 *          following return values are defined:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_get_sid( $ctx, $id, $user );


/**
 * Get the User Principal Name (UPN) for a user account.
 *
 * @param ctx     A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id      Identity of user used to perform Active Directory searches
 *                Pass NULL to perform anonymous searches.
 *
 * @param user    A ::vas_user_t for the user account.
 *
 * @return string Used to return the UPN of the user account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_get_upn( $ctx, $id, $user );


/**
 * Get the passwd entry for a Unix enabled user.
 *
 * This function returns a struct passwd which contains the Unix username
 * uid, gid etc of a user. If the user is not Unix enabled VAS_ERR_NOT_FOUND
 * is returned. This function
 * does not search Active Directory directly, but uses the VAS cache mechanism
 * to look up the information. The returned passwd struct contains the
 * user information directly from Active Directory, which will not be validated
 * for the local Unix system (for example - the UID is not validated to ensure
 * that is within the valid range for the Unix system). This function does not
 * call the system getpwnam() function.
 *
 * @param ctx           A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id            Currently unused, may be NULL.
 *
 * @param user          A ::vas_user_t for the user account.
 *
 * @return class CVAS_passwd           struct passwd for returning information
 *                      about a Unix enabled user.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - User is not a Unix enabled user
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_get_pwinfo( $ctx, $id, $user );


/**
 * Get the Kerberos client name for a user account.
 *
 * This function returns the user account's Kerberos principal name
 * for retrieving client tickets. This is equivalent to
 * samAccountName\@realm. This name is always guaranteed to work for
 * obtaining ticket granting tickets for any user account.
 *
 * @param ctx           A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id            Identity of user used to perform Active Directory searches.
 *                      Pass NULL to perform anonymous searches.
 *
 * @param user          A ::vas_user_t for the user account.
 *
 * @return string   Used to return the Kerberos client name
 *                      of the user account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_get_krb5_client_name( $ctx, $id, $user );


/**
 * Get account control flags for this user account.
 *
 * @param ctx               A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id                Identity of user used to perform Active Directory
                            searches. Pass  NULL to perform anonymous searches.
 *
 * @param user              A ::vas_user_t for the user account.
 *
 * @return integer   An integer to return the flags.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_get_account_control( $ctx, $id, $user );


/**
 * Check if a user has access to a given service.
 *
 * This function queries the VAS users.allow and users.deny files, or the
 * service specific rule set if configured, to determine
 * whether a given user may access a given service on this machine.
 *
 * @param ctx               A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param user              A ::vas_user_t for the user account.
 *
 * @param service           Service to check access for. This may be NULL to
 *                          query the default users.allow and users.deny file.
 *                          If no allow or deny file has been configured for the
 *                          given service, then the default users.allow and
 *                          users.deny files will be used as well. For
 *                          information on configuring these access control files,
 *                          see the VAS Administrator's Guide.
 *
 * @return The vas_err() code is returned.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCESS if the user is allowed access, or one of the
 *          following error codes:
 *          - VAS_ERR_ACCESS          - Access is denied for the service.
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_check_access( $ctx, $user, $service );


/**
 * Check to see if a user has a UID conflict with another user.
 *
 * This function will determine whether any Unix accounts on the current Unix
 * host have the same Unix UID number as the given user. The set of Unix
 * accounts searched include the local Unix accounts, the set of Active Directory
 * Unix accounts configured for the given system, and any other Unix accounts
 * available to the Unix host through other account backends (for example, NIS).
 *
 * @param ctx               A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param user              A ::vas_user_t for the user account.
 *
 * @return The vas_err() code is returned.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS if no conflicts were found, or one of the
 *          following error codes:
 *          - VAS_ERR_EXISTS          - A user with a conflicting UID was found
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_user_check_conflicts( $ctx, $user );


/****************************************************************************
 *                                                                          *
 *                           VAS GROUP FUNCTIONS                            *
 *                                                                          *
 ****************************************************************************/

/**
 * Create a vas_group_t for the given Active Directory group
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform an anonymous searches.
 * @param name      Name of the group to resolve. See
 *                  vas_name_to_dn() for details of the supported name formats.
 * @param flags     Flags to pass to control searching behaviour. See
 *                  vas_name_to_dn() for supported flags and their behaviour.
 *
 * @return vas_group_t The new group.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Could not locate a group
 *                                      with the given name.
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_group_init( $ctx, $id, $name, $flags );


/**
 * Compare two ::vas_group_t objects for equality.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param group_a   First group to compare.
 * @param group_b   Second group to compare.
 *
 * @return VAS_ERR_SUCCESS if users are equal, VAS_ERR_FAILURE otherwise.
 */
vas_err_t vas_group_compare( $ctx, $a, $b );


/**
 * Determine whether a group has the given user as a member.
 *
 * If the user is not a member, VAS_ERR_NOT_FOUND is returned, but this
 * error is not added to the vas_ctx_t passed in. Therefore you should
 * call this as follows:
 *
 * @code
 * switch ( vas_group_has_member( $ctx, $id, $group, $user ) )
 * {
 *    case VAS_ERR_SUCCESS:
 *        // The user is a member
 *        ...
 *    case VAS_ERR_NOT_FOUND:
 *        // The user is not a member
 *        ...
 *    default:
 *        // A different error has occurred
 *        err_str = vas_err_get_string( ctx, 1 );
 *        ...
 * }
 * @endcode
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param id        Identity of user to perform Active Directory searches as.
 *                  Pass NULL to perform anonymous searches.
 * @param group     A ::vas_group_t for the group.
 * @param user      A ::vas_user_t for the user account to check membership.
 *
 * @return The vas_err() code is returned.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS if the user is a member of the group, or one of the
 *          following error codes:
 *          - VAS_ERR_NOT_FOUND       - The user is not a member
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 **/
function vas_group_has_member( $ctx, $id, $group, $user );


/**
 * Lookup arbitrary attributes for the given group.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 * @param group     A ::vas_group_t for the group.
 * @param anames    Array of attribute names to get.
 * @return vas_attrs_t     Attributes.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 **/
function vas_group_get_attrs( $ctx, $id, $group, $anames );


/**
 * Get the distinguished name (DN) for a group.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 * @param group     A ::vas_group_t for the group.
 *
 * @return string  Used to return the DN of the group.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_group_get_dn( $ctx, $id, $group );


/**
 * Get the Active Directory domain the group exists in.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 * @param group     A ::vas_group_t for the group.
 * @return string   Used to return the domain the group exists in.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 * @since 3.0.1
 **/
function vas_group_get_domain( $ctx, $id, $group );


/**
 * Get the SID for a group.
 *
 * @param ctx      A :vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id       Identity of user used to perform Active Directory searches.
 *                 Pass NULL to perform anonymous searches.
 *
 * @param group    A ::vas_group_t for the group.
 *
 * @return string  Used to return the sid of the group.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_group_get_sid( $ctx, $id, $group );


/**
 * Get the group entry for a Unix enabled group
 *
 * This function returns a struct group which contains the Unix group,
 * gid and members of a group. If the group is not Unix enabled VAS_ERR_NOT_FOUND
 * is returned. Memory for both the group structure and the string pointers
 * in this structure is allocated in a contiguous buffer that must be freed
 * by calling free() on the returned struct group pointer. This function
 * does not search Active Directory directly, but uses the VAS cache mechanism
 * to look up the information. The returned group struct contains the
 * user information directly from Active Directory, which will not be validated
 * for the local Unix system (for example, the GID is not validated to ensure
 * that is within the valid range for the Unix system). This function does NOT
 * call the system getgrnam() function.
 *
 * @param ctx      A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id       Currently unused, may be NULL.
 *
 * @param group    A ::vas_group_t for the group account.
 *
 * @param grp      pointer to struct group for returning information about a
 *                 Unix-enabled group. Must be freed by calling free().
 *                 If this function fails, the structure pointed at by grp
 *                 is undefined and must not be freed.
 *
 * @return  struct group* grp     Returns a pointer to the Unix-emabled group
 *                  information structure.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_NOT_FOUND       - Group is not a Unix enabled group
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_group_get_grinfo( $ctx, $id, $group );


/****************************************************************************
 *                                                                          *
 *                      VAS SERVICE ACCOUNT FUNCTIONS                       *
 *                                                                          *
 ****************************************************************************/

/**
 * Create a ::vas_service_t for the given Active Directory service account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user to perform Active Directory searches as.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param name      Name of the service account to resolve. See
 *                  vas_name_to_dn() for details of the supported name formats.
 *
 * @param flags     Flags to pass to control searching behaviour. See
 *                  vas_name_to_dn() for supported flags and their behaviour.
 *
 * @return vas_service_t The new vas_service_t
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Could not locate a service account
 *                                      with the given name.
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_service_init( $ctx, $id, $name, $flags );


/**
 * Compare two ::vas_service_t objects for equality.
 *
 * @param ctx           A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param service_a     First service to compare.
 * @param service_b     Second service to compare.
 *
 * @return VAS_ERR_SUCCESS if users are equal, VAS_ERR_FAILURE otherwise.
 */
function vas_service_compare( $ctx, $service_a, $service_b );


/**
 * Lookup attributes for the given Active Directory service account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user to perform Active Directory searches as.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param service   A ::vas_service_t for the service account.
 *
 * @param anames    An array of attributes names to lookup
 *
 * @return vas_attrs_t     The attribute values can be obtained
 *                  with the vas_vals_get* family of functions.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 **/
function vas_service_get_attrs( $ctx, $id, $service, $anames );


/**
 * Get the distinguished name (DN) for a service account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param service   A ::vas_service_t for the service account.
 *
 * @return string   Used to return the DN of the service account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_service_get_dn( $ctx, $id, $service );


/**
 * Get the Active Directory domain to which the given service belongs.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param service   A ::vas_service_t for the service account.
 *
 * @return string   Used to return the domain of the service account.
 *
 *
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 * @since 3.0.1
 **/
function vas_service_get_domain( $ctx, $id, $service );


/**
 * Get the Kerberos client name for a service account.
 *
 * This function returns the service account's Kerberos principal name
 * for retrieving client tickets. This is equivalent to
 * samAccountName\@realm. This name is always guaranteed to work for
 * obtaining ticket granting tickets for any service account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param service   A ::vas_service_t for the service account.
 *
 * @return string   Used to return the Kerberos client name of the service
 *                  account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_service_get_krb5_client_name( $ctx, $id, $service );


/**
 * Get a list of Service Principal Names (SPNs) for a service account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param service   A ::vas_service_t for the service account.
 *
 * @return string[] Used to return an array of the SPNs of
 *                  the service account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_service_get_spns( $ctx, $id, $service );


/**
 * Get the User Principal Name (UPN) for a service account.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param service   A ::vas_service_t for the service account.
 *
 * @return string   Used to return the UPN of the service account.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_service_get_upn( $ctx, $id, $service );


/****************************************************************************
 *                                                                          *
 *                   COMPUTER OBJECT RELATED FUNCTIONS                      *
 *                                                                          *
 ****************************************************************************/

/**
 * Lookup a computer object and return a ::vas_computer_t.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param name      Name of the computer object to resolve. See
 *                  vas_name_to_dn() for details of the supported name formats.
 *
 * @param flags     Flags to pass to control searching behaviour. See
 *                  vas_name_to_dn() for supported flags and their behaviour.
 *
 * @return vas_computer_t
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - Could not locate a computer object
 *                                      with the given name.
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 */
function vas_computer_init( $ctx, $id, $name, $flags );


/**
 * Compare two ::vas_computer_t objects for equality.
 *
 * @param ctx           A ::vas_ctx_t obtained from vas_ctx_alloc().
 * @param computer_a    First computer to compare.
 * @param computer_b    Second computer to compare.
 *
 * @return VAS_ERR_SUCCESS if users are equal, VAS_ERR_FAILURE otherwise.
 */
function vas_computer_compare( $ctx, $computer_a, $computer_b );

/**
 * Determine whether the given computer object is a member of the given
 * Active Directory group.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @param group     A ::vas_group_t for the group to check membership of.
 *
 * @return The vas_err() code is returned.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_NOT_FOUND       - The user is not a member
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 * @see vas_user_is_member().
 **/
function vas_computer_is_member( $ctx, $id, $computer, $group );


/**
 * Lookup attributes for the given computer object.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @param anames    An array of attribute names to retrieve.
 *
 * @return vas_attrs_t     The attribute values can be obtained using this
 *                  value with the vas_vals_get* family of functions.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 **/
function vas_computer_get_attrs( $ctx, $id, $computer, $anames );

/**
 * Get the distinguished name (DN) for a computer object.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string   Used to return the DN of the computer object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_dn( $ctx, $id, $computer );


/**
 * Get the name for a computer object by which it is known to the Domain Name
 * Service (DNS).
 *
 * @param ctx      A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id       Identity of user used to perform Active Directory searches.
 *                 Pass NULL to perform anonymous searches.
 *
 * @param computer A ::vas_computer_t for the computer object.
 *
 * @return string  Used to return the DNS name of the computer object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_dns_hostname( $ctx, $id, $computer );


/**
 * Get the Active Directory domain the given computer exists in.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string   Used to return the domain of the computer object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 *
 * @since 3.0.1
 **/
function vas_computer_get_domain( $ctx, $id, $computer );


/**
 * Get the SID for a computer object.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string   Used to return the sid of the computer object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_sid( $ctx, $id, $computer );


/**
 * Get the Service Principal Names (SPNs) for a computer object.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string[] Used to return the SPNs of the computer object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_spns( $ctx, $id, $computer );


/**
 * Get the SAM Account Name (NETBIOS name) for a computer object.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string   Used to return the SAM Account Name of the computer object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_sam_account_name( $ctx, $id, $computer );


/**
 * Get the User Principal Name (UPN) for a computer object.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string   Used to return the UPN of the computer object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_upn( $ctx, $id, $computer );


/**
 * Get the Kerberos client name for a computer object.
 *
 * This function returns the computer object's Kerberos principal name
 * for retrieving client tickets. This is equivalent to NETBIOS\$\@realm where
 * NETBIOS is the NETBIOS name or samAccountName of the computer object.
 * This name is always guaranteed to work for obtaining ticket granting
 * tickets for any computer object.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string   Used to return the Kerberos client name of the computer
 *                  object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_krb5_client_name( $ctx, $id, $computer );


/**
 * Get the Kerberos service name for a computer object.
 *
 * This function returns the computer object's Kerberos principal name
 * for obtaining service tickets. This is equivalent to
 * HOST/NETBIOS\$\@realm where NETBIOS is the NETBIOS  or samAccountName.
 * This name is always guaranteed to work for obtaining service tickets for
 * any computer object.
 *
 * Note: this function does not return the servicePrincipalName attribute
 * from Active Directory, which is not guaranteed to be set.
 * To retrieve the Service Principal Names using the servicePrincipalName
 * attribute, use the vas_computer_get_spns() function.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        Identity of user used to perform Active Directory searches.
 *                  Pass NULL to perform anonymous searches.
 *
 * @param computer  A ::vas_computer_t for the computer object.
 *
 * @return string   Used to return the Kerberos service name of the computer
 *                  object.
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_host_spn( $ctx, $id, $computer );


/**
 * Get account control flags for this computer object.
 *
 * @param ctx               A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id                Identity of user used to perform Active Directory
 *                          searches. Pass NULL to perform anonymous searches.
 *
 * @param computer          A ::vas_computer_t for the computer object.
 *
 * @return integer
 *
 * On return vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM   - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY       - Memory allocation failed
 *          - VAS_ERR_FAILURE         - Unspecified failure
 **/
function vas_computer_get_account_control( $ctx, $id, $computer );

?>
