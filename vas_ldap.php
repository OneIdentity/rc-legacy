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
 * Function declarations that allow transition to the LDAP API
 *
 * These declarations are intended to be used in conjunction with the
 * LDAP header files that are shipped with the VAS SDK and with libvas.so
 * no other LDAP header files LDAP library should be linked in.
 **/


/** Obtain an initialized and bound LDAP handle that can be used with
 *  "standard" the LDAP V3 functions included with the VASAPI.
 *
 * @param ctx   A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id    The identity that will be used to authenticate
 *              to the LDAP server. The id MUST have established
 *              credentials. Pass in NULL to perform anonymous
 *              LDAP searches.
 *
 * @param uri   The URI that identifies what will be bound to
 *              an acceptable URI looks like one of  following:
 *              *              - "DC://"[ server ][ "@" domain ]
 *              - "GC://"[ server ][ "@" domain ]
 *              - "LDAP://"[ server ][ ":" port ]
 *
 *              Use a DC:// URI when you need to bind to Active
 *              Directory Domain controllers in a specific domain.
 *              If a DC:// URI is used without specifying a domain,
 *              the library will select a domain controller that is
 *              in the same domain as the identity being used in
 *              the call to vas_ldap_init_and_bind().
 *
 *              Use a GC:// URI when you need to bind to a Microsoft
 *              Active Directory Global Catalog. Though not normally
 *              necessary, you may specify a particular server and
 *              domain. If a server is not specified, the library will
 *              select a Global Catalog that is in the current site.
 *
 *              The LDAP:// URI is provided for *partial* compatibility
 *              with rfc2255. ldap_init_and_bind() only recognizes the
 *              host and port components of an RFC 2255 URI. If the
 *              LDAP:// URI does not specify a  port, the default LDAP
 *              port (389) will be used.
 *
 *              The following are examples of valid URIs:
 *              - DC://
 *              - DC://myserver.example.com
 *              - GC://
 *              - GC://myserver.example.com
 *              - LDAP://
 *              - LDAP://myserver.example.com
 *              - LDAP://myserver.example.com:389
 *
 * @return ldap-handle    Set to point to an initialized and bound LDAP handle.
 *
 * vas_err() is set as follows:
 *          - VAS_ERR_SUCCESS on success, or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM  - Invalid parameters
 *          - VAS_ERR_NO_MEMORY      - Memory allocation failed
 *          - VAS_ERR_CONFIG         - Default realm not configured
 *          - VAS_ERR_CRED_NEEDED    - Need credentials for id
 *          - VAS_ERR_CRED_EXPIRED   - Credentials have expired
 *          - VAS_ERR_KRB5           - Could not perform Kerberos auth
 *          - VAS_ERR_LDAP           - Could not connect to LDAP server
 */
function vas_ldap_init_and_bind( $ctx, $id, $uri );


/** Set attributes on a given LDAP object.
 *
 * @param ctx   A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id    The identity that will be used to authenticate
 *              to the LDAP server. The id MUST have established
 *              credentials. Pass in NULL to perform an anonymous
 *              LDAP modify, however, Active Directory permissions will not
 *              allow an anonymous modify in most cases.
 *
 * @param uri   The URI that identifies the server that will be bound to.
 *              For more details on URI format see: vas_ldap_init_and_bind()
 *
 * @param dn    The distinguished name of the LDAP object to modify
 *
 * @param mods  An array of CVAS_LDAPMod structures. See the LDAP
 *              documentation for more information on how to use LDAPMod
 *              structures.
 *
 * @return  VAS_ERR_SUCCESS on success, or one of the following error codes:
 *          - VAS_ERR_INVALID_PARAM  - Invalid parameters
 *          - VAS_ERR_NO_MEMORY      - Memory allocation failed
 *          - VAS_ERR_LDAP           - LDAP specific error
 */
function vas_ldap_set_attributes( $ctx,
                                  $id,
                                  $uri,
                                  $dn,
                                  $mods );

?>
