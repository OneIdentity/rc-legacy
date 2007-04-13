<?php

/**
 * Vintela Authentication Service (VAS) GSSAPI and SPNEGO transition API
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
 * Function declarations for SPNEGO convenience functions and functions
 * that allow transition to RFC 2744 GSSAPI
 *
 * These declarations are intended to be used in conjunction with the
 * GSSAPI (RFC 2744) implementation found in libvas.so. Do not link in
 * any other GSSAPI library!
 *
 * ----------
 *
 * Provides a GSSAPI implementation that is compatibile with RFCs
 * 1508 and 1509.
 *
 * The implementation is contained in libvas.so. No other GSSAPI library
 * should be linked in when linking to libvas.
 *
 * ----------
 *
 * Function declarations that allow transition to the "MIT-style" KRB5 API
 *
 * These declarations are intended to be used in conjunction with the
 * krb5 header files that are part of the VAS SDK. The implementation for the
 * krb5 library is found in libvas.so. No other krb5 library should be
 * linked in.
 **/


/** The encoding types for SPNEGO tokens.
 */
enum vas_gss_spnego_encoding_t
{
    VAS_GSS_SPNEGO_ENCODING_DER = 0,   /* The tokens are encoded with
                                           standard ASN.1 DER. */
    VAS_GSS_SPNEGO_ENCODING_BASE64 = 1 /* The tokens are standard ASN.1 DER
                                          encoded, then base64 encoded. */
};


/** Developers using the GSSAPI functionality VAS API Library should call
 * vas_gss_initialize() before using any of the vas_gss or GSSAPI v2
 * functions. Calling vas_gss_initialize() causes some of the data from VAS
 * API to be used when initializing GSSAPI data structures. In particular,
 * calling vas_gss_initialize() allows the GSSAPI to operate using the
 * credential cache (and keytab) associated with the specified ::vas_id_t.
 *
 * The design of the GSS API version 2 (RFC 2744) makes it difficult to
 * accomplish many mechanism-specific tasks such as selection of
 * default_realm/domain, credential caches,and keytabs. Fortunately, efforts
 * toward GSSAPI v3 are being made in the IETF Kitten Workgroup that may
 * address some of the difficulties for GSSAPI implementors.
 *
 * NOTE: Unlike in other versions of the API, there is no equivelant
 *       functionality to vas_gss_deinitialize() in the PHP API.
 *
 * @param ctx   A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id    A ::vas_id_t whose credential cache, keytab, and realm
 *              information will be used as defaults for the GSSAPI
 *              implementation. Pass in NULL to use standard Kerberos
 *              derived defaults (ccache derived from username and
 *              default_realm and default_keytab_name derived from the
 *              vas.conf file).
 *
 * @return null
 *
 * On return vas_err() is set as follows: VAS_ERR_SUCCESS on success or one of
 * the following error codes:
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t functions
 *                                    to obtain Kerberos error details
 **/
function vas_gss_initialize( vas_ctx_t* ctx , vas_id_t* id );

/** Obtain a GSSAPI credential from a ::vas_id_t.
 *
 * @param ctx     A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id      A ::vas_id_t with established credentials.
 *
 * @param usage   One of the following GSS credentials types:
 *                - GSS_C_BOTH
 *                - GSS_C_INITIATE
 *                - GSS_C_ACCEPT
 *
 * @return gss_cred_id_t The returned credential handle.
 *
 * On return vas_err() is set as follows: VAS_ERR_SUCCESS on success or one of
 * the following error codes:
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t
 *                                    functions to obtain Kerberos error
 *                                    details
 *
 * On return vas_err_minor() is set to any minor status code returned.
 **/
function  vas_gss_acquire_cred( $ctx, $id, $usage );

/** Obtain a ::vas_auth_t from the ::gss_ctx_id_t established by a completed
 * call to gss_accept_sec_context() or vas_gss_spnego_accept().
 *
 * @param ctx     A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param cred    Credential used as the acceptor in call to
 *                gss_accept_sec_context().
 *
 * @param context The gss_ctx_id_t returned by completed calls to
 *                gss_accept_sec_context() and vas_gss_spnego_accept()
 *
 * @return vas_auth_t
 *
 * On return vas_err() is set as follows: VAS_ERR_SUCCESS on success or one of
 * the following error codes:
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t
 *                                    functions to obtain Kerberos error
 *                                    details
 *
 * On return vas_err_minor() is set to any minor status code returned.
 **/
function vas_gss_auth( $ctx, $cred, $context );

/** Convenience function used to obtain an initiator GSS SPNEGO token (or
 * continue GSS SPNEGO negotiation as an initiator).
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        The ::vas_id_t of the client initiator.
 *
 * @param reserved  Pass in NULL.
 *
 * @param gssctx    Will be set to a gss_ctx_id_t, the read/modify context
 *                  handle for the new context.
 *                  Supply GSS_C_NO_CONTEXT for the first call.
 *
 * @param name      The principal name of the server
 *                  For example: "http/jaws.foobar.com@foobar.com"
 *
 * @param  flags    Bitmask of GSS_C_XXXXX_FLAG values. Currently supports
 *                  - GSS_C_DELEG_FLAG
 *                  - GSS_C_MUTUAL_FLAG
 *                  - GSS_C_REPLAY_FLAG
 *                  - GSS_C_SEQUENCE_FLAG
 *                  - GSS_C_CONF_FLAG
 *                  - GSS_C_INTEG_FLAG
 *
 * @param encoding  Specifies the encoding format for in and out negotiation
 *                  tokens. Currently supported values include:
 *                  - VAS_GSS_SPNEGO_ENCODING_DER
 *                  - VAS_GSS_SPNEGO_ENCODING_BASE64
 *
 * @param in_token  The input token buffer. Should be GSS_C_NO_BUFFER when
 *                  on first call. On a subsequent calls, the in_token should
 *                  be the negTokenTarg NegotiationToken like what is returned
 *                  as an out_token from a call to vas_gss_spnego_accept(). In
 *                  PHP, these tokens are strings.
 *
 * @param out_token Reference to the output token buffer. The out_token buffer

 *                  will be a Mechanism-Independent Token as defined by RFC
 *                  2078 where the innerToken is a negTokenInit Negotiation
 *                  Token as defined by RFC 2478. The resulting out_token is
 *                  suitable for use as an in_token in a call to
 *                  vas_gss_spnego_accept(). In PHP, these tokens are strings.
 *
 * @return GSS status code as documented in 5.19 of RFC 2744.
 **/
function vas_gss_spnego_initiate( $ctx,
                                  $id,
                                  $reserved,
                                  &$gssctx,
                                  $name,
                                  $flags,
                                  $encoding,
                                  $in_token,
                                  &$out_token );


/** Convenience function used to accept GSS SPNEGO tokens (or continue
 * GSS SPNEGO negotiation as an acceptor).
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        The ::vas_id_t of the service acceptor.
 *
 * @param auth      [out] Parameter set to a ::vas_auth_t
 *
 * @param gssctx    [in/out] gss_ctx_id_t, read/modify context handle for new
 *                  context.
 *                  Supply GSS_C_NO_CONTEXT for first call.
 *
 * @param flags     [out] Flags that were returned by underlying gssapi call.
 *
 * @param encoding  Specifies the encoding format for in and out negotiation
 *                  tokens. Currently supported values include:
 *                  - VAS_GSS_SPNEGO_ENCODING_DER
 *                  - VAS_GSS_SPNEGO_ENCODING_BASE64
 *
 * @param in_token  The input token buffer which should be a
 *                  Mechanism-Independent Token as defined by RFC 2078
 *                  where the innerToken is a negTokenInit Negotiation
 *                  Token; this is what is generated as an out_token by
 *                  the call to vas_gss_spnego_initiate(). In PHP, these tokens
 *                  are strings.
 *
 * @param out_token [out] The output token buffer. The
 *                  output buffer is a negTokenTarg Negotiation token
 *                  that is suitable for use as an in_token in a call to
 *                  vas_gss_spnego_initiate(). In PHP, these tokens are strings.
 *
 * @param deleg_cred [out] If the initiation is for delegated credentials,
 *                   this parameter will be set to hold the delegation
 *                   credentials. Pass NULL if delegated creds are not desired.
 *
 * @return GSS status code as documented in 5.19 of RFC 2744.
 **/
function vas_gss_spnego_accept( $ctx,
                                $id,
                                &$auth,
                                &$gssctx,
                                &$flags,
                                $encoding,
                                $in_token,
                                &$out_token,
                                &$deleg_cred );


/** Obtain the subkey associated with an initiator or acceptor gss_ctx_id_t.
 *
 * @param ctx         A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param gssctx      A ::gss_ctx_id_t returned by a completed call to either
 *                    gss_accept_sec_context(), gss_init_sec_context(),
 *                    vas_gss_spnego_initiate(), or vas_gss_spnego_accept()
 *
 * @param key         Returns the keyblock.
 *
 * @return GSS_S_COMPLETE or GSS_KRB5_S_KG_NO_SUBKEY
 **/
function vas_gss_krb5_get_subkey( $ctx, $gssctx, &$key );


/********************* GSS-API Data Types and Defines **********************/

/** Value for an empty gss_OID type. */
#define GSS_C_NO_OID        ((gss_OID) 0 )

/** For GSSAPI v.1 comapatibility */
#define GSS_C_NULL_OID      GSS_C_NO_OID

/** Value for an empty gss_OID_set type. */
#define GSS_C_NO_OID_SET    ((gss_OID_set) 0)

/** For GSSAPI v.1 compatibility. */
#define GSS_C_NULL_OID_SET  GSS_C_NO_OID_SET


/** Value for an empty gss_cred_id_t type. */
#define GSS_C_NO_CREDENTIAL     ((gss_cred_id_t) 0)

/** Value for an empty gss_ctx_id_t type. */
#define GSS_C_NO_CONTEXT        ((gss_ctx_id_t) 0)

/** Value for an empty gss_name_t type. */
#define GSS_C_NO_NAME   ((gss_name_t) 0)

/** Value for an empty gss_channel_bindings_t type. */
#define GSS_C_NO_CHANNEL_BINDINGS ((gss_channel_bindings_t) 0)


/** Constants for address family type stored in initiator_addrtype
 * and acceptor_addrtype. */
#define GSS_C_AF_UNSPEC     0
#define GSS_C_AF_LOCAL      1
#define GSS_C_AF_INET       2
#define GSS_C_AF_IMPLINK    3
#define GSS_C_AF_PUP        4
#define GSS_C_AF_CHAOS      5
#define GSS_C_AF_NS         6
#define GSS_C_AF_NBS        7
#define GSS_C_AF_ECMA       8
#define GSS_C_AF_DATAKIT    9
#define GSS_C_AF_CCITT      10
#define GSS_C_AF_SNA        11
#define GSS_C_AF_DECnet     12
#define GSS_C_AF_DLI        13
#define GSS_C_AF_LAT        14
#define GSS_C_AF_HYLINK     15
#define GSS_C_AF_APPLETALK  16
#define GSS_C_AF_BSC        17
#define GSS_C_AF_DSS        18
#define GSS_C_AF_OSI        19
#define GSS_C_AF_X25        21
#define GSS_C_AF_INET6      24
#define GSS_C_AF_NULLADDR   255


/** Flags for context level services */
#define GSS_C_DELEG_FLAG      1
#define GSS_C_MUTUAL_FLAG     2
#define GSS_C_REPLAY_FLAG     4
#define GSS_C_SEQUENCE_FLAG   8
#define GSS_C_CONF_FLAG       16
#define GSS_C_INTEG_FLAG      32
#define GSS_C_ANON_FLAG       64
#define GSS_C_PROT_READY_FLAG 128
#define GSS_C_TRANS_FLAG      256


/** Credential usage type */
enum gss_cred_usage_t
{
  /** Credential usage values. */
  GSS_C_BOTH  =   0,
  GSS_C_INITIATE = 1,
  GSS_C_ACCEPT =  2,
};

/** Status code types for gss_display_status. */
#define GSS_C_GSS_CODE  1
#define GSS_C_MECH_CODE 2


/** Define the default Quality of Protection for per-message
 * services. Note that an implementation that offers multiple
 * levels of QOP may define GSS_C_QOP_DEFAULT to be either zero
 * (as done here) to mean "default protection", or to a specific
 * explicit QOP value. However, a value of 0 should always be
 * interpreted by a GSS-API implementation as a request for the
 * default protection level.
 **/
#define GSS_C_QOP_DEFAULT 0


/** Expiration time of 2^32-1 seconds means infinite lifetime for a
 * credential or security context
 **/
#define GSS_C_INDEFINITE 0xfffffffful


/** OID's for the standard name types  */
extern gss_OID  GSS_C_NT_USER_NAME;             /** x **/
extern gss_OID  GSS_C_NT_MACHINE_UID_NAME;      /** x **/
extern gss_OID  GSS_C_NT_STRING_UID_NAME;       /** x **/
extern gss_OID  GSS_C_NT_HOSTBASED_SERVICE_X;   /** x **/
extern gss_OID  GSS_C_NT_HOSTBASED_SERVICE;     /** x **/
extern gss_OID  GSS_C_NT_ANONYMOUS;             /** x **/
extern gss_OID  GSS_C_NT_EXPORT_NAME;           /** x **/
extern gss_OID GSS_SPNEGO_MECHANISM;            /** x **/

/*********************** GSS-API Error Codes *******************************/

/** Offset definitions for parsing status code macros */
#define GSS_C_CALLING_ERROR_OFFSET      24
#define GSS_C_ROUTINE_ERROR_OFFSET      16
#define GSS_C_SUPPLEMENTARY_OFFSET      0
#define GSS_C_CALLING_ERROR_MASK        ((OM_uint32) 0377ul)
#define GSS_C_ROUTINE_ERROR_MASK        ((OM_uint32) 0377ul)
#define GSS_C_SUPPLEMENTARY_MASK        ((OM_uint32) 0177777ul)

/** Macros for evaluating status codes */
/*
#define GSS_CALLING_ERROR(x) (x & \
                              (GSS_C_CALLING_ERROR_MASK << \
                               GSS_C_CALLING_ERROR_OFFSET))

#define GSS_ROUTINE_ERROR(x) (x & \
                              (GSS_C_ROUTINE_ERROR_MASK << \
                               GSS_C_ROUTINE_ERROR_OFFSET))

#define GSS_SUPPLEMENTARY_INFO(x) (x & \
                                   (GSS_C_SUPPLEMENTARY_MASK << \
                                    GSS_C_SUPPLEMENTARY_OFFSET))

#define GSS_ERROR(x) (x & \
                      ((GSS_C_CALLING_ERROR_MASK << \
                        GSS_C_CALLING_ERROR_OFFSET) | \
                       (GSS_C_ROUTINE_ERROR_MASK << \
                        GSS_C_ROUTINE_ERROR_OFFSET)))
*/
/************************* Calling Errors **********************************/

/** A required input parameter could not be read. */
#define GSS_S_CALL_INACCESSIBLE_READ  (1ul << GSS_C_CALLING_ERROR_OFFSET)

/** A require output parameter could not be written. */
#define GSS_S_CALL_INACCESSIBLE_WRITE (2ul << GSS_C_CALLING_ERROR_OFFSET)

/** A parameter was malformed. */
#define GSS_S_CALL_BAD_STRUCTURE      (3ul << GSS_C_CALLING_ERROR_OFFSET)

/************************* Routine Errors **********************************/

/** An unsupported mechanism was requested. */
#define GSS_S_BAD_MECH (1ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** An invalid name was supplied. */
#define GSS_S_BAD_NAME (2ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** A supplied name was of an unsupported type. */
#define GSS_S_BAD_NAMETYPE (3ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** Incorrect channel bindings were supplied. */
#define GSS_S_BAD_BINDINGS (4ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** An invalid status code was supplied. */
#define GSS_S_BAD_STATUS (5ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** A token had an invalid MIC. */
#define GSS_S_BAD_MIC (6ul << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_SIG GSS_S_BAD_MIC

/** No credentials were supplied, or were unavailable or inaccessible. */
#define GSS_S_NO_CRED (7ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** No context has been established. */
#define GSS_S_NO_CONTEXT (8ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** A token was invalid. */
#define GSS_S_DEFECTIVE_TOKEN (9ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** A credential was invalid. */
#define GSS_S_DEFECTIVE_CREDENTIAL (10ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** The referenced credentials have expired. */
#define GSS_S_CREDENTIALS_EXPIRED (11ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** The context has expired. */
#define GSS_S_CONTEXT_EXPIRED (12ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** Miscellaneous failure (see text). */
#define GSS_S_FAILURE (13ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** The quality of protection requested couldnot be provided. */
#define GSS_S_BAD_QOP (14ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** The operation is forbidden by local security policy. */
#define GSS_S_UNAUTHORIZED (15ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** The operation or option is unavailable. */
#define GSS_S_UNAVAILABLE (16ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** The requested credential element already exists. */
#define GSS_S_DUPLICATE_ELEMENT (17ul << GSS_C_ROUTINE_ERROR_OFFSET)

/** The provided name was not a mechanism name. */
#define GSS_S_NAME_NOT_MN (18ul << GSS_C_ROUTINE_ERROR_OFFSET)


/************************* Routine Errors **********************************/

/** The routine must be called again to complete it's function. Only returned
 * by gss_init_sec_context() or gss_accept_sec_context().
 **/
#define GSS_S_CONTINUE_NEEDED (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 0))

/** The token was a duplicate of an earlier token. */
#define GSS_S_DUPLICATE_TOKEN (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 1))

/** The token's validity period has expired. */
#define GSS_S_OLD_TOKEN (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 2))

/** A later token has already been processed. */
#define GSS_S_UNSEQ_TOKEN (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 3))

/** An expected per-message token was not recieved. */
#define GSS_S_GAP_TOKEN (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 4))


/** No errors at all... */
#define GSS_S_COMPLETE 0




/******************* Credential Management Routines ************************/

/** Assume a global identity.
 * Obtain a GSS-API credential handle for pre-existing credentials
 *
 * @param minor_status
 * @param desired_name
 * @param time_req
 * @param desired_mechs
 * @param cred_usage
 * @param output_cred_handle
 * @param actual_mechs
 * @param time_rec
 *
 * @return
 **/
OM_uint32 gss_acquire_cred( OM_uint32* minor_status,
                            const gss_name_t desired_name,
                            OM_uint32 time_req,
                            const gss_OID_set desired_mechs,
                            gss_cred_usage_t cred_usage,
                            gss_cred_id_t* output_cred_handle,
                            gss_OID_set* actual_mechs,
                            OM_uint32* time_rec );


/** Construct credentials incrementally.
 *
 **/
OM_uint32 gss_add_cred( OM_uint32* minor_status,
                        const gss_cred_id_t input_cred_handle,
                        const gss_name_t desired_name,
                        const gss_OID desired_mech,
                        gss_cred_usage_t cred_usage,
                        OM_uint32 initiator_time_req,
                        OM_uint32 acceptor_time_req,
                        gss_cred_id_t* output_cred_handle,
                        gss_OID_set* actual_mechs,
                        OM_uint32* initiator_time_rec,
                        OM_uint32* acceptor_time_rec );


/** Obtain information about a credential.
 *
 **/
OM_uint32 gss_inquire_cred( OM_uint32* minor_status,
                            const gss_cred_id_t cred_handle,
                            gss_name_t* name,
                            OM_uint32* lifetime,
                            gss_cred_usage_t* cred_usage,
                            gss_OID_set* mechanisms );


/** Obtain per-mechanism information about a credential.
 *
 **/
OM_uint32 gss_inquire_cred_by_mech( OM_uint32* minor_status,
                                    const gss_cred_id_t cred_handle,
                                    const gss_OID mech_type,
                                    gss_name_t* name,
                                    OM_uint32* initiator_lifetime,
                                    OM_uint32* acceptor_lifetime,
                                    gss_cred_usage_t* cred_usage );


/*********************** Context Level Routines ****************************/

/** Initiate a security context a peer application.
 *
 **/
OM_uint32 gss_init_sec_context( OM_uint32* minor_status,
                                const gss_cred_id_t initiator_cred_handle,
                                gss_ctx_id_t* context_handle,
                                const gss_name_t target_name,
                                const gss_OID mech_type,
                                OM_uint32 req_flags,
                                OM_uint32 time_req,
                                const gss_channel_bindings_t input_chan_bindings,
                                const gss_buffer_t input_token,
                                gss_OID* actual_mech_type,
                                gss_buffer_t output_token,
                                OM_uint32* ret_flags,
                                OM_uint32* time_rec );


/** Accept a security token initiated by a peer application.
 *
 **/
OM_uint32 gss_accept_sec_context( OM_uint32* minor_status,
                                  gss_ctx_id_t* context_handle,
                                  const gss_cred_id_t acceptor_cred_handle,
                                  const gss_buffer_t input_token_buffer,
                                  const gss_channel_bindings_t input_chan_bindings,
                                  gss_name_t* src_name,
                                  gss_OID* mech_type,
                                  gss_buffer_t output_token,
                                  OM_uint32* ret_flags,
                                  OM_uint32* time_rec,
                                  gss_cred_id_t* delegated_cred_handle );


/** Discard a security context.
 *
 **/
OM_uint32 gss_delete_sec_context( OM_uint32* minor_status,
                                  gss_ctx_id_t* context_handle,
                                  gss_buffer_t output_token );


/** Process a token on a security context from a peer application.
 *
 **/
OM_uint32 gss_process_context_token( OM_uint32* minor_status,
                                     const gss_ctx_id_t context_handle,
                                     const gss_buffer_t token_buffer );


/** Determine for how long a context will remain valid.
 *
 **/
OM_uint32 gss_context_time( OM_uint32* minor_status,
                            const gss_ctx_id_t context_handle,
                            OM_uint32* time_rec );


/** Obtain information about a security context.
 *
 **/
OM_uint32 gss_inquire_context( OM_uint32* minor_status,
                               const gss_ctx_id_t context_handle,
                               gss_name_t* src_name,
                               gss_name_t* targ_name,
                               OM_uint32* lifetime_rec,
                               gss_OID* mech_type,
                               OM_uint32* ctx_flags,
                               int* locally_initiated,
                               int* open_context );


/** Determine token-size limit for gss_wrap on a context.
 *
 **/
OM_uint32 gss_wrap_size_limit( OM_uint32* minor_status,
                               const gss_ctx_id_t context_handle,
                               int conf_req_flag,
                               gss_qop_t qop_req,
                               OM_uint32 req_output_size,
                               OM_uint32* max_input_size );


/** Transfer a security context to another process.
 *
 **/
OM_uint32 gss_export_sec_context( OM_uint32* minor_status,
                                  gss_ctx_id_t* context_handle,
                                  gss_buffer_t interprocess_token );


/** Import a transferred context.
 *
 **/
OM_uint32 gss_import_sec_context( OM_uint32* minor_status,
                                  const gss_buffer_t interprocess_token,
                                  gss_ctx_id_t* context_handle );



/*********************** Per-Message Routines ****************************/

/** Calculate a cryptographic message integrity code (MIC) for a message.
 * Provides an integrity service.
 *
 **/
OM_uint32 gss_get_mic( OM_uint32* minor_status,
                       const gss_ctx_id_t context_handle,
                       gss_qop_t qop_req,
                       const gss_buffer_t message_buffer,
                       gss_buffer_t message_token );


/** Check a MIC against a message.
 * Verifies the integrity of a recieved message.
 *
 **/
OM_uint32 gss_verify_mic( OM_uint32* minor_status,
                          const gss_ctx_id_t context_handle,
                          const gss_buffer_t message_buffer,
                          const gss_buffer_t token_buffer,
                          gss_qop_t* qop_state );


/** Attach a MIC to a message and optionally encrypt the message content.
 * Provides a confidentiality service.
 *
 **/
OM_uint32 gss_wrap( OM_uint32* minor_status,
                    const gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    const gss_buffer_t input_message_buffer,
                    int* conf_state,
                    gss_buffer_t output_message_buffer );


/** Verify a message with attached MIC, and decrypt the message content
 * if necessary.
 *
 **/
OM_uint32 gss_unwrap( OM_uint32* minor_status,
                      const gss_ctx_id_t context_handle,
                      const gss_buffer_t input_message_buffer,
                      gss_buffer_t output_message_buffer,
                      int* conf_state,
                      gss_qop_t* qop_state );


/** Obsolete variants from GSS-API v1.
 *
 **/
OM_uint32 gss_sign( OM_uint32* minor_status,
                    gss_ctx_id_t context_handle,
                    int qop_req,
                    gss_buffer_t message_buffer,
                    gss_buffer_t message_token );

OM_uint32 gss_verify( OM_uint32* minor_status,
                      gss_ctx_id_t context_handle,
                      gss_buffer_t message_buffer,
                      gss_buffer_t token_buffer,
                      int* qop_state );

OM_uint32 gss_seal( OM_uint32* minor_status,
                    gss_ctx_id_t context_handle,
                    int conf_req_flag,
                    int qop_req,
                    gss_buffer_t input_message_buffer,
                    int* conf_state,
                    gss_buffer_t output_message_buffer );

OM_uint32 gss_unseal( OM_uint32* minor_status,
                      gss_ctx_id_t context_handle,
                      gss_buffer_t input_message_buffer,
                      gss_buffer_t output_message_buffer,
                      int* conf_state,
                      int* qop_state );



/********************* Name Manipulation Routines **************************/

/** Convert a contiguous string name to an internal form.
 *
 **/
OM_uint32 gss_import_name( OM_uint32* minor_state,
                           const gss_buffer_t input_name_buffer,
                           const gss_OID input_name_type,
                           gss_name_t* output_name );


/** Convert internal form name to text.
 *
 **/
OM_uint32 gss_display_name( OM_uint32* minor_status,
                            const gss_name_t input_name,
                            gss_buffer_t output_name_buffer,
                            gss_OID* output_name_type );


/** Compare two internal form names.
 *
 **/
OM_uint32 gss_compare_name( OM_uint32* minor_status,
                            const gss_name_t name1,
                            const gss_name_t name2,
                            int* name_equal );


/** Discard an internal form name.
 *
 **/
OM_uint32 gss_release_name( OM_uint32* minor_status,
                            gss_name_t* input_name );


/** List the name types supported by the specified mechanism.
 *
 **/
OM_uint32 gss_inquire_names_for_mech( OM_uint32* minor_status,
                                      const gss_OID mechanism,
                                      gss_OID_set* name_types );


/** List the mechanisms that support the specified name type.
 *
 **/
OM_uint32 gss_inquire_mechs_for_name( OM_uint32* minor_status,
                                      const gss_name_t input_name,
                                      gss_OID_set* mech_types );


/** Convert an internal name to an MN.
 *
 **/
OM_uint32 gss_canonicalize_name( OM_uint32* minor_status,
                                 const gss_name_t input_name,
                                 const gss_OID mech_type,
                                 gss_name_t* output_name );


/** Convert an MN to export form.
 *
 **/
OM_uint32 gss_export_name( OM_uint32* minor_status,
                           const gss_name_t input_name,
                           gss_buffer_t exported_name );


/** Create a copy of an internal name.
 *
 **/
OM_uint32 gss_duplicate_name( OM_uint32* minor_status,
                              const gss_name_t src_name,
                              gss_name_t* dest_name );


/*********************** Miscellaneous Routines ****************************/

/** Convert a GSS-API status code to text.
 *
 **/
OM_uint32 gss_display_status( OM_uint32* minor_status,
                              OM_uint32 status_value,
                              int status_type,
                              const gss_OID mech_type,
                              OM_uint32* message_context,
                              gss_buffer_t status_string );


/** Create an OID set containing no object identifiers.
 *
 **/
OM_uint32 gss_create_empty_oid_set( OM_uint32* minor_status,
                                    gss_OID_set* oid_set );


/** Add an object identifier to an OID set.
 *
 **/
OM_uint32 gss_add_oid_set_member( OM_uint32* minor_status,
                                  const gss_OID member_oid,
                                  gss_OID_set* oid_set );


/** Determine whether on object identifier is a member of an OID set.
 *
 **/
OM_uint32 gss_test_oid_set_member( OM_uint32* minor_status,
                                   const gss_OID member,
                                   const gss_OID_set set,
                                   int* present );


/** Discard a set of object identifiers.
 *
 **/
OM_uint32 gss_release_oid_set( OM_uint32* minor_status,
                               gss_OID_set* set );


/** Discard a buffer.
 *
 **/
OM_uint32 gss_release_buffer( OM_uint32* minor_status,
                              gss_buffer_t buffer );


/** Determine available underlying authentication mechanisms.
 *
 **/
OM_uint32 gss_indicate_mechs( OM_uint32* minor_status,
                              gss_OID_set* mech_set );


/** Obtain the Krb5 context used by a VAS context.
 * Used to obtain a pointer to the krb5_context that is used by a ::vas_ctx_t
 * The returned krb5ctx pointer is a pointer that could be orphaned by
 * subsequent calls to other VAS functions. To avoid possible problems
 * with orphaned pointers, vas_krb5_get_context() should be called
 * each time the krb5_context is needed.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @return krb5ctx  Will be set to point to the internal krb5ctx context.
 *
 * On return vas_err() is set as follows: VAS_ERR_SUCCESS on success or one of
 * the following error codes:
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t functions
 *                                    to obtain Kerberos error details
 **/
function vas_krb5_get_context( $ctx );


/** Obtain the Kerberos principal associated with a VAS identity.
 * Used to obtain a pointer to the krb5_principal that is associated with
 * a ::vas_id_t. The returned krb5princ pointer is a pointer that could be
 * orphaned by subsequent calls to other VAS functions. To avoid possible
 * problems with orphaned pointers, vas_krb5_get_principal() should
 * be called each time the krb5_principal is needed.
 *
 * @param ctx        A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id         The ::vas_id_t for which you need the krb5_principal.
 *
 * @return krb5princ Will be set to point to the krb5_principal of the id.
 *
 * On return vas_err() is set as follows: VAS_ERR_SUCCESS on success or one of
 * the following error codes:
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t functions
 *                                    to obtain Kerberos error details
 **/
function vas_krb5_get_principal( &ctx, &id );


/** Obtain the krb5_ccache that is associated with a ::vas_id_t.
 * The returned krb5cc pointer is a pointer that could be
 * orphaned by subsequent calls to other VAS functions (like
 * vas_id_free()). To avoid possible problems with orphaned
 * krb5 credential cache pointers, vas_krb5_get_ccache() should
 * be called each time the krb5_ccache is needed.
 *
 * @param ctx       A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id        The ::vas_id_t that you need the krb5cc for.
 *
 * @return krb5cc   The krb5 credential cache associated with the specified
 *                  ::vas_id_t.
 *
 * On return vas_err() is set as follows: VAS_ERR_SUCCESS on success or one of
 * the following error codes:
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t functions
 *                                    to obtain Kerberos error details
 **/
function vas_krb5_get_ccache( $ctx, $id );


/** Used to obtain, cache, and validate krb5 credentials.
 *
 * @param ctx         A ::vas_ctx_t obtained from vas_ctx_alloc().
 *
 * @param id          The ::vas_id_t (client) that will be used to obtain creds.
 *
 * @param addtocache  If set to 1, the requested ticket will be added to the id's
 *                    associated ticket cache.
 *
 * @param target      The principal name of the ticket that will be requested.
 *
 * @return creds      The krb5_creds.
 *
 * On return vas_err() is set as follows: Zero on success or non-zero errno on
 * error. The following
 *          return values are defined:
 *          - VAS_ERR_SUCCESS       - Credentials ARE already established.
 *          - VAS_ERR_KRB5          - Kerberos error
 *          - VAS_ERR_CRED_NEEDED   - Credentials are NOT established
 *          - VAS_ERR_CRED_EXPIRED  - Credentials are expired.
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 **/
function vas_krb5_get_credentials( $ctx,
                                   $id,
                                   $target,
                                   $addtocache );


/** Validate Kerberos credentials and obtain authentication data
 *
 * @param ctx     vas_ctx_t obtained from vas_ctx_alloc()
 *
 * @param creds   The creds to be validated
 *
 * @param keytab  The service keytab file to use to validate creds. Pass
 *                in NULL to use the default service keytab
 *
 * @return auth   Authentication data that can be used in calls to to
 *                vas_auth_xxx() functions.
 *
 * On return vas_err() is set as follows:
 *          Zero on success or non-zero error. The following return values
 *          are defined
 *          - VAS_ERR_SUCCESS       - Success
 *          - VAS_ERR_KRB5          - Kerberos error. Use vas_err_t functions
 *                                    to obtain Kerberos error details
 *          - VAS_ERR_INVALID_PARAM - An invalid parameter was passed
 *          - VAS_ERR_NO_MEMORY     - Memory allocation failed
 *          - VAS_ERR_CRED_NEEDED   - Credentials not established for client
 *                                    or server ::vas_id_t
 *          - VAS_ERR_CRED_EXPIRED  - Client credentials are expired.
 **/
function vas_krb5_validate_credentials( $ctx, $creds, $keytab );

?>
