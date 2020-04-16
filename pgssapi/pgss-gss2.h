
/*
 * NOTES:
 *   A 'provider' is a GSSAPI implementation that provides
 *   access to one or more GSS mechanisms. Providers are selected
 *   by a mechanism OID. More than one mechanism OID may correspond to
 *   the same provider.
 */

/*
 * Wrapper around a single provider's context.
 */
struct pgss_ctx_id {
    struct pgss_dispatch *owner;
    D_gss_ctx_id_t ctx;
};

/*
 * Wrapper around a collection of provider's credentials.
 */
struct pgss_cred_id {
    OM_uint32 count;		/* number of elements */
    struct pgss_cred_element {
	struct pgss_dispatch *owner;
	D_gss_cred_id_t cred;	/* gss_cred_id_t */
	gss_OID_set mechs;	/* mechs added */
    } element[1];
};

/*
 * Wrapper around a GSS name.
 *
 * GSS names are either 
 *    * 'internal names' (IN) or 
 *    * 'single-mechanism internal names' (MN). 
 *
 * We import IN names 'on-demand' by passing the name type provided
 * to the provider in use at the time.
 *
 * For INs, a pgss_name is imported 'on-demand' when supplied to
 * provider functions.
 * PGSS performs 'late' internalisation.
 *
 *
 * MNs are only ever created by:
 *    gss_canonicalize_name()
 *    gss_accept_sec_context()
 *    gss_import_name() (only when nametype is EXPORT_NAME)
 *    gss_duplicate_name()
 *    gss_inquire_cred_by_mech()
 *    gss_inquire_context()
 * INs are created by
 *    gss_import_name() (when nametype != EXPORT_NAME)
 *    gss_inquire_cred()
 *    gss_duplicate_name()
 * 
 * Note that gss_inquire_cred() will result in INs of no type.
 * This means the data field is invalid, and the IN cannot be
 * 'demand-imported' when passed to a different mechanism.
 */
struct pgss_name {
    gss_buffer_desc data;	/* valid only if imported */
    gss_OID type;		/* valid only if imported */
    OM_uint32 count;
    struct pgss_name_element {
	struct pgss_dispatch *owner;
	D_gss_name_t name;
    } *element;
    OM_uint32 is_mn : 1,	/* true if MN; false if IN */
	      is_imported : 1;
};

/*
 * Internal OIDs provided by the GSSv2 wrapper.
 */
extern gss_OID_desc
    _pgss_NT_USER_NAME,            /* 1.2.840.113554.1.2.1.1 */
    _pgss_NT_MACHINE_UID_NAME,     /* 1.2.840.113554.1.2.1.2 */
    _pgss_NT_STRING_UID_NAME,      /* 1.2.840.113554.1.2.1.3 */
    _pgss_NT_HOSTBASED_SERVICE_X,  /* 1.3.6.1.5.6.2 */
    _pgss_NT_HOSTBASED_SERVICE,    /* 1.2.840.113554.1.2.1.4 */
    _pgss_NT_ANONYMOUS,            /* 1.3.6.1.5.6.3 */
    _pgss_NT_EXPORT_NAME,          /* 1.3.6.1.5.6.4 */
    _pgss_KRB5_MECHANISM,          /* 1.2.840.113554.1.2.2 */
    _pgss_KRB5_NT_PRINCIPAL_NAME;  /* 1.2.840.113554.1.2.2.1 */

/*
 * A dispatcher that always returns GSS_C_UNAVAILABLE errors.
 * This can be used to redirect unimplemented functions in other dispatchers,
 * or is selecetd in a configuration when someone uses type=unavailable.
 */
extern struct pgss_dispatch _pgss_unavailable;

