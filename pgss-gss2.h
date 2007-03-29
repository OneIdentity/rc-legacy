
struct pgss_ctx_id {
            int x;
};

/*
 * Wrapper around a collection of mechanism credentials.
 */
struct pgss_cred_id {
    OM_uint32 length;		/* number of elements */
    struct {
	gss_OID_desc mech;	/* provider (dup_oid) */
	D_gss_cred_id_t cred;	/* gss_cred_id_t */
    } element[1];
};

/*
 * Wrapper around a mechanism or non-mechanism name.
 */
struct pgss_name {
    struct pgss_dispatch *owner; /* Mechanism that owns this name */
    D_gss_name_t     name;	/* valid when owner != NULL */
    gss_buffer_desc  data;	/* valid when owner == NULL */
    gss_OID	     type;	/* type (dup_oid) */
};

/*
 * Internal OIDs provided by the GSSv2 wrapper.
 * I trust that these are not controversial.
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

