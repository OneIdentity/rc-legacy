
struct pgss_ctx_id {
            int x;
};

struct pgss_cred_id {
            int x;
};

struct pgss_name {
    struct pgss_dispatch *owner;
    gss_name_t	     name;	/* valid when owner != NULL */
    gss_buffer_desc  data;	/* valid when owner == NULL */
    gss_OID	     type;
};

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

extern struct pgss_dispatch _pgss_unavailable;

