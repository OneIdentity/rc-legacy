
OM_uint32   pgss_ctl(
    OM_uint32   *minor_return, 
    gss_OID	     mech, 
    OM_uint32    op, 
    gss_buffer_t data);

#define PGSS_CTL_MECH_INIT		0x00000000
#define PGSS_CTL_GET_CONFIG_ERRORS	0x00000001
#define PGSS_CTL_SET_CONFIG_FILE	0x00000002
#define PGSS_CTL_SET_EXEC_NAME		0x00000003
