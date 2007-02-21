/*
 * GSSAPI library dispatch structure.
 */

typedef OM_uint32 (*gss_acquire_cred_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* desired_name */
	       OM_uint32,              /* time_req */
	       const gss_OID_set,      /* desired_mechs */
	       gss_cred_usage_t,       /* cred_usage */
	       gss_cred_id_t *,        /* output_cred_handle */
	       gss_OID_set *,          /* actual_mechs */
	       OM_uint32 *             /* time_rec */
	      );

typedef OM_uint32 (*gss_release_cred_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_cred_id_t *         /* cred_handle */
	      );

typedef OM_uint32 (*gss_init_sec_context_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* initiator_cred_handle */
	       gss_ctx_id_t *,         /* context_handle */
	       const gss_name_t,       /* target_name */
	       const gss_OID,          /* mech_type */
	       OM_uint32,              /* req_flags */
	       OM_uint32,              /* time_req */
	       const gss_channel_bindings_t,
				       /* input_chan_bindings */
	       const gss_buffer_t,     /* input_token */
	       gss_OID *,              /* actual_mech_type */
	       gss_buffer_t,           /* output_token */
	       OM_uint32 *,            /* ret_flags */
	       OM_uint32 *             /* time_rec */
	      );

typedef OM_uint32 (*gss_accept_sec_context_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_ctx_id_t *,         /* context_handle */
	       const gss_cred_id_t,    /* acceptor_cred_handle */
	       const gss_buffer_t,     /* input_token_buffer */
	       const gss_channel_bindings_t,
				       /* input_chan_bindings */
	       gss_name_t *,           /* src_name */
	       gss_OID *,              /* mech_type */
	       gss_buffer_t,           /* output_token */
	       OM_uint32 *,            /* ret_flags */
	       OM_uint32 *,            /* time_rec */
	       gss_cred_id_t *         /* delegated_cred_handle */
	      );

typedef OM_uint32 (*gss_process_context_token_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       const gss_buffer_t      /* token_buffer */
	      );

typedef OM_uint32 (*gss_delete_sec_context_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_ctx_id_t *,         /* context_handle */
	       gss_buffer_t            /* output_token */
	      );

typedef OM_uint32 (*gss_context_time_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       OM_uint32 *             /* time_rec */
	      );

typedef OM_uint32 (*gss_get_mic_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       gss_qop_t,              /* qop_req */
	       const gss_buffer_t,     /* message_buffer */
	       gss_buffer_t            /* message_token */
	      );

typedef OM_uint32 (*gss_verify_mic_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       const gss_buffer_t,     /* message_buffer */
	       const gss_buffer_t,     /* token_buffer */
	       gss_qop_t *             /* qop_state */
	      );

typedef OM_uint32 (*gss_wrap_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       int,                    /* conf_req_flag */
	       gss_qop_t,              /* qop_req */
	       const gss_buffer_t,     /* input_message_buffer */
	       int *,                  /* conf_state */
	       gss_buffer_t            /* output_message_buffer */
	      );

typedef OM_uint32 (*gss_unwrap_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       const gss_buffer_t,     /* input_message_buffer */
	       gss_buffer_t,           /* output_message_buffer */
	       int *,                  /* conf_state */
	       gss_qop_t *             /* qop_state */
	      );



typedef OM_uint32 (*gss_display_status_t)
	      (OM_uint32 *,            /* minor_status */
	       OM_uint32,              /* status_value */
	       int,                    /* status_type */
	       const gss_OID,          /* mech_type */
	       OM_uint32,              /* message_context */
	       gss_buffer_t            /* status_string */
	      );

typedef OM_uint32 (*gss_indicate_mechs_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_OID_set *           /* mech_set */
	      );

typedef OM_uint32 (*gss_compare_name_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* name1 */
	       const gss_name_t,       /* name2 */
	       int *                   /* name_equal */
	      );

typedef OM_uint32 (*gss_display_name_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       gss_buffer_t,           /* output_name_buffer */
	       gss_OID *               /* output_name_type */
	      );

typedef OM_uint32 (*gss_import_name_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_buffer_t,     /* input_name_buffer */
	       const gss_OID,          /* input_name_type */
	       gss_name_t *            /* output_name */
	      );

typedef OM_uint32 (*gss_export_name_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       gss_buffer_t            /* exported_name */
	      );

typedef OM_uint32 (*gss_release_name_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_name_t *            /* input_name */
	      );

typedef OM_uint32 (*gss_release_buffer_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_buffer_t            /* buffer */
	      );

typedef OM_uint32 (*gss_release_oid_set_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_OID_set *           /* set */
	      );

typedef OM_uint32 (*gss_inquire_cred_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* cred_handle */
	       gss_name_t *,           /* name */
	       OM_uint32 *,            /* lifetime */
	       gss_cred_usage_t *,     /* cred_usage */
	       gss_OID_set *           /* mechanisms */
	      );

typedef OM_uint32 (*gss_inquire_context_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       gss_name_t *,           /* src_name */
	       gss_name_t *,           /* targ_name */
	       OM_uint32 *,            /* lifetime_rec */
	       gss_OID *,              /* mech_type */
	       OM_uint32 *,            /* ctx_flags */
	       int *,                  /* locally_initiated */
	       int *                   /* open */
	      );


typedef OM_uint32 (*gss_wrap_size_limit_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_ctx_id_t,     /* context_handle */
	       int,                    /* conf_req_flag */
	       gss_qop_t,              /* qop_req */
	       OM_uint32,              /* req_output_size */
	       OM_uint32 *             /* max_input_size */
	      );

typedef OM_uint32 (*gss_add_cred_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* input_cred_handle */
	       const gss_name_t,       /* desired_name */
	       const gss_OID,          /* desired_mech */
	       gss_cred_usage_t,       /* cred_usage */
	       OM_uint32,              /* initiator_time_req */
	       OM_uint32 *,            /* acceptor_time_req */
	       gss_cred_id_t *,        /* output_cred_handle */
	       gss_OID_set *,          /* actual_mechs */
	       OM_uint32 *,            /* initiator_time_rec */
	       OM_uint32 *             /* acceptor_time_rec */
	      );

typedef OM_uint32 (*gss_inquire_cred_by_mech_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_cred_id_t,    /* cred_handle */
	       const gss_OID,          /* mech_type */
	       gss_name_t *,           /* name */
	       OM_uint32 *,            /* initiator_lifetime */
	       OM_uint32 *,            /* acceptor_lifetime */
	       gss_cred_usage_t *      /* cred_usage */
	      );

typedef OM_uint32 (*gss_export_sec_context_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_ctx_id_t,           /* context_handle */
	       gss_buffer_t            /* interprocess_token */
	      );

typedef OM_uint32 (*gss_import_sec_context_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_buffer_t,     /* interprocess_token */
	       gss_ctx_id_t *          /* context_handle */
	      );


typedef OM_uint32 (*gss_create_empty_oid_set_t)
	      (OM_uint32 *,            /* minor_status */
	       gss_OID_set *           /* oid_set */
	      );

typedef OM_uint32 (*gss_add_oid_set_member_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_OID,          /* member_oid */
	       gss_OID_set *           /* oid_set */
	      );

typedef OM_uint32 (*gss_test_oid_set_member_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_OID,          /* member */
	       const gss_OID_set,      /* set */
	       int *                   /* present */
	      );

typedef OM_uint32 (*gss_inquire_names_for_mech_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_OID,          /* mechanism */
	       gss_OID_set *           /* name_types */
	      );

typedef OM_uint32 (*gss_inquire_mechs_for_name_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       gss_OID_set *           /* mech_types */
	      );

typedef OM_uint32 (*gss_canonicalize_name_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* input_name */
	       const gss_OID,          /* mech_type */
	       gss_name_t *            /* output_name */
	      );

typedef OM_uint32 (*gss_duplicate_name_t)
	      (OM_uint32 *,            /* minor_status */
	       const gss_name_t,       /* src_name */
	       gss_name_t *            /* dest_name */
	      );

typedef OM_uint32 (*gss_sign_t)
	      (OM_uint32 *,       /* minor_status */
	       gss_ctx_id_t,      /* context_handle */
	       int,               /* qop_req */
	       gss_buffer_t,      /* message_buffer */
	       gss_buffer_t       /* message_token */
	      );


typedef OM_uint32 (*gss_verify_t)
	      (OM_uint32 *,       /* minor_status */
	       gss_ctx_id_t,      /* context_handle */
	       gss_buffer_t,      /* message_buffer */
	       gss_buffer_t,      /* token_buffer */
	       int *              /* qop_state */
	      );

typedef OM_uint32 (*gss_seal_t)
	      (OM_uint32 *,       /* minor_status */
	       gss_ctx_id_t,      /* context_handle */
	       int,               /* conf_req_flag */
	       int,               /* qop_req */
	       gss_buffer_t,      /* input_message_buffer */
	       int,               /* conf_state */
	       gss_buffer_t       /* output_message_buffer */
	      );


typedef OM_uint32 (*gss_unseal_t)
	      (OM_uint32 *,       /* minor_status */
	       gss_ctx_id_t,      /* context_handle */
	       gss_buffer_t,      /* input_message_buffer */
	       gss_buffer_t,      /* output_message_buffer */
	       int,               /* conf_state */
	       int *              /* qop_state */
	      );

typedef OM_uint32 (*pgss_ctl_t)
	      (OM_uint32 *,       /* minor_status */
	       gss_OID,           /* mechanism */
	       OM_uint32,         /* operation */
	       gss_buffer_t       /* data_buffer */
	      );


struct pgss_dispatch {
    gss_acquire_cred_t           gss_acquire_cred;
    gss_release_cred_t           gss_release_cred;
    gss_init_sec_context_t       gss_init_sec_context;
    gss_accept_sec_context_t     gss_accept_sec_context;
    gss_process_context_token_t  gss_process_context_token;
    gss_delete_sec_context_t     gss_delete_sec_context;
    gss_context_time_t           gss_context_time;
    gss_get_mic_t                gss_get_mic;
    gss_verify_mic_t             gss_verify_mic;
    gss_wrap_t                   gss_wrap;
    gss_unwrap_t                 gss_unwrap;
    gss_display_status_t         gss_display_status;
    gss_indicate_mechs_t         gss_indicate_mechs;
    gss_compare_name_t           gss_compare_name;
    gss_display_name_t           gss_display_name;
    gss_import_name_t            gss_import_name;
    gss_export_name_t            gss_export_name;
    gss_release_name_t           gss_release_name;
    gss_release_buffer_t         gss_release_buffer;
    gss_release_oid_set_t        gss_release_oid_set;
    gss_inquire_cred_t           gss_inquire_cred;
    gss_inquire_context_t        gss_inquire_context;
    gss_wrap_size_limit_t        gss_wrap_size_limit;
    gss_add_cred_t               gss_add_cred;
    gss_inquire_cred_by_mech_t   gss_inquire_cred_by_mech;
    gss_export_sec_context_t     gss_export_sec_context;
    gss_import_sec_context_t     gss_import_sec_context;
    gss_create_empty_oid_set_t   gss_create_empty_oid_set;
    gss_add_oid_set_member_t     gss_add_oid_set_member;
    gss_test_oid_set_member_t    gss_test_oid_set_member;
    gss_inquire_names_for_mech_t gss_inquire_names_for_mech;
    gss_inquire_mechs_for_name_t gss_inquire_mechs_for_name;
    gss_canonicalize_name_t      gss_canonicalize_name;
    gss_duplicate_name_t         gss_duplicate_name;
    gss_sign_t                   gss_sign;
    gss_verify_t                 gss_verify;
    gss_seal_t                   gss_seal;
    gss_unseal_t                 gss_unseal;
    pgss_ctl_t			 pgss_ctl;
};

struct config;
struct pgss_dispatch *_pgss_dl_provider(struct config *config);

