/**
 ** PHP Extension for Quest Software, Inc. Vintela Authentication Services.
 **
 ** Copyright (c) 2006, 2007 Quest Software, Inc.
 **
 **/
#ifndef PHP_VAS_H
#define PHP_VAS_H

#include "vas.h"
#include "vas_gss.h"
#include "vas_ldap.h"

/*
 * Coerce the functions, their names and definitions into what PHP's Zend core
 * needs. These are some VAS macros atop Zend's own.
 */
#define WRAP( name )          _wrap_##name
#if defined( __PHP_4__ )
# define ZEND_VAS( name )     ZEND_NAMED_FE( name, WRAP(name), NULL )
# define ZEND_VAS2( name, i ) ZEND_NAMED_FE( name, WRAP(name), i )
# define ZEND_VAS_ARG_INFO( name )  /* (unused in PHP-4...) */

#elif defined( __PHP_5__ )
/* ZEND_NAMED_FE(zend_name, name, arg_info)	ZEND_FENTRY(zend_name, name, arg_info, 0)
	char *fname;
	void (*handler)(INTERNAL_FUNCTION_PARAMETERS);
	struct _zend_arg_info *arg_info;
	zend_uint num_args;
	zend_uint flags;
 * */
# define ZEND_VAS( name )     ZEND_NAMED_FE( name, WRAP(name), &_info##name )
# define ZEND_VAS2( name, i ) ZEND_VAS( name )
# define ZEND_VAS_ARG_INFO( name )          \
        static zend_arg_info _info##name =  \
        {                                   \
            #name,                          \
            sizeof( #name ) - 1,            \
            "", 0,                          \
            0, 0, 0, 0, 0                   \
        }

#else
# error You must define __PHP_4__ or __PHP_5__
#endif

#define ZEND_VAS_NAMED_FUNC( name ) ZEND_NAMED_FUNCTION( WRAP( name ) )


extern zend_module_entry vas_module_entry;
#define phpext_vas_ptr &vas_module_entry

#ifdef PHP_WIN32
# define PHP_VAS_API __declspec(dllexport)
#else
# define PHP_VAS_API
#endif

PHP_MINIT_FUNCTION(vas);
PHP_MSHUTDOWN_FUNCTION(vas);
PHP_RINIT_FUNCTION(vas);
PHP_RSHUTDOWN_FUNCTION(vas);
PHP_MINFO_FUNCTION(vas);

ZEND_VAS_NAMED_FUNC(new_vas_err_info_t);
ZEND_VAS_NAMED_FUNC(new_vas_val_binary_t);
ZEND_VAS_NAMED_FUNC(vas_err_internal);
ZEND_VAS_NAMED_FUNC(vas_err_minor_internal);
ZEND_VAS_NAMED_FUNC(vas_ctx_alloc);
ZEND_VAS_NAMED_FUNC(vas_ctx_set_option);
ZEND_VAS_NAMED_FUNC(vas_ctx_get_option);
ZEND_VAS_NAMED_FUNC(vas_id_alloc);
ZEND_VAS_NAMED_FUNC(vas_id_get_ccache_name);
ZEND_VAS_NAMED_FUNC(vas_id_get_keytab_name);
ZEND_VAS_NAMED_FUNC(vas_id_get_name);
ZEND_VAS_NAMED_FUNC(vas_id_get_user);
ZEND_VAS_NAMED_FUNC(vas_id_is_cred_established);
ZEND_VAS_NAMED_FUNC(vas_id_establish_cred_password);
ZEND_VAS_NAMED_FUNC(vas_id_establish_cred_keytab);
ZEND_VAS_NAMED_FUNC(vas_id_renew_cred);
ZEND_VAS_NAMED_FUNC(vas_auth);
ZEND_VAS_NAMED_FUNC(vas_auth_with_password);
ZEND_VAS_NAMED_FUNC(vas_auth_check_client_membership);
ZEND_VAS_NAMED_FUNC(vas_auth_get_client_groups);
ZEND_VAS_NAMED_FUNC(vas_attrs_alloc);
ZEND_VAS_NAMED_FUNC(vas_attrs_find);
ZEND_VAS_NAMED_FUNC(vas_attrs_find_continue);
ZEND_VAS_NAMED_FUNC(vas_attrs_set_option);
ZEND_VAS_NAMED_FUNC(vas_attrs_get_option);
ZEND_VAS_NAMED_FUNC(vas_vals_get_string);
ZEND_VAS_NAMED_FUNC(vas_vals_get_integer);
ZEND_VAS_NAMED_FUNC(vas_vals_get_binary);
ZEND_VAS_NAMED_FUNC(vas_vals_get_anames);
ZEND_VAS_NAMED_FUNC(vas_vals_get_dn);
ZEND_VAS_NAMED_FUNC(vas_name_to_principal);
ZEND_VAS_NAMED_FUNC(vas_name_to_dn);
ZEND_VAS_NAMED_FUNC(vas_info_forest_root);
ZEND_VAS_NAMED_FUNC(vas_info_joined_domain);
ZEND_VAS_NAMED_FUNC(vas_info_site);
ZEND_VAS_NAMED_FUNC(vas_info_domains);
ZEND_VAS_NAMED_FUNC(vas_info_servers);
ZEND_VAS_NAMED_FUNC(vas_prompt_for_cred_string);
ZEND_VAS_NAMED_FUNC(vas_err_get_code);
ZEND_VAS_NAMED_FUNC(vas_err_get_string);
ZEND_VAS_NAMED_FUNC(vas_err_clear);
ZEND_VAS_NAMED_FUNC(vas_err_get_info);
ZEND_VAS_NAMED_FUNC(vas_err_info_get_string);
ZEND_VAS_NAMED_FUNC(vas_err_get_cause_by_type);
ZEND_VAS_NAMED_FUNC(vas_user_init);
ZEND_VAS_NAMED_FUNC(vas_user_is_member);
ZEND_VAS_NAMED_FUNC(vas_user_get_groups);
ZEND_VAS_NAMED_FUNC(vas_user_get_attrs);
ZEND_VAS_NAMED_FUNC(vas_user_get_dn);
ZEND_VAS_NAMED_FUNC(vas_user_get_domain);
ZEND_VAS_NAMED_FUNC(vas_user_get_sam_account_name);
ZEND_VAS_NAMED_FUNC(vas_user_get_sid);
ZEND_VAS_NAMED_FUNC(vas_user_get_upn);
ZEND_VAS_NAMED_FUNC(vas_user_get_pwinfo);
ZEND_VAS_NAMED_FUNC(vas_user_get_krb5_client_name);
ZEND_VAS_NAMED_FUNC(vas_user_get_account_control);
ZEND_VAS_NAMED_FUNC(vas_user_check_access);
ZEND_VAS_NAMED_FUNC(vas_user_check_conflicts);
ZEND_VAS_NAMED_FUNC(vas_group_init);
ZEND_VAS_NAMED_FUNC(vas_group_has_member);
ZEND_VAS_NAMED_FUNC(vas_group_get_attrs);
ZEND_VAS_NAMED_FUNC(vas_group_get_dn);
ZEND_VAS_NAMED_FUNC(vas_group_get_domain);
ZEND_VAS_NAMED_FUNC(vas_group_get_sid);
ZEND_VAS_NAMED_FUNC(vas_service_init);
ZEND_VAS_NAMED_FUNC(vas_service_get_attrs);
ZEND_VAS_NAMED_FUNC(vas_service_get_dn);
ZEND_VAS_NAMED_FUNC(vas_service_get_domain);
ZEND_VAS_NAMED_FUNC(vas_service_get_krb5_client_name);
ZEND_VAS_NAMED_FUNC(vas_service_get_spns);
ZEND_VAS_NAMED_FUNC(vas_service_get_upn);
ZEND_VAS_NAMED_FUNC(vas_computer_init);
ZEND_VAS_NAMED_FUNC(vas_computer_is_member);
ZEND_VAS_NAMED_FUNC(vas_computer_get_attrs);
ZEND_VAS_NAMED_FUNC(vas_computer_get_dn);
ZEND_VAS_NAMED_FUNC(vas_computer_get_dns_hostname);
ZEND_VAS_NAMED_FUNC(vas_computer_get_domain);
ZEND_VAS_NAMED_FUNC(vas_computer_get_sid);
ZEND_VAS_NAMED_FUNC(vas_computer_get_spns);
ZEND_VAS_NAMED_FUNC(vas_computer_get_sam_account_name);
ZEND_VAS_NAMED_FUNC(vas_computer_get_upn);
ZEND_VAS_NAMED_FUNC(vas_computer_get_krb5_client_name);
ZEND_VAS_NAMED_FUNC(vas_computer_get_host_spn);
ZEND_VAS_NAMED_FUNC(vas_computer_get_account_control);
ZEND_VAS_NAMED_FUNC(vas_gss_initialize);
ZEND_VAS_NAMED_FUNC(vas_gss_acquire_cred);
ZEND_VAS_NAMED_FUNC(vas_gss_auth);
ZEND_VAS_NAMED_FUNC(vas_gss_spnego_initiate);
ZEND_VAS_NAMED_FUNC(vas_gss_spnego_accept);
ZEND_VAS_NAMED_FUNC(vas_gss_krb5_get_subkey);
ZEND_VAS_NAMED_FUNC(new_gss_buffer_desc);
ZEND_VAS_NAMED_FUNC(delete_gss_buffer_desc);
ZEND_VAS_NAMED_FUNC(new_gss_OID_desc);
ZEND_VAS_NAMED_FUNC(delete_gss_OID_desc);
ZEND_VAS_NAMED_FUNC(new_gss_OID_set_desc);
ZEND_VAS_NAMED_FUNC(delete_gss_OID_set_desc);
ZEND_VAS_NAMED_FUNC(new_gss_channel_bindings_struct);
ZEND_VAS_NAMED_FUNC(delete_gss_channel_bindings_struct);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_USER_NAME_set);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_USER_NAME_get);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_MACHINE_UID_NAME_set);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_MACHINE_UID_NAME_get);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_STRING_UID_NAME_set);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_STRING_UID_NAME_get);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_HOSTBASED_SERVICE_X_set);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_HOSTBASED_SERVICE_X_get);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_HOSTBASED_SERVICE_set);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_HOSTBASED_SERVICE_get);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_ANONYMOUS_set);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_ANONYMOUS_get);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_EXPORT_NAME_set);
ZEND_VAS_NAMED_FUNC(GSS_C_NT_EXPORT_NAME_get);
ZEND_VAS_NAMED_FUNC(GSS_SPNEGO_MECHANISM_set);
ZEND_VAS_NAMED_FUNC(GSS_SPNEGO_MECHANISM_get);
ZEND_VAS_NAMED_FUNC(gss_acquire_cred);
ZEND_VAS_NAMED_FUNC(gss_add_cred);
ZEND_VAS_NAMED_FUNC(gss_inquire_cred);
ZEND_VAS_NAMED_FUNC(gss_inquire_cred_by_mech);
ZEND_VAS_NAMED_FUNC(gss_init_sec_context);
ZEND_VAS_NAMED_FUNC(gss_accept_sec_context);
ZEND_VAS_NAMED_FUNC(gss_process_context_token);
ZEND_VAS_NAMED_FUNC(gss_context_time);
ZEND_VAS_NAMED_FUNC(gss_inquire_context);
ZEND_VAS_NAMED_FUNC(gss_wrap_size_limit);
ZEND_VAS_NAMED_FUNC(gss_export_sec_context);
ZEND_VAS_NAMED_FUNC(gss_import_sec_context);
ZEND_VAS_NAMED_FUNC(gss_get_mic);
ZEND_VAS_NAMED_FUNC(gss_verify_mic);
ZEND_VAS_NAMED_FUNC(gss_wrap);
ZEND_VAS_NAMED_FUNC(gss_unwrap);
ZEND_VAS_NAMED_FUNC(gss_sign);
ZEND_VAS_NAMED_FUNC(gss_verify);
ZEND_VAS_NAMED_FUNC(gss_seal);
ZEND_VAS_NAMED_FUNC(gss_unseal);
ZEND_VAS_NAMED_FUNC(gss_import_name);
ZEND_VAS_NAMED_FUNC(gss_display_name);
ZEND_VAS_NAMED_FUNC(gss_compare_name);
ZEND_VAS_NAMED_FUNC(gss_release_name);
ZEND_VAS_NAMED_FUNC(gss_inquire_names_for_mech);
ZEND_VAS_NAMED_FUNC(gss_inquire_mechs_for_name);
ZEND_VAS_NAMED_FUNC(gss_canonicalize_name);
ZEND_VAS_NAMED_FUNC(gss_export_name);
ZEND_VAS_NAMED_FUNC(gss_duplicate_name);
ZEND_VAS_NAMED_FUNC(gss_display_status);
ZEND_VAS_NAMED_FUNC(gss_create_empty_oid_set);
ZEND_VAS_NAMED_FUNC(gss_add_oid_set_member);
ZEND_VAS_NAMED_FUNC(gss_test_oid_set_member);
ZEND_VAS_NAMED_FUNC(gss_release_oid_set);
ZEND_VAS_NAMED_FUNC(gss_release_buffer);
ZEND_VAS_NAMED_FUNC(gss_indicate_mechs);
ZEND_VAS_NAMED_FUNC(vas_krb5_get_context);
ZEND_VAS_NAMED_FUNC(vas_krb5_get_principal);
ZEND_VAS_NAMED_FUNC(vas_krb5_get_ccache);
ZEND_VAS_NAMED_FUNC(vas_krb5_get_credentials);
ZEND_VAS_NAMED_FUNC(vas_krb5_validate_credentials);
ZEND_VAS_NAMED_FUNC(vas_ldap_init_and_bind);
ZEND_VAS_NAMED_FUNC(vas_ldap_set_attributes);

ZEND_BEGIN_MODULE_GLOBALS(vas)
     vas_err_t g_vas_err;
     vas_err_t g_vas_err_minor;
ZEND_END_MODULE_GLOBALS(vas)

#ifdef ZTS
# define VAS_D       zend_vas_globals *vas_globals
# define VAS_DC      , VAS_D
# define VAS_C       vas_globals
# define VAS_CC      , VAS_C
# define VAS_SG(v)   (vas_globals->v)
# define VAS_FETCH() zend_vas_globals *vas_globals = ts_resource(vas_globals_id)
# define VAS_G(v)    TSRMG(vas_globals_id, zend_vas_globals *, v)
#else
# define VAS_D
# define VAS_DC
# define VAS_C
# define VAS_CC
# define VAS_SG(v)   (vas_globals.v)
# define VAS_FETCH()
# define VAS_G(v)    (vas_globals.v)
#endif

#endif /* PHP_VAS_H */
