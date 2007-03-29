#include <dlfcn.h>
#include <string.h>
#include <gssapi.h>
#include <pgssapi.h>
#include "pgss-common.h"
#include "pgss-dispatch.h"
#include "pgss-config.h"

/*
 * A dynamically loaded library provider.
 * This provider uses dlopen to open a shared library that exposes
 * a GSS ABI. It provides a dispatch table populated with pointers directly
 * into the shared library, or with NULL if the function doesn't exist.
 */

struct pgss_dispatch *
_pgss_dl_provider(struct config *config)
{
    struct pgss_dispatch *dispatch;
    void *handle;

    handle = dlopen(config->name, RTLD_NOW);
    if (!handle)
    	return NULL;
    
    dispatch = new(struct pgss_dispatch);
    memset(dispatch, 0, sizeof *dispatch);

#define LOOKUP(name) dispatch->name = (name##_t)dlsym(handle, #name)
    LOOKUP(gss_acquire_cred);
    LOOKUP(gss_release_cred);
    LOOKUP(gss_init_sec_context);
    LOOKUP(gss_accept_sec_context);
    LOOKUP(gss_process_context_token);
    LOOKUP(gss_delete_sec_context);
    LOOKUP(gss_context_time);
    LOOKUP(gss_get_mic);
    LOOKUP(gss_verify_mic);
    LOOKUP(gss_wrap);
    LOOKUP(gss_unwrap);
    LOOKUP(gss_display_status);
    LOOKUP(gss_indicate_mechs);
    LOOKUP(gss_compare_name);
    LOOKUP(gss_display_name);
    LOOKUP(gss_import_name);
    LOOKUP(gss_export_name);
    LOOKUP(gss_release_name);
    LOOKUP(gss_release_buffer);
    LOOKUP(gss_release_oid_set);
    LOOKUP(gss_inquire_cred);
    LOOKUP(gss_inquire_context);
    LOOKUP(gss_wrap_size_limit);
    LOOKUP(gss_add_cred);
    LOOKUP(gss_inquire_cred_by_mech);
    LOOKUP(gss_export_sec_context);
    LOOKUP(gss_import_sec_context);
    LOOKUP(gss_create_empty_oid_set);
    LOOKUP(gss_add_oid_set_member);
    LOOKUP(gss_test_oid_set_member);
    LOOKUP(gss_inquire_names_for_mech);
    LOOKUP(gss_inquire_mechs_for_name);
    LOOKUP(gss_canonicalize_name);
    LOOKUP(gss_duplicate_name);
    LOOKUP(gss_sign);
    LOOKUP(gss_verify);
    LOOKUP(gss_seal);
    LOOKUP(gss_unseal);
    LOOKUP(pgss_ctl);

    return dispatch;
}
