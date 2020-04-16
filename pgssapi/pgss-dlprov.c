/* 
 * (c) 2007 Quest Software, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *  a. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 
 *  b. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 
 *  c. Neither the name of Quest Software, Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */ 

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

    handle = dlopen(config->name, RTLD_LAZY | RTLD_LOCAL);
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
