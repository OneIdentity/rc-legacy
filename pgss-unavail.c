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

/*
 * A dispatcher that returns GSS_S_UNAVAILABLE for all operations
 */

#include <gssapi.h>
#include <pgssapi.h>
#include "pgss-dispatch.h"

static OM_uint32
unavailable(minor_status)
    OM_uint32 *minor_status;
{
    *minor_status = 0;
    return GSS_S_UNAVAILABLE;
}

static OM_uint32
unavail_acquire_cred(minor_status, desired_name, time_req, 
        desired_mechs, cred_usage, output_cred_handle, 
        actual_mechs, time_rec)
   OM_uint32 *minor_status;
   const gss_name_t desired_name;
   OM_uint32 time_req;
   const gss_OID_set desired_mechs;
   gss_cred_usage_t cred_usage;
   gss_cred_id_t *output_cred_handle;
   gss_OID_set *actual_mechs;
   OM_uint32 *time_rec;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_release_cred(minor_status, cred_handle)
   OM_uint32 *minor_status;
   gss_cred_id_t *cred_handle;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_init_sec_context(minor_status, initiator_cred_handle, context_handle,
        target_name, mech_type, req_flags, time_req, input_chan_bindings,
        input_token, actual_mech_type, output_token, ret_flags, time_rec)
   OM_uint32 *minor_status;
   const gss_cred_id_t initiator_cred_handle;
   gss_ctx_id_t *context_handle;
   const gss_name_t target_name;
   const gss_OID mech_type;
   OM_uint32 req_flags;
   OM_uint32 time_req;
   const gss_channel_bindings_t input_chan_bindings;
   const gss_buffer_t input_token;
   gss_OID *actual_mech_type;
   gss_buffer_t output_token;
   OM_uint32 *ret_flags;
   OM_uint32 *time_rec;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_accept_sec_context(minor_status, context_handle, acceptor_cred_handle,
        input_token_buffer, input_chan_bindings, src_name, mech_type,
        output_token, ret_flags, time_rec, delegated_cred_handle)
   OM_uint32 *minor_status;
   gss_ctx_id_t *context_handle;
   const gss_cred_id_t acceptor_cred_handle;
   const gss_buffer_t input_token_buffer;
   const gss_channel_bindings_t input_chan_bindings;
   gss_name_t *src_name;
   gss_OID *mech_type;
   gss_buffer_t output_token;
   OM_uint32 *ret_flags;
   OM_uint32 *time_rec;
   gss_cred_id_t *delegated_cred_handle;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_process_context_token(minor_status, context_handle, token_buffer)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   const gss_buffer_t token_buffer;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_delete_sec_context(minor_status, context_handle, output_token)
   OM_uint32 *minor_status;
   gss_ctx_id_t *context_handle;
   gss_buffer_t output_token;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_context_time(minor_status, context_handle, time_rec)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   OM_uint32 *time_rec;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_get_mic(minor_status, context_handle, qop_req, message_buffer, 
        message_token)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   gss_qop_t qop_req;
   const gss_buffer_t message_buffer;
   gss_buffer_t message_token;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_verify_mic(minor_status, context_handle, message_buffer, 
        token_buffer, qop_state)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   const gss_buffer_t message_buffer;
   const gss_buffer_t token_buffer;
   gss_qop_t *qop_state;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_wrap(minor_status, context_handle, conf_req_flag, qop_req, 
        input_message_buffer, conf_state, output_message_buffer)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   int conf_req_flag;
   gss_qop_t qop_req;
   const gss_buffer_t input_message_buffer;
   int *conf_state;
   gss_buffer_t output_message_buffer;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_unwrap(minor_status, context_handle, input_message_buffer, 
        output_message_buffer, conf_state, qop_state)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   const gss_buffer_t input_message_buffer;
   gss_buffer_t output_message_buffer;
   int *conf_state;
   gss_qop_t *qop_state;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_display_status(minor_status, status_value, status_type, mech_type,
        message_context, status_string)
   OM_uint32 *minor_status;
   OM_uint32 status_value;
   int status_type;
   const gss_OID mech_type;
   OM_uint32 *message_context;
   gss_buffer_t status_string;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_indicate_mechs(minor_status, mech_set)
   OM_uint32 *minor_status;
   gss_OID_set *mech_set;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_compare_name(minor_status, name1, name2, name_equal)
   OM_uint32 *minor_status;
   const gss_name_t name1;
   const gss_name_t name2;
   int *name_equal;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_display_name(minor_status, input_name, output_name_buffer, output_name_type)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   gss_buffer_t output_name_buffer;
   gss_OID *output_name_type;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_import_name(minor_status, input_name_buffer, input_name_type, output_name)
   OM_uint32 *minor_status;
   const gss_buffer_t input_name_buffer;
   const gss_OID input_name_type;
   gss_name_t *output_name;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_export_name(minor_status, input_name, exported_name)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   gss_buffer_t exported_name;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_release_name(minor_status, input_name)
   OM_uint32 *minor_status;
   gss_name_t *input_name;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_release_buffer(minor_status, buffer)
   OM_uint32 *minor_status;
   gss_buffer_t buffer;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_release_oid_set(minor_status, set)
   OM_uint32 *minor_status;
   gss_OID_set *set;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_inquire_cred(minor_status, cred_handle, name, lifetime, cred_usage,
        mechanisms)
   OM_uint32 *minor_status;
   const gss_cred_id_t cred_handle;
   gss_name_t *name;
   OM_uint32 *lifetime;
   gss_cred_usage_t *cred_usage;
   gss_OID_set *mechanisms;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_inquire_context(minor_status, context_handle, src_name, targ_name,
        lifetime_rec, mech_type, ctx_flags, locally_initiated, open)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   gss_name_t *src_name;
   gss_name_t *targ_name;
   OM_uint32 *lifetime_rec;
   gss_OID *mech_type;
   OM_uint32 *ctx_flags;
   int *locally_initiated;
   int *open;
{
    return unavailable(minor_status);
}


static OM_uint32
unavail_wrap_size_limit(minor_status, context_handle, conf_req_flag, qop_req,
        req_output_size, max_input_size)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   int conf_req_flag;
   gss_qop_t qop_req;
   OM_uint32 req_output_size;
   OM_uint32 *max_input_size;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_add_cred(minor_status, input_cred_handle, desired_name, desired_mech,
        cred_usage, initiator_time_req, acceptor_time_req, output_cred_handle,
        actual_mechs, initiator_time_rec, acceptor_time_rec)
   OM_uint32 *minor_status;
   const gss_cred_id_t input_cred_handle;
   const gss_name_t desired_name;
   const gss_OID desired_mech;
   gss_cred_usage_t cred_usage;
   OM_uint32 initiator_time_req;
   OM_uint32 acceptor_time_req;
   gss_cred_id_t *output_cred_handle;
   gss_OID_set *actual_mechs;
   OM_uint32 *initiator_time_rec;
   OM_uint32 *acceptor_time_rec;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_inquire_cred_by_mech(minor_status, cred_handle, mech_type, name,
        initiator_lifetime, acceptor_lifetime, cred_usage)
   OM_uint32 *minor_status;
   const gss_cred_id_t cred_handle;
   const gss_OID mech_type;
   gss_name_t *name;
   OM_uint32 *initiator_lifetime;
   OM_uint32 *acceptor_lifetime;
   gss_cred_usage_t *cred_usage;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_export_sec_context(minor_status, context_handle, interprocess_token)
   OM_uint32 *minor_status;
   gss_ctx_id_t *context_handle;
   gss_buffer_t interprocess_token;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_import_sec_context(minor_status, interprocess_token, context_handle)
   OM_uint32 *minor_status;
   const gss_buffer_t interprocess_token;
   gss_ctx_id_t *context_handle;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_create_empty_oid_set(minor_status, oid_set)
   OM_uint32 *minor_status;
   gss_OID_set *oid_set;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_add_oid_set_member(minor_status, member_oid, oid_set)
   OM_uint32 *minor_status;
   const gss_OID member_oid;
   gss_OID_set *oid_set;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_test_oid_set_member(minor_status, member, set, present)
   OM_uint32 *minor_status;
   const gss_OID member;
   const gss_OID_set set;
   int *present;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_inquire_names_for_mech(minor_status, mechanism, name_types)
   OM_uint32 *minor_status;
   const gss_OID mechanism;
   gss_OID_set *name_types;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_inquire_mechs_for_name(minor_status, input_name, mech_types)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   gss_OID_set *mech_types;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_canonicalize_name(minor_status, input_name, mech_type, output_name)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   const gss_OID mech_type;
   gss_name_t *output_name;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_duplicate_name(minor_status, src_name, dest_name)
   OM_uint32 *minor_status;
   const gss_name_t src_name;
   gss_name_t *dest_name;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_sign(minor_status, context_handle, qop_req, message_buffer,
        message_token)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   int qop_req;
   gss_buffer_t message_buffer;
   gss_buffer_t message_token;
{
    return unavailable(minor_status);
}


static OM_uint32
unavail_verify(minor_status, context_handle, message_buffer, token_buffer,
        qop_state)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   gss_buffer_t message_buffer;
   gss_buffer_t token_buffer;
   int *qop_state;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_seal(minor_status, context_handle, conf_req_flag, qop_req,
        input_message_buffer, conf_state, output_message_buffer)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   int conf_req_flag;
   int qop_req;
   gss_buffer_t input_message_buffer;
   int *conf_state;
   gss_buffer_t output_message_buffer;
{
    return unavailable(minor_status);
}

static OM_uint32
unavail_unseal(minor_status, context_handle, input_message_buffer,
        output_message_buffer, conf_state, qop_state)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   gss_buffer_t input_message_buffer;
   gss_buffer_t output_message_buffer;
   int *conf_state;
   int *qop_state;
{
    return unavailable(minor_status);
}

struct pgss_dispatch _pgss_unavailable = {
	unavail_acquire_cred,		/* gss_acquire_cred */
	unavail_release_cred,		/* gss_release_cred */
	unavail_init_sec_context,	/* gss_init_sec_context */
	unavail_accept_sec_context,	/* gss_accept_sec_context */
	unavail_process_context_token,	/* gss_process_context_token */
	unavail_delete_sec_context,	/* gss_delete_sec_context */
	unavail_context_time,		/* gss_context_time */
	unavail_get_mic,		/* gss_get_mic */
	unavail_verify_mic,		/* gss_verify_mic */
	unavail_wrap,			/* gss_wrap */
	unavail_unwrap,			/* gss_unwrap */
	unavail_display_status,	        /* gss_display_status */
	unavail_indicate_mechs,		/* gss_indicate_mechs */
	unavail_compare_name,		/* gss_compare_name */
	unavail_display_name,		/* gss_display_name */
	unavail_import_name,		/* gss_import_name */
	unavail_export_name,		/* gss_export_name */
	unavail_release_name,		/* gss_release_name */
	unavail_release_buffer,		/* gss_release_buffer */
	unavail_release_oid_set,	/* gss_release_oid_set */
	unavail_inquire_cred,		/* gss_inquire_cred */
	unavail_inquire_context,	/* gss_inquire_context */
	unavail_wrap_size_limit,	/* gss_wrap_size_limit */
	unavail_add_cred,		/* gss_add_cred */
	unavail_inquire_cred_by_mech,	/* gss_inquire_cred_by_mech */
	unavail_export_sec_context,	/* gss_export_sec_context */
	unavail_import_sec_context,	/* gss_import_sec_context */
	unavail_create_empty_oid_set,	/* gss_create_empty_oid_set */
	unavail_add_oid_set_member,	/* gss_add_oid_set_member */
	unavail_test_oid_set_member,	/* gss_test_oid_set_member */
	unavail_inquire_names_for_mech,	/* gss_inquire_names_for_mech */
	unavail_inquire_mechs_for_name,	/* gss_inquire_mechs_for_name */
	unavail_canonicalize_name,	/* gss_canonicalize_name */
	unavail_duplicate_name,		/* gss_duplicate_name */
	unavail_sign,			/* gss_sign */
	unavail_verify,			/* gss_verify */
	unavail_seal,			/* gss_seal */
	unavail_unseal,			/* gss_unseal */
	0				/* gss_ctl */
};
