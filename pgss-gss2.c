/*
 * (c) 2007, Quest Software, Inc. All rights reserved. 
 */

#include <errno.h>
#include <gssapi.h>
#include <pgssapi.h>
#include <string.h>
#include "pgss-common.h"
#include "pgss-gss2.h"
#include "pgss-dispatch.h"
#include "pgss-config.h"

gss_OID_desc
    _pgss_NT_USER_NAME =           /* 1.2.840.113554.1.2.1.1 */
	    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"},
    _pgss_NT_MACHINE_UID_NAME =    /* 1.2.840.113554.1.2.1.2 */
	    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"},
    _pgss_NT_STRING_UID_NAME =     /* 1.2.840.113554.1.2.1.3 */
	    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"},
    _pgss_NT_HOSTBASED_SERVICE_X = /* 1.3.6.1.5.6.2 */
	    { 6, (void *)"\x2b\x06\x01\x05\x06\x02"},
    _pgss_NT_HOSTBASED_SERVICE =   /* 1.2.840.113554.1.2.1.4 */
	    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"},
    _pgss_NT_ANONYMOUS =           /* 1.3.6.1.5.6.3 */
	    { 6, (void *)"\x2b\x06\x01\x05\x06\x03"},
    _pgss_NT_EXPORT_NAME =         /* 1.3.6.1.5.6.4 */
	    { 6, (void *)"\x2b\x06\x01\x05\x06\x04"},
    _pgss_KRB5_MECHANISM =         /* 1.2.840.113554.1.2.2 */
	    { 9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"},
    _pgss_KRB5_NT_PRINCIPAL_NAME = /* 1.2.840.113554.1.2.2.1 */
	    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01"};

gss_OID
    GSS_C_NT_USER_NAME =           &_pgss_NT_USER_NAME,
    GSS_C_NT_MACHINE_UID_NAME =    &_pgss_NT_MACHINE_UID_NAME,
    GSS_C_NT_STRING_UID_NAME =     &_pgss_NT_STRING_UID_NAME,
    GSS_C_NT_HOSTBASED_SERVICE_X = &_pgss_NT_HOSTBASED_SERVICE_X,
    GSS_C_NT_HOSTBASED_SERVICE =   &_pgss_NT_HOSTBASED_SERVICE,
    GSS_C_NT_ANONYMOUS =           &_pgss_NT_ANONYMOUS,
    GSS_C_NT_EXPORT_NAME =         &_pgss_NT_EXPORT_NAME,
    GSS_KRB5_MECHANISM =           &_pgss_KRB5_MECHANISM,
    GSS_KRB5_NT_PRINCIPAL_NAME =   &_pgss_KRB5_NT_PRINCIPAL_NAME;

/*
 * Sets minor_status to 0 and returns GSS_S_COMPLETE
 */
static OM_uint32
complete(minor_status)
    OM_uint32 *minor_status;
{
    if (minor_status)
	*minor_status = 0;
    return GSS_S_COMPLETE;
}

/*
 * Sets minor_status to an error code and returns GSS_S_FAILURE.
 * Convenience function.
 */
static OM_uint32
failure(minor_status, code)
    OM_uint32 *minor_status;
{
    if (minor_status)
	*minor_status = code;
    return GSS_S_FAILURE;
}

/*
 * Sets minor_status to errno and returns GSS_S_FAILURE.
 * Convenience function.
 */
static OM_uint32
failure_from_errno(minor_status)
    OM_uint32 *minor_status;
{
    return failure(errno);
}

/*
 * Returns a mechanism error converted into a generic error.
 */
static OM_uint32
mech_error(major, minor_status, dispatch)
    OM_uint32 major;
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
{
    /* TBD */
    return major;
}

/*
 * Ensure the pgssapi has been initialised.
 * Returns zero (GSS_S_COMPLETE) on success.
 */
static OM_uint32
init(minor_status)
    OM_uint32 *minor_status;
{
    /* TBD */
    return complete(minor_status);
}

/*
 * Returns the dispatch table for a mechanism.
 * Returns GSS_S_BAD_MECH if the mechanism is not known.
 */
static OM_uint32
find_dispatch(minor_status, mech, dispatch_return)
    OM_uint32 *minor_status;
    gss_OID mech;
    struct pgss_dispatch **dispatch_return;
{
    struct config *config;

    if (minor_status)
	*minor_status = 0;

    /* Look for a configuration keyed by the mechanism */
    config = _pgss_config_find(mech);
    if (!config)
	return GSS_S_BAD_MECH;

    /* Return the dispatch table associated with the mechanism */
    *dispatch_return = config->dispatch;
    return GSS_S_COMPLETE;
}

/*
 * Copies out a buffer so that we don't have to worry about
 * translating gss_release_buffer() calls later.
 * Modifies the buffer content to point to stoareg owned by PGSS.
 * On success and error, the buffer will always be released.
 */
static OM_uint32
copyout_buffer(minor_status, dispatch, buffer)
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
    gss_buffer_t buffer;
{
    void *new_data;
    OM_uint32 major, ignore, length;

    if (buffer == GSS_C_NO_BUFFER)
	return complete(minor_status);

    /* Copy the old buffer content */
    length = buffer->length;
    if (length) {
	new_data = new_array(char, length);
	if (!new_data) {
	    (void)(*dispatch->gss_release_buffer)(&ignore, buffer);
	    return failure(minor_status, ENOMEM);
	}
	memcpy(new_data, buffer->value, length);
    } else
	new_data = NULL;

    /* Release the old buffer */
    major = (*dispatch->gss_release_buffer)(&ignore, buffer);
    if (major) {
	if (new_data)
	    free(new_data);
	return major;
    }

    /* Replace with the new content */
    buffer->length = length;
    buffer->value = new_data;
    return complete(minor_status);
}

/*
 * Copies out an oid-set so that we don't have to worry about
 * translating gss_release_oid_set() calls later.
 * Modifies the oid_set pointer to point to stoareg owned by PGSS.
 * On success and error, the oid_set will always be released.
 */
static OM_uint32
copyout_oid_set(minor_status, dispatch, oid_set)
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
    gss_OID_set *oid_set;
{
    OM_uint32 major, ignore;
    gss_OID_set new_oid_set;

    if (!minor_status)
	minor_status = &ignore;

    if (*oid_set == GSS_C_NO_OID_SET)
	return complete(minor_status);

    /* Duplicate the oid set */
    new_oid_set = new(gss_OID_set_desc);
    if (!new_oid_set)
	goto nomem;
    new_oid_set->elements = NULL;
    new_oid_set->count = 0;
    if ((*oid_set)->count) {
	new_oid_set->elements = new_array(gss_OID_desc, (*oid_set)->count);
	if (!new_oid_set->elements) 
	    goto nomem;
    }
    while (new_oid_set->count < (*oid_set)->count) {
	gss_OID new_oid = &new_oid_set->elements[new_oid_set->count];
	gss_OID old_oid = &(*oid_set)->elements[new_oid_set->count];

	new_oid->elements = new_array(char, old_oid->length);
	if (!new_oid->elements)
	    goto nomem;
	memcpy(new_oid->elements, old_oid->elements, old_oid->length);
	new_oid->length = old_oid->length;
	new_oid_set->count++;
    }

    /* Release the mechanism's oid set */
    major = (*dispatch->gss_release_oid_set)(minor_status, oid_set);
    if (major == GSS_S_COMPLETE)
	*oid_set = new_oid_set;
    else {
	(void)gss_release_oid_set(NULL, &new_oid_set);
	return mech_error(major, minor_status, dispatch);
    }

    return complete(minor_status);

nomem:
    if (new_oid_set) {
	if (new_oid_set->elements) {
	    while (new_oid_set->count--)
		free(new_oid_set->elements[new_oid_set->count].elements);
	    free(new_oid_set->elements);
	}
	free(new_oid_set);
    }
    (void)(*dispatch->gss_release_oid_set)(&ignore, oid_set);
    return failure(minor_status, ENOMEM);
}


/*
 * Replaces a name returned from a provider with a pgss_name wrapper.
 * Modifies the name pointer. 
 * On error, the underlying name will be released.
 */
static OM_uint32
copyout_name(minor_status, dispatch, name)
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
    gss_name_t *name;
{
    OM_uint32 ignore;
    struct pgss_name *new_name;

    new_name = new(struct pgss_name);
    if (!new_name)
	goto nomem;

    new_name->owner = dispatch;
    new_name->name = *name;
    new_name->type = GSS_C_NO_OID;

    *name = new_name;
    return complete(minor_status);

nomem:
    if (new_name)
	free(new_name);
    (void)(*dispatch->gss_release_name)(&ignore, name);
    return failure(minor_status, ENOMEM);
}


OM_uint32
gss_acquire_cred(minor_status, desired_name, time_req, 
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
    /* TBD */
}

OM_uint32
gss_release_cred(minor_status, cred_handle)
   OM_uint32 *minor_status;
   gss_cred_id_t *cred_handle;
{
    /* TBD */
}

OM_uint32
gss_init_sec_context(minor_status, initiator_cred_handle, context_handle,
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
    /* TBD */
}

OM_uint32
gss_accept_sec_context(minor_status, context_handle, acceptor_cred_handle,
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
    /* TBD */
}

OM_uint32
gss_process_context_token(minor_status, context_handle, token_buffer)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   const gss_buffer_t token_buffer;
{
    /* TBD */
}

OM_uint32
gss_delete_sec_context(minor_status, context_handle, output_token)
   OM_uint32 *minor_status;
   gss_ctx_id_t *context_handle;
   gss_buffer_t output_token;
{
    /* TBD */
}

OM_uint32
gss_context_time(minor_status, context_handle, time_rec)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   OM_uint32 *time_rec;
{
    /* TBD */
}

OM_uint32
gss_get_mic(minor_status, context_handle, qop_req, message_buffer, 
        message_token)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   gss_qop_t qop_req;
   const gss_buffer_t message_buffer;
   gss_buffer_t message_token;
{
    /* TBD */
}

OM_uint32
gss_verify_mic(minor_status, context_handle, message_buffer, 
        token_buffer, qop_state)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   const gss_buffer_t message_buffer;
   const gss_buffer_t token_buffer;
   gss_qop_t *qop_state;
{
    /* TBD */
}

OM_uint32
gss_wrap(minor_status, context_handle, conf_req_flag, qop_req, 
        input_message_buffer, conf_state, output_message_buffer)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   int conf_req_flag;
   gss_qop_t qop_req;
   const gss_buffer_t input_message_buffer;
   int *conf_state;
   gss_buffer_t output_message_buffer;
{
    /* TBD */
}

OM_uint32
gss_unwrap(minor_status, context_handle, input_message_buffer, 
        output_message_buffer, conf_state, qop_state)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   const gss_buffer_t input_message_buffer;
   gss_buffer_t output_message_buffer;
   int *conf_state;
   gss_qop_t *qop_state;
{
    /* TBD */
}

OM_uint32
gss_display_status(minor_status, status_value, status_type, mech_type,
        message_context, status_string)
   OM_uint32 *minor_status;
   OM_uint32 status_value;
   int status_type;
   const gss_OID mech_type;
   OM_uint32 *message_context;
   gss_buffer_t status_string;
{
    /* TBD */
}

OM_uint32
gss_indicate_mechs(minor_status, mech_set)
   OM_uint32 *minor_status;
   gss_OID_set *mech_set;
{
    OM_uint32 major;
    struct config *config;
    void *iter;
    gss_OID mech;
    gss_OID_set result;

    if ((major = init(minor_status)))
	return major;

    if ((major = gss_create_empty_oid_set(minor_status, &result)))
	return major;

    /* Iterate over the mechanism OIDs, adding them to the result set */
    /* (could be optimized) */
    iter = 0;
    while ((config = _pgss_config_iterate(&iter, &mech))) {
	major = gss_add_oid_set_member(minor_status, mech, &result);
	if (major) {
	    (void)gss_release_oid_set(NULL, &result);
	    return major;
	}
    }

    *mech_set = result;
    return complete(minor_status);
}

OM_uint32
gss_compare_name(minor_status, name1, name2, name_equal)
   OM_uint32 *minor_status;
   const gss_name_t name1;
   const gss_name_t name2;
   int *name_equal;
{
    /* TBD */
}

OM_uint32
gss_display_name(minor_status, input_name, output_name_buffer, output_name_type)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   gss_buffer_t output_name_buffer;
   gss_OID *output_name_type;
{
    /* TBD */
}

OM_uint32
gss_import_name(minor_status, input_name_buffer, input_name_type, output_name)
   OM_uint32 *minor_status;
   const gss_buffer_t input_name_buffer;
   const gss_OID input_name_type;
   gss_name_t *output_name;
{
    /* TBD */
}

OM_uint32
gss_export_name(minor_status, input_name, exported_name)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   gss_buffer_t exported_name;
{
    /* TBD */
}

OM_uint32
gss_release_name(minor_status, input_name)
   OM_uint32 *minor_status;
   gss_name_t *input_name;
{
    OM_uint32 ignore, major;
    struct pgss_dispatch *dispatch;
    struct pgss_name *name;

    if (!minor_status)
	minor_status = &ignore;

    name = *input_name;
    if (name) {
	dispatch = name->owner;
	if (dispatch) {
	    /* Ask the mechanism to release the name */
	    major = (*dispatch->gss_release_name)(minor_status, &name->name);
	    if (major)
		return major;
	} else
	    (void)gss_release_buffer(NULL, &name->data);

	free(name);
	*input_name = GSS_C_NO_NAME;
    }
    return complete(minor_status);
}

OM_uint32
gss_release_buffer(minor_status, buffer)
   OM_uint32 *minor_status;
   gss_buffer_t buffer;
{
    if (buffer) {
	if (buffer->value) {
	    free(buffer->value);
	    buffer->value = 0;
	}
	buffer->length = 0;
    }
    return complete(minor_status);
}

OM_uint32
gss_release_oid_set(minor_status, set)
   OM_uint32 *minor_status;
   gss_OID_set *set;
{
    OM_uint32 i;

    if (*set != GSS_C_NO_OID_SET) {
	for (i = 0; i < (*set)->count; i++)
	    free((*set)->elements[i].elements);
	if ((*set)->elements)
	    free((*set)->elements);
	free(*set);
    }
    *set = GSS_C_NO_OID_SET;
    return complete(minor_status);
}

OM_uint32
gss_inquire_cred(minor_status, cred_handle, name, lifetime, cred_usage,
        mechanisms)
   OM_uint32 *minor_status;
   const gss_cred_id_t cred_handle;
   gss_name_t *name;
   OM_uint32 *lifetime;
   gss_cred_usage_t *cred_usage;
   gss_OID_set *mechanisms;
{
    /* TBD */
}

OM_uint32
gss_inquire_context(minor_status, context_handle, src_name, targ_name,
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
    /* TBD */
}


OM_uint32
gss_wrap_size_limit(minor_status, context_handle, conf_req_flag, qop_req,
        req_output_size, max_input_size)
   OM_uint32 *minor_status;
   const gss_ctx_id_t context_handle;
   int conf_req_flag;
   gss_qop_t qop_req;
   OM_uint32 req_output_size;
   OM_uint32 *max_input_size;
{
    /* TBD */
}

OM_uint32
gss_add_cred(minor_status, input_cred_handle, desired_name, desired_mech,
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
    /* TBD */
}

OM_uint32
gss_inquire_cred_by_mech(minor_status, cred_handle, mech_type, name,
        initiator_lifetime, acceptor_lifetime, cred_usage)
   OM_uint32 *minor_status;
   const gss_cred_id_t cred_handle;
   const gss_OID mech_type;
   gss_name_t *name;
   OM_uint32 *initiator_lifetime;
   OM_uint32 *acceptor_lifetime;
   gss_cred_usage_t *cred_usage;
{
    /* TBD */
}

OM_uint32
gss_export_sec_context(minor_status, context_handle, interprocess_token)
   OM_uint32 *minor_status;
   gss_ctx_id_t *context_handle;
   gss_buffer_t interprocess_token;
{
    /* TBD */
}

OM_uint32
gss_import_sec_context(minor_status, interprocess_token, context_handle)
   OM_uint32 *minor_status;
   const gss_buffer_t interprocess_token;
   gss_ctx_id_t *context_handle;
{
    /* TBD */
}

OM_uint32
gss_create_empty_oid_set(minor_status, oid_set)
   OM_uint32 *minor_status;
   gss_OID_set *oid_set;
{
    gss_OID_set new_set;
   
    new_set = new(gss_OID_set_desc);
    if (!new_set)
	return failure(minor_status, ENOMEM);
    new_set->count = 0;
    new_set->elements = NULL;
    *oid_set = new_set;
    return complete(minor_status);
}

OM_uint32
gss_add_oid_set_member(minor_status, member_oid, oid_set)
   OM_uint32 *minor_status;
   const gss_OID member_oid;
   gss_OID_set *oid_set;
{
    int present;
    OM_uint32 major;
    gss_OID new_elements;
    void *new_oid_elements;
    gss_OID_set set;
   
    set = *oid_set;

    /* Do nothing if the member is already present */
    major = gss_test_oid_set_member(minor_status, member_oid, set, &present);
    if (major != GSS_S_COMPLETE)
	return major;
    if (present)
	return complete(minor_status);

    /* Allocate a slightly larger array */
    new_elements = new_array(gss_OID_desc, set->count + 1);
    if (!new_elements)
	return failure(minor_status, ENOMEM);
    new_oid_elements = new_array(char, member_oid->length);
    if (!new_oid_elements) {
	free(new_elements);
	return failure(minor_status, ENOMEM);
    }

    /* Copy in the old array, and append a copy of the new member_oid */
    memcpy(new_elements, set->elements, set->count * sizeof *new_elements);
    memcpy(new_oid_elements, member_oid->elements, member_oid->length);
    new_elements[set->count].length = member_oid->length;
    new_elements[set->count].elements = new_oid_elements;

    /* Release old array, and update the oid_set */
    free(set->elements);
    set->elements = new_elements;
    set->count++;

    return complete(minor_status);
}

OM_uint32
gss_test_oid_set_member(minor_status, member, set, present)
   OM_uint32 *minor_status;
   const gss_OID member;
   const gss_OID_set set;
   int *present;
{
    int i;

    /* Linear search for the OID */
    *present = 0;
    for (i = 0; i < set->count; i++)
	if (OID_EQUALS(&set->elements[i], member)) {
	    *present = 1;
	    break;
	}
    return success(minor_status);
}

OM_uint32
gss_inquire_names_for_mech(minor_status, mechanism, name_types)
   OM_uint32 *minor_status;
   const gss_OID mechanism;
   gss_OID_set *name_types;
{
    /* TBD */
}

OM_uint32
gss_inquire_mechs_for_name(minor_status, input_name, mech_types)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   gss_OID_set *mech_types;
{
    /* TBD */
}

OM_uint32
gss_canonicalize_name(minor_status, input_name, mech_type, output_name)
   OM_uint32 *minor_status;
   const gss_name_t input_name;
   const gss_OID mech_type;
   gss_name_t *output_name;
{
    /* TBD */
}

OM_uint32
gss_duplicate_name(minor_status, src_name, dest_name)
   OM_uint32 *minor_status;
   const gss_name_t src_name;
   gss_name_t *dest_name;
{
    /* TBD */
}

OM_uint32
gss_sign(minor_status, context_handle, qop_req, message_buffer,
        message_token)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   int qop_req;
   gss_buffer_t message_buffer;
   gss_buffer_t message_token;
{
    /* TBD */
}


OM_uint32
gss_verify(minor_status, context_handle, message_buffer, token_buffer,
        qop_state)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   gss_buffer_t message_buffer;
   gss_buffer_t token_buffer;
   int *qop_state;
{
    /* TBD */
}

OM_uint32
gss_seal(minor_status, context_handle, conf_req_flag, qop_req,
        input_message_buffer, conf_state, output_message_buffer)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   int conf_req_flag;
   int qop_req;
   gss_buffer_t input_message_buffer;
   int *conf_state;
   gss_buffer_t output_message_buffer;
{
    /* TBD */
}

OM_uint32
gss_unseal(minor_status, context_handle, input_message_buffer,
        output_message_buffer, conf_state, qop_state)
   OM_uint32 *minor_status;
   gss_ctx_id_t context_handle;
   gss_buffer_t input_message_buffer;
   gss_buffer_t output_message_buffer;
   int *conf_state;
   int *qop_state;
{
    /* TBD */
}

