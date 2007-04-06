/*
 * (c) 2007, Quest Software, Inc. All rights reserved. 
 */

/*
 * Provides an interface for GSSAPI v2, mapping calls onto providers
 */

#include <errno.h>
#include <assert.h>
#include <string.h>
#include "gssapi.h"
#include "pgssapi.h"
#include "pgss-common.h"
#include "pgss-dispatch.h"
#include "pgss-gss2.h"
#include "pgss-config.h"
#include "pgss-oidstr.h"

struct error_tab {
    OM_uint32   code;
    const char *text;
};

/* Prototypes */
static OM_uint32 complete(OM_uint32 *minor_status);
static OM_uint32 error(OM_uint32 *minor_status, const OM_uint32 major, 
		    const OM_uint32 minor);
static OM_uint32 failure(OM_uint32 *minor_status, const OM_uint32 minor);
static OM_uint32 failure_from_errno(OM_uint32 *minor_status, int err);
static OM_uint32 mech_error(OM_uint32 *minor_status, const OM_uint32 major, 
		    struct pgss_dispatch *dispatch);

static OM_uint32 init(OM_uint32 *minor_status);
static OM_uint32 find_dispatch(OM_uint32 *minor_status, gss_OID mech,
		    struct pgss_dispatch **dispatch_return);
static void      zero_buffer(gss_buffer_t buffer);
static OM_uint32 memdup_buffer(OM_uint32 *minor_status, const void *str,
		    OM_uint32 length, gss_buffer_t buffer);
static OM_uint32 strdup_buffer(OM_uint32 *minor_status, const char *str,
		    gss_buffer_t buffer);
static OM_uint32 copyout_buffer(OM_uint32 *minor_status, 
		    struct pgss_dispatch *dispatch, gss_buffer_t buffer);
static OM_uint32 copyout_oid_set(OM_uint32 *minor_status, 
		    struct pgss_dispatch *dispatch, gss_OID_set *oid_set);

static OM_uint32 copyout_name(OM_uint32 *minor_status, 
		    struct pgss_dispatch *dispatch, D_gss_name_t mech_name,
		    gss_name_t *name_return, OM_uint32 is_mn);
static OM_uint32 alloc_name(OM_uint32 *minor_status, const gss_buffer_t buffer,
		    gss_OID type, struct pgss_name **name_return);
static OM_uint32 get_any_mech_name(OM_uint32 *minor_status, 
		    struct pgss_name *name, struct pgss_dispatch **dispatch_ret,
		    D_gss_name_t *name_return);
static OM_uint32 get_mech_name(OM_uint32 *minor_status, struct pgss_name *name,
		    struct pgss_dispatch *dispatch, D_gss_name_t *name_return);
static OM_uint32 add_mech_name(OM_uint32 *minor_status, struct pgss_name *name,
		    struct pgss_dispatch *dispatch, D_gss_name_t mech_name);
static void      free_name(struct pgss_name **name_return);

static OM_uint32 alloc_cred_id(OM_uint32 *minor_status, 
		    struct pgss_cred_id **cred_return, OM_uint32 size);
static void      free_cred_id(struct pgss_cred_id **cred_return);
static OM_uint32 append_cred_id(OM_uint32 *minor_status, 
		    struct pgss_cred_id **cred_return, gss_OID mech, 
		    void *cred);

static OM_uint32 dup_oid(OM_uint32 *minor_status, const gss_OID oid, 
		    gss_OID oid_copy);
static void      free_oid(gss_OID oid);

static const char *error_tab_search(const struct error_tab *tab,OM_uint32 code);
static const char *major_display_status_opt(OM_uint32 code, OM_uint32 context);
static OM_uint32 major_display_status(OM_uint32 *minor_status, 
			OM_uint32 status_value, OM_uint32 *message_context, 
			gss_buffer_t status_string);

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

/*------------------------------------------------------------
 * Convenience major/minor error return functions
 */

/*
 * Sets minor_status to 0 and returns GSS_S_COMPLETE.
 * Convenience function.
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
 * Sets minor_status to 0 and returns the GSS_S_ major status.
 * Convenience function.
 */
static OM_uint32
error(minor_status, major, minor)
    OM_uint32 *minor_status;
    const OM_uint32 major, minor;
{
    if (minor_status)
	*minor_status = minor;
    return major;
}

/*
 * Sets minor_status to an error code and returns GSS_S_FAILURE.
 * Convenience function.
 */
static OM_uint32
failure(minor_status, minor)
    OM_uint32 *minor_status;
    const OM_uint32 minor;
{
    if (minor_status)
	*minor_status = minor;
    return GSS_S_FAILURE;
}

/*
 * Sets minor_status to errno and returns GSS_S_FAILURE.
 * Convenience function.
 */
static OM_uint32
failure_from_errno(minor_status, err)
    OM_uint32 *minor_status;
{
    /* strerror(err) */
    return failure(minor_status, 0);
}

/*
 * Returns a mechanism error converted into a generic error.
 * Convenience function.
 */
static OM_uint32
mech_error(minor_status, major, dispatch)
    OM_uint32 *minor_status;
    const OM_uint32 major;
    struct pgss_dispatch *dispatch;
{
    /* TBD */
    return major;
}

/*------------------------------------------------------------
 * Internal dispatch functions
 */

/*
 * Ensure the pgssapi has been initialised.
 * Returns zero (GSS_S_COMPLETE) on success.
 */
static OM_uint32
init(minor_status)
    OM_uint32 *minor_status;
{
    if (_pgss_init() == -1)
	return failure(minor_status, 0);
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

    /* Look for a configuration keyed by the mechanism */
    config = _pgss_config_find(mech);
    if (!config)
	return error(minor_status, GSS_S_BAD_MECH, 0);

    /* Return the dispatch table associated with the mechanism */
    *dispatch_return = config->dispatch;
    return complete(minor_status);
}

/*------------------------------------------------------------
 * Internal memory management functions
 */

/* Clears a buffer to an empty value. Safe for use with NULL buffers */
static void
zero_buffer(buffer)
    gss_buffer_t buffer;
{
    if (buffer) {
	buffer->value = NULL;
	buffer->length = 0;
    }
}

/* Copies memory into a buffer */
static OM_uint32
memdup_buffer(minor_status, value, length, buffer)
    OM_uint32 *minor_status;
    const void *value;
    OM_uint32 length;
    gss_buffer_t buffer;
{
    char *cp;

    if (length == 0) {
	/* Special case for NULL strings: no change */
	zero_buffer(buffer);
    } else {
	if (!(cp = (char *)malloc(length)))
	    return failure(minor_status, ENOMEM);
	memcpy(cp, value, length);
	buffer->length = length;
	buffer->value = cp;
    }
    return complete(minor_status);
}

/* Copies a C string into a buffer */
static OM_uint32
strdup_buffer(minor_status, str, buffer)
    OM_uint32 *minor_status;
    const char *str;
    gss_buffer_t buffer;
{
    char *cp;

    if (str == NULL) 
	return memdup_buffer(minor_status, NULL, 0, buffer);
    else
	return memdup_buffer(minor_status, str, strlen(str), buffer);
}

/*
 * Re-copies a buffer so that we don't have to worry about
 * translating gss_release_buffer() calls later.
 * Modifies the buffer pointers to point to new storage owned by PGSS,
 * and releases the old storage before returning.
 * On error, the original buffer will have been released.
 */
static OM_uint32
copyout_buffer(minor_status, dispatch, buffer)
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
    gss_buffer_t buffer;
{
    void *new_data;
    OM_uint32 major, minor, length;

    if (!buffer)
	return complete(minor_status);

    /*
     * TODO: maybe allow provider configs to flag that their buffers are
     * releasable with generic free(). This could improve performance.
     */

    /* Copy the old buffer content */
    length = buffer->length;
    if (length) {
	assert(buffer->value != NULL);

	new_data = new_array(char, length);
	if (!new_data) {
	    (void)(*dispatch->gss_release_buffer)(&minor, buffer);
	    zero_buffer(buffer);
	    return failure(minor_status, ENOMEM);
	}

	memcpy(new_data, buffer->value, length);

	/* Release the old buffer */
	if ((major = (*dispatch->gss_release_buffer)(&minor, buffer))) {
	    if (new_data)
		free(new_data);
	    zero_buffer(buffer);
	    return error(minor_status, major, minor);
	}

	/* Update buffer to point to the new data location. */
	buffer->value = new_data;
	buffer->length = length;
    }

    return complete(minor_status);
}

/*------------------------------
 * OID routines
 */

/*
 * Deep-copy an OID.
 * The fields of the output gss_OID_desc are set to point
 * to newly-allocated storage.
 */
static OM_uint32
dup_oid(minor_status, oid, oid_copy)
    OM_uint32 *minor_status;
    const gss_OID oid;
    gss_OID oid_copy;
{
    void *elements_copy;

    if (oid->length) {
	elements_copy = (void *)malloc(oid->length);
	if (!elements_copy)
	    return failure(minor_status, ENOMEM);
	memcpy(elements_copy, oid->elements, oid->length);
    } else
	elements_copy = NULL;

    oid_copy->length = oid->length;
    oid_copy->elements = elements_copy;

    return complete(minor_status);
}

/* Duplicate an OID pointer (deep copy). Returns NULL if no memory left */
static OM_uint32
dup_oid_pointer(minor_status, oid, oid_return)
    OM_uint32 *minor_status;
    gss_OID oid;
    gss_OID *oid_return;
{
    gss_OID copy;

    if (!oid) {
	*oid_return = NULL;
	return complete(minor_status);
    }
   
    if (!(copy = new(gss_OID_desc)))
	return failure(minor_status, ENOMEM);

    if (GSS_ERROR(dup_oid(NULL, oid, copy))) {
	free(copy);
	return failure(minor_status, ENOMEM);
    }

    *oid_return = copy;
    return complete(minor_status);
}

/* Releases an OID allocated with dup_oid */
static void
free_oid(oid)
    gss_OID oid;
{
    if (oid) {
	if (oid->elements)
	    free(oid->elements);
	oid->length = 0;
	oid->elements = NULL;
    }
}

/* Releases an OID allocated with dup_oid_pointer() */
static void
free_oid_pointer(oid)
    gss_OID *oid;
{
    if (*oid) {
	free_oid(*oid);
	free(*oid);
	*oid = NULL;
    }
}

/*----------------------------------------
 * OID set routines
 */

/* Creates a read-only, temporary singleton oid set */
static gss_OID_set
make_singleton_oid_set(oid_set, oid)
    gss_OID_set_desc *oid_set;	    /* points to temporary storage */
    const gss_OID oid;
{
    if (oid) {
	oid_set->count = 1;
	oid_set->elements = (gss_OID)oid;
    } else {
	oid_set->count = 0;
	oid_set->elements = NULL;
    }
    return oid_set;
}

/*
 * Copies out an oid-set so that we don't have to worry about
 * translating gss_release_oid_set() calls later.
 * Modifies the oid_set pointer to point to storage owned by PGSS.
 * On success and error, the original oid_set will always be released.
 */
static OM_uint32
copyout_oid_set(minor_status, dispatch, oid_set)
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
    gss_OID_set *oid_set;
{
    OM_uint32 major, minor, ignore;
    gss_OID_set new_oid_set;

    if (!minor_status)
	minor_status = &ignore;

    if (*oid_set == GSS_C_NO_OID_SET)
	return complete(minor_status);

    /*
     * TODO: allow provider configs to flag that their buffers are
     * releasable with generic free(). This would improve performance.
     */

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
    if (dispatch->gss_release_oid_set) {
	major = (*dispatch->gss_release_oid_set)(&minor, oid_set);
	if (GSS_ERROR(major)) {
	    (void)gss_release_oid_set(NULL, &new_oid_set);
	    return error(minor_status, major, minor);
	} else
	    *oid_set = new_oid_set;
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

/*----------------------------------------
 * Name routines
 */

/*
 * Wraps a name returned from a provider, modifying the name pointer. 
 * On error, the underlying name will be released.
 */
static OM_uint32
copyout_name(minor_status, dispatch, mech_name, name_return, is_mn)
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
    D_gss_name_t mech_name;
    gss_name_t *name_return;
    OM_uint32 is_mn;
{
    OM_uint32 major, ignore;
    gss_name_t new_name;

    if ((major = alloc_name(minor_status, GSS_C_NO_BUFFER,
		    GSS_C_NO_OID, &new_name)))
    {
	if (dispatch->gss_release_name)
	    (void)(*dispatch->gss_release_name)(&ignore, mech_name);
	return major;
    }

    new_name->is_imported = 0;
    new_name->is_mn = is_mn;

    if ((major = add_mech_name(minor_status, new_name, dispatch, mech_name))) {
	free_name(&new_name);
	return major;
    }

    *name_return = new_name;
    return complete(minor_status);
}

/* Creates a new PGSS name. */
static OM_uint32
alloc_name(minor_status, buffer, type, name_return)
    OM_uint32 *minor_status;
    const gss_buffer_t buffer;
    gss_OID type;
    struct pgss_name **name_return;
{
    OM_uint32 major;
    struct pgss_name *new_name;

    new_name = new(struct pgss_name);
    if (!new_name)
	return failure(minor_status, ENOMEM);

    if ((major = memdup_buffer(minor_status, buffer->value, 
	buffer->length, &new_name->data))) 
    {
	free(new_name);
	return major;
    }

    if ((major = dup_oid_pointer(minor_status, type, &new_name->type))) {
	(void)gss_release_buffer(NULL, &new_name->data);
	free(new_name);
	return major;
    }

    new_name->count = 0;
    new_name->element = NULL;
    new_name->is_mn = OID_EQUALS(type, GSS_C_NT_EXPORT_NAME);
    new_name->is_imported = 1;

    *name_return = new_name;

    return complete(minor_status);
}

/* Adds a mechanism name into a PGSS name. 
 * Takes ownership of the mech_name, meaning this function releases it if an 
 * error occurs, or if the pgss name is ever freed by free_name().
 */
static OM_uint32
add_mech_name(minor_status, name, dispatch, mech_name)
    OM_uint32 *minor_status;
    struct pgss_name *name;
    struct pgss_dispatch *dispatch;
    D_gss_name_t mech_name;
{
    OM_uint32 ignore;
    struct pgss_name_element *new_elements;

    if (name->count)
	new_elements = (struct pgss_name_element *)realloc(
		name->element, (name->count + 1) * sizeof *new_elements);
    else
	new_elements = new_array(struct pgss_name_element, 1);
    if (!new_elements) {
	if (!dispatch->gss_release_name)
	    (void)(*dispatch->gss_release_name)(&ignore, &mech_name);
	return failure(minor_status, ENOMEM);
    }

    name->element = new_elements;
    name->element[name->count].owner = dispatch;
    name->element[name->count].name = mech_name;
    name->count++;

    return complete(minor_status);
}

/*
 * Returns the first D_gss_name_t from a PGSS name. If none has been
 * cached, then the default mechanism is used to import it as a name type.
 */
static OM_uint32
get_any_mech_name(minor_status, name, dispatch_return, name_return)
    OM_uint32 *minor_status;
    struct pgss_name *name;
    struct pgss_dispatch **dispatch_return;
    D_gss_name_t *name_return;
{
    gss_OID mech;
    OM_uint32 major;
    struct pgss_dispatch *dispatch;
   
    if (name->count)
	dispatch = name->element[0].owner;
    else {
	if (!(mech = _pgss_get_default_mech()))
	    return error(minor_status, GSS_S_BAD_MECH, 0);
	if ((major = find_dispatch(minor_status, mech, &dispatch)))
	    return major;
    }
    if ((major = get_mech_name(minor_status, name, dispatch, name_return)))
	return major;
    if (dispatch_return)
	*dispatch_return = dispatch;
    return complete(minor_status);
}

/* 
 * Returns a provider D_gss_name_t from a PGSS name, suitable
 * for the given dispatch/provider. Performs an import_name if required.
 */
static OM_uint32
get_mech_name(minor_status, name, dispatch, name_return)
    OM_uint32 *minor_status;
    struct pgss_name *name;
    struct pgss_dispatch *dispatch;
    D_gss_name_t *name_return;
{
    OM_uint32 i, major, minor;
    D_gss_name_t mech_name;

    if (!name) {
	if (name_return)
	    *name_return = NULL;
	return complete(minor_status);
    }

    for (i = 0; i < name->count; i++)
	if (name->element[i].owner == dispatch) {
	    /*
	     * We have the original name or something
	     * we generated previously. Return that.
	     */
	    *name_return = name->element[i].name;
	    return complete(minor_status);
	}

    if (!name->is_imported)
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    if (!dispatch->gss_import_name)
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    if ((major = (*dispatch->gss_import_name)(&minor, &name->data,
	    name->type, &mech_name)))
	return error(minor_status, major, minor);

    if ((major = add_mech_name(minor_status, name, dispatch, mech_name)))
	return major;
    
    if (name_return)
	*name_return = mech_name;
    return complete(minor_status);
}

/* Releases storage for a PGSS name */
static void
free_name(name_return)
    struct pgss_name **name_return;
{
    OM_uint32 i, ignore;
    struct pgss_name *name = *name_return;

    if (!name)
	return;

    for (i = 0; i < name->count; i++)
	if (name->element[i].owner->gss_release_name)
	    (void)(*name->element[i].owner->gss_release_name)(&ignore,
		&name->element[i].name);

    if (name->element)
	free(name->element);

    if (name->is_imported) {
	free_oid_pointer(&name->type);
	gss_release_buffer(NULL, &name->data);
    }
    free(name);

    *name_return = NULL; 
}

/*
 * Allocates a cred structure with room for size cred pointers.
 * The caller is able to increment the length field up to the size
 * they requested.
 */
static OM_uint32
alloc_cred_id(minor_status, cred_return, size)
    OM_uint32 *minor_status;
    struct pgss_cred_id **cred_return;
    OM_uint32 size;
{
    struct pgss_cred_id *cred_id;

    cred_id = (struct pgss_cred_id *)malloc(sizeof *cred_id + 
	    (size - 1) * sizeof *cred_id->element);
    if (!cred_id)
	return failure(minor_status, ENOMEM);
    cred_id->count = 0;
    return complete(minor_status);
}

/*
 * Extracts a provider credential suitable for the given mechanism
 */
static OM_uint32
get_cred_by_mech(minor_status, cred, mech, cred_return)
    OM_uint32 *minor_status;
    struct pgss_cred_id *cred;
    gss_OID mech;
    D_gss_cred_id_t *cred_return;
{
    OM_uint32 i;

    if (!cred) {
	if (cred_return)
	    *cred_return = NULL;
	return complete(minor_status);
    }

    for (i = 0; i < cred->count; i++)
	if (OID_EQUALS(&cred->element[i].mech, mech)) {
	    if (cred_return)
		*cred_return = cred->element[i].cred;
	    return complete(minor_status);
	}

    return error(minor_status, GSS_S_BAD_MECH, 0);
}

/*
 * Releases storage for a cred_id structure.
 * DOES NOT RELEASE THE MECHANISM CREDS.
 */
static void
free_cred_id(cred_return)
    struct pgss_cred_id **cred_return;
{
    OM_uint32 i;

    for (i = 0; i < (*cred_return)->count; i++)
	free_oid(&(*cred_return)->element[i].mech);
    free(*cred_return);
    *cred_return = NULL;
}

/*
 * Resizes a pgss_cred_id structure to fit another credential.
 * On failure, makes no changes to the original credentials.
 * On success, replaces the cred_return pointer with the new pointer.
 */
static OM_uint32
append_cred_id(minor_status, cred_return, mech, cred)
    OM_uint32 *minor_status;
    struct pgss_cred_id **cred_return;
    gss_OID mech;
    void *cred;
{
    OM_uint32 major;
    struct pgss_cred_id *new_cred_id;

    /* Allocate slightly larger storgae */
    new_cred_id = (struct pgss_cred_id *)malloc(sizeof *new_cred_id + 
	    ((*cred_return)->count - 1 + 1) * sizeof *new_cred_id->element);
    if (!new_cred_id)
	return failure(minor_status, ENOMEM);

    /* Copy in the old elements */
    new_cred_id->count = (*cred_return)->count + 1;
    memcpy(new_cred_id->element, 
	    (*cred_return)->element,
	    (*cred_return)->count * sizeof *new_cred_id->element);

    /* Copy the mech OID of the newly appended element */
    if ((major = dup_oid(minor_status, mech, 
	&new_cred_id->element[new_cred_id->count - 1].mech)))
    {
	free(new_cred_id);
	return major;
    }

    /* Copying the cred doesn't require anything special */
    new_cred_id->element[new_cred_id->count - 1].cred = cred;

    /* Release the smaller structure */
    free(*cred_return);
    *cred_return = new_cred_id;

    return complete(minor_status);
}

OM_uint32
alloc_ctx(minor_status, dispatch, ctx, ctx_return)
    OM_uint32 *minor_status;
    struct pgss_dispatch *dispatch;
    D_gss_ctx_id_t ctx;
    struct pgss_ctx_id **ctx_return;
{
    struct pgss_ctx_id *new_ctx;
    OM_uint32 ignore;

    if (!ctx) 
	new_ctx = NULL;
    else {
	new_ctx = new(struct pgss_ctx_id);
	if (!new_ctx) {
	    if (dispatch->gss_delete_sec_context)
		(void)(*dispatch->gss_delete_sec_context)(&ignore, 
		    &ctx, GSS_C_NO_BUFFER);
	    return error(minor_status, GSS_S_FAILURE, ENOMEM);
	}
	new_ctx->owner= dispatch;
	new_ctx->ctx = ctx;
    }

    if (ctx_return)
	*ctx_return = new_ctx;

    return complete(minor_status);
}


/*------------------------------------------------------------
 * GSSAPI v2u1 multi-mech dispatch wrapper
 */

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
    OM_uint32 major;
    struct pgss_dispatch *dispatch;
    gss_OID mech, oid;
    int i, j;
    OM_uint32 trec, mintrec = GSS_C_INDEFINITE;
    OM_uint32 ignore;
    gss_OID_set acquired_mechs = GSS_C_NO_OID_SET;
    gss_OID_set actual_ret = GSS_C_NO_OID_SET;
    gss_OID_set desired;
    struct pgss_cred_id *creds = NULL;
    gss_OID_set_desc default_mech;

    if ((major = init(minor_status)))
	return major;

    if (actual_mechs) {
	if ((major = gss_create_empty_oid_set(minor_status, &acquired_mechs)))
	    return major;
    }

    /* If a desired_mech was not provided, then use the default mech */
    if (desired_mechs)
	desired = desired_mechs;
    else {
	mech = _pgss_get_default_mech();
	if (!mech) {
	    /* XXX There is no default mech; what do we do? */
	    major = error(minor_status, GSS_S_BAD_MECH, 0);
	    goto failed;
	}
	desired = make_singleton_oid_set(&default_mech, mech);
    } 

    if ((major = alloc_cred_id(minor_status, &creds, desired->count)))
	goto failed;

    /* Acquire creds for each of the listed mechs */
    for (i = 0; i < desired->count; i++) {
	gss_cred_id_t cred;
	gss_OID_set_desc dmech;

	mech = desired->elements + i;
	if ((major = find_dispatch(minor_status, mech, &dispatch)))
	    goto failed;

	if (!dispatch->gss_acquire_cred || !dispatch->gss_release_cred)
	{
	    major = error(minor_status, GSS_S_BAD_MECH, 0);
	    goto failed;
	}

	if ((major = (*dispatch->gss_acquire_cred)(minor_status, 
		desired_name, time_req, make_singleton_oid_set(&dmech, mech), 
		cred_usage, &creds->element[creds->count].cred,
		&actual_ret, time_rec ? &trec : NULL)))
	    goto failed;

	if ((major = dup_oid(minor_status, mech, 
			&creds->element[creds->count].mech)))
	{
	    if (dispatch->gss_release_oid_set)
		(void)(*dispatch->gss_release_oid_set)(&ignore, &actual_ret);
	    if (dispatch->gss_release_cred)
		(void)(*dispatch->gss_release_cred)(&ignore,
		    &creds->element[creds->count].cred);
	    goto failed;
	}
	creds->count++;

	/* 
	 * Accumulate the mechanisms for which the credential is valid.
	 * Since the provider may return OIDs of unconfigured mechs, 
	 * the unknown ones are stripped out.
	 */
	if (acquired_mechs)
	    for (j = 0; j < actual_ret->count; j++) 
	    {
		oid = actual_ret->elements + j;
		if (_pgss_config_find(oid)) {
		    major = gss_add_oid_set_member(minor_status, oid,
			&acquired_mechs);
		    if (major)
			break;
		}
	    }
	if (dispatch->gss_release_oid_set)
	    (void)(*dispatch->gss_release_oid_set)(&ignore, &actual_ret);

	if (major)
	    goto failed;

	/* Calculate minimum time the credentials remain valid */
	if (time_rec && (mintrec == GSS_C_INDEFINITE || mintrec > trec))
	    mintrec = trec;
    }

    *output_cred_handle = creds;
    creds = NULL;

    if (actual_mechs) {
	*actual_mechs = acquired_mechs;
	acquired_mechs = GSS_C_NO_OID_SET;
    }

    if (time_rec)
	*time_rec = mintrec;

    major = complete(minor_status);

failed:
    (void)gss_release_cred(NULL, &creds);
    (void)gss_release_oid_set(NULL, &acquired_mechs);
    return major;
}

/* Releases a cred_id wrapper */
OM_uint32
gss_release_cred(minor_status, cred_handle)
    OM_uint32 *minor_status;
    gss_cred_id_t *cred_handle;
{
    OM_uint32 major;
    struct pgss_dispatch *dispatch;
    int i;
    OM_uint32 minor;
    struct pgss_cred_id *creds;
    struct pgss_cred_element *el;

    if ((major = init(minor_status)))
	return major;

    if (*cred_handle == GSS_C_NO_CREDENTIAL)
	return complete(minor_status);

    creds = *cred_handle;
    while (creds->count) {
	/* 
	 * Loop invariant: The creds structure is valid, i.e. it 
	 * contains no released mechanism creds. 
	 * We do this by releasing creds from the end and decrementing 
	 * the count when the last has been properly released. 
	 * That means this loop can abort and the credentials are 
	 * still potentially usable.
	 */
	el = &creds->element[creds->count - 1];
	major = find_dispatch(minor_status, &el->mech, &dispatch);
	if (GSS_ERROR(major))
	    return major;
	if (dispatch->gss_release_cred) {
	    major = (*dispatch->gss_release_cred)(&minor, 
		    &creds->element[i].cred);
	    if (GSS_ERROR(major))
		return error(minor_status, major, minor);
	}
	free_oid(&el->mech);
	creds->count--;
    }
    free(creds);

    *cred_handle = GSS_C_NO_CREDENTIAL;
    return complete(minor_status);
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
    OM_uint32 major, major2, minor, ignore;
    gss_OID mech;
    struct pgss_dispatch *dispatch;
    D_gss_ctx_id_t *mech_ctx, new_mech_ctx;
    struct pgss_ctx_id *new_id = NULL;
    D_gss_name_t target;
    D_gss_cred_id_t init_cred;

    if ((major = init(minor_status)))
	return major;

    /* Find the right provider, or use the default */
    if (mech_type)
	mech = mech_type;
    else {
	mech = _pgss_get_default_mech();
	if (!mech)
	    return error(minor_status, GSS_S_BAD_MECH, 0);
    }
    if ((major = find_dispatch(minor_status, mech, &dispatch)))
	return major;

    if (*context_handle) {
	/* Don't mix providers */
	if ((*context_handle)->owner != dispatch)
	    return error(minor_status, GSS_S_BAD_MECH, 0);
	mech_ctx = &(*context_handle)->ctx;
    } else {
	/* A new context! */
	new_mech_ctx = GSS_C_NO_CONTEXT;
	mech_ctx = &new_mech_ctx;
    }

    if (!dispatch->gss_init_sec_context)
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    if ((major = get_mech_name(minor_status, target_name, dispatch, &target)))
	return major;

    if ((major = get_cred_by_mech(minor_status, initiator_cred_handle,
	    mech, &init_cred)))
	return major;

    /*
     * Initialise the output token to empty so that on 'failure',
     * the copyout_buffer() function won't try to copy/release something
     * potentially bogus
     */
    zero_buffer(output_token);

    minor = 0;
    major = (*dispatch->gss_init_sec_context)(&minor, init_cred, mech_ctx, 
	    target, mech, req_flags, time_req, input_chan_bindings, 
	    input_token, actual_mech_type, output_token, ret_flags, time_rec);
    if (GSS_ERROR(major))
	return error(minor_status, major, minor);

    /* Wrap new contexts. (Be careful to preserve value of 'major') */
    if (!*context_handle)
       if ((major2 = alloc_ctx(minor_status, dispatch, mech_ctx, 
		       context_handle)))
	{
	    if (output_token && dispatch->gss_release_buffer)
		(void)(*dispatch->gss_release_buffer)(&ignore, output_token);
	    return major2;
	}

    if ((major2 = copyout_buffer(minor_status, dispatch, output_token))) {
	(void)gss_delete_sec_context(NULL, context_handle, NULL);
	return major2;
    }

    if (minor_status)
	*minor_status = minor;
    return major;
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
    OM_uint32 major;

    if ((major = init(minor_status)))
	return major;

    return error(minor_status, GSS_S_UNAVAILABLE, 0);
    /* TBD */
}

OM_uint32
gss_process_context_token(minor_status, context_handle, token_buffer)
    OM_uint32 *minor_status;
    const gss_ctx_id_t context_handle;
    const gss_buffer_t token_buffer;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

OM_uint32
gss_delete_sec_context(minor_status, context_handle, output_token)
    OM_uint32 *minor_status;
    gss_ctx_id_t *context_handle;
    gss_buffer_t output_token;
{
    OM_uint32 major, minor;

    if ((major = init(minor_status)))
	return major;

    if (!*context_handle)
	return error(minor_status, GSS_S_NO_CONTEXT, 0);

    if (!(*context_handle)->owner->gss_delete_sec_context)
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    zero_buffer(output_token);
    if ((major = (*(*context_handle)->owner->gss_delete_sec_context)(&minor,
	    &(*context_handle)->ctx, output_token)))
	return error(minor_status, major, minor);

    /* The output_token is only valid for GSSAPIv1 */
    return copyout_buffer(minor_status, (*context_handle)->owner, output_token);
}

OM_uint32
gss_context_time(minor_status, context_handle, time_rec)
    OM_uint32 *minor_status;
    const gss_ctx_id_t context_handle;
    OM_uint32 *time_rec;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
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
    OM_uint32 major, minor;

    if ((major = init(minor_status)))
	return major;

    if (!context_handle)
	return error(minor_status, GSS_S_NO_CONTEXT, 0);

    if (context_handle->owner->gss_get_mic) 
	major = (*context_handle->owner->gss_get_mic)(&minor, 
		context_handle->ctx, qop_req, message_buffer, message_token);
    else if (context_handle->owner->gss_sign)
	major = (*context_handle->owner->gss_sign)(&minor, 
		context_handle->ctx, qop_req, message_buffer, message_token);
    else
	return error(minor_status, GSS_S_UNAVAILABLE, 0);
    
    if (major)
	return error(minor_status, major, minor);

    return copyout_buffer(minor_status, context_handle->owner, 
	    message_token);
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
    OM_uint32 major, minor;

    if ((major = init(minor_status)))
	return major;

    if (!context_handle)
	return error(minor_status, GSS_S_NO_CONTEXT, 0);

    if (context_handle->owner->gss_verify_mic)
	major = (*context_handle->owner->gss_verify_mic)(&minor,
		context_handle->ctx, message_buffer, token_buffer, qop_state);
    else if (context_handle->owner->gss_verify)
	major = (*context_handle->owner->gss_verify)(&minor,
		context_handle->ctx, message_buffer, token_buffer, qop_state);
    else
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    return error(minor_status, major, minor);
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
    OM_uint32 major, minor;

    if ((major = init(minor_status)))
	return major;

    if (!context_handle)
	return error(minor_status, GSS_S_NO_CONTEXT, 0);

    zero_buffer(output_message_buffer);

    if (context_handle->owner->gss_wrap)
	major = (*context_handle->owner->gss_wrap)(&minor,
	    context_handle->ctx, conf_req_flag, qop_req,
	    input_message_buffer, conf_state, output_message_buffer);
    else if (context_handle->owner->gss_seal)
	major = (*context_handle->owner->gss_seal)(&minor,
	    context_handle->ctx, conf_req_flag, (int)qop_req,
	    input_message_buffer, conf_state, output_message_buffer);
    else
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    if (major)
	return error(minor_status, major, minor);

    return copyout_buffer(minor_status, context_handle->owner, 
	    output_message_buffer);
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
    OM_uint32 major, minor;
    int qop_int;

    if ((major = init(minor_status)))
	return major;

    if (!context_handle)
	return error(minor_status, GSS_S_NO_CONTEXT, 0);

    zero_buffer(output_message_buffer);

    if (context_handle->owner->gss_unwrap)
	major = (*context_handle->owner->gss_unwrap)(&minor,
	    context_handle->ctx, input_message_buffer, 
	    output_message_buffer, conf_state, qop_state);
    else if (context_handle->owner->gss_unseal) {
	major = (*context_handle->owner->gss_unseal)(&minor,
	    context_handle->ctx, input_message_buffer, 
	    output_message_buffer, conf_state, qop_state ? &qop_int : NULL);
	if (!GSS_ERROR(major) && qop_state)
	    *qop_state = (gss_qop_t)qop_int;
    } else
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    if (major)
	return error(minor_status, major, minor);

    return copyout_buffer(minor_status, context_handle->owner, 
	    output_message_buffer);
}

/* Error message tables for gss_display_status() */
static const struct error_tab calling_errors[] = {
    { GSS_S_CALL_INACCESSIBLE_READ,  "A required input parameter could "
					"not be read" },
    { GSS_S_CALL_INACCESSIBLE_WRITE, "A required input parameter could "
					"not be written" },
    { GSS_S_CALL_BAD_STRUCTURE,      "A parameter was malformed" },
    { 0, 0 }
}, routine_errors[] = {
    { 0,                         "Successful completion" },
    { GSS_S_BAD_MECH,            "An unsupported mechanism was requested" },
    { GSS_S_BAD_NAME,            "An invalid name was supplied" },
    { GSS_S_BAD_NAMETYPE,        "A supplied name was of an unsupported type" },
    { GSS_S_BAD_BINDINGS,        "Incorrect channel bindings were supplied" },
    { GSS_S_BAD_STATUS,          "An invalid input status code was supplied" },
    { GSS_S_BAD_MIC,             "A token had an invalid MIC" },
    { GSS_S_NO_CRED,             "No credentials were supplied, or the "
				     "credentials were unavailable or "
				     "inaccessible" },
    { GSS_S_NO_CONTEXT,          "No context has been established" },
    { GSS_S_DEFECTIVE_TOKEN,     "A token was invalid" },
    { GSS_S_DEFECTIVE_CREDENTIAL,"A credential was invalid" },
    { GSS_S_CREDENTIALS_EXPIRED, "The referenced credentials have expired" },
    { GSS_S_CONTEXT_EXPIRED,     "The context has expired" },
    { GSS_S_FAILURE,             "Miscellaneous failure (see text)" },
    { GSS_S_BAD_QOP,             "The quality-of-protection requested could "
				     "not be provided" },
    { GSS_S_UNAUTHORIZED,        "The operation is forbidden "
				     "by local security policy" },
    { GSS_S_UNAVAILABLE,         "The operation or option is unavailable" },
    { GSS_S_DUPLICATE_ELEMENT,   "The requested credential element "
				     "already exists" },
    { GSS_S_NAME_NOT_MN,         "The provided name was not a mechanism name" },
    { 0, 0 }
}, supplementary_info[] = {
    { GSS_S_CONTINUE_NEEDED, "Continue needed" },
    { GSS_S_DUPLICATE_TOKEN, "The token was a duplicate of an earlier token" },
    { GSS_S_OLD_TOKEN,	     "The token's validity period has expired" },
    { GSS_S_UNSEQ_TOKEN,     "A later token has already been processed" },
    { GSS_S_GAP_TOKEN,	     "An expected per-message token was not received" },
    { 0, 0 }
};

/* Searches an error message table, returning the found message, or NULL */
static const char *
error_tab_search(tab, code)
    const struct error_tab *tab;
    OM_uint32 code;
{
    int i;

    for (i = 0; tab[i].text; i++)
	if (tab[i].code == code)
	    return tab[i].text;
    return NULL;
}

/* Maximum value of the major status display context */
#define MAX_CONTEXT \
	(sizeof supplementary_info / sizeof supplementary_info[0] - 1 + 2)

/*
 * Returns a status message for a given context integer, or NULL
 * For different values of context:
 *   0: the routine name, or "Unknown routine"
 *   1: the calling error, or NULL
 *   2..(MAX_CONTEXT-1): supplementary text or NULL
 */
static const char *
major_display_status_opt(OM_uint32 code, OM_uint32 context)
{
    const char *text;
    const struct error_tab *tab;

    assert(context < MAX_CONTEXT);

    switch (context) {
    case 0:
	text = error_tab_search(routine_errors, GSS_ROUTINE_ERROR(code));
	if (!text)
	    text = "Unknown routine";
	return text;
    case 1:
	return error_tab_search(calling_errors, GSS_CALLING_ERROR(code));
    default:
	tab = &supplementary_info[context - 2];
	if (GSS_SUPPLEMENTARY_INFO(code) & tab->code)
	    return tab->text;
	else
	    return NULL;
    }
}

/*
 * Determines the next status text for the given message_context.
 * Increments message_context, or sets it to zero if the returned
 * text is the last message.
 */
static OM_uint32
major_display_status(minor_status, status_value, message_context, status_string)
    OM_uint32 *minor_status;
    OM_uint32 status_value;
    OM_uint32 *message_context;
    gss_buffer_t status_string;
{
    OM_uint32 context = *message_context, next_context = 0;
    const char *text, *next_text;

    context = *message_context;

    /* 
     * First, get the next status message. Intermediate messages
     * may be NULL, in which case they are skipped.
     */
    while (context < MAX_CONTEXT) {
	text = major_display_status_opt(status_value, context);
	context++;
	if (text)
	    break;
    }

    /*
     * Look ahead to see if there will be a non-NULL future status message.
     * If not, then the next context integer will be zero to indicate
     * end of messages.
     */
    next_context = context;
    while (next_context < MAX_CONTEXT) {
	next_text = major_display_status_opt(status_value, next_context);
	next_context++;
	if (next_text)
	    break;
    }
    *message_context = next_context < MAX_CONTEXT ? context : 0;

    return strdup_buffer(minor_status, text, status_string);
}

/*
 * Returns a human-readable status message.
 * For GSS code types, this function is mechanism independent.
 * For mechanism code types, this function dispatches to the given
 * mechanism, or the default mechanism if none is given.
 */
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
    OM_uint32 major;
    struct pgss_dispatch *dispatch;
    int i;
    OM_uint32 minor;
    struct pgss_cred_id *creds;
    gss_OID effective_mech_type;

#if 0
    if (status_type == GSS_C_GSS_CODE)
	return major_display_status(minor_status, status_value,
	       	message_context, status_string);
    
    else if (status_type == GSS_C_MECH_CODE) {
#endif

	if ((major = init(minor_status)))
	    return major;

	/* If no mech is supplied, use the default mechanism */
	if (mech_type)
	    effective_mech_type = mech_type;
	else
	    effective_mech_type = _pgss_get_default_mech();

	/* If there is no default mechanism, then uh, I don't know. */
	if (!effective_mech_type)
	    return strdup_buffer(minor_status, "Unknown mechanism error", 
		    status_string);

	if ((major = find_dispatch(NULL, effective_mech_type, &dispatch)))
	    return major;

	/* Dispatch the minor error code display to the named mechanism */
	zero_buffer(status_string);
	if ((major = (*dispatch->gss_display_status)(&minor, status_value,
		status_type, mech_type, message_context, 
		status_string)))
	    return error(minor_status, major, minor);

	return copyout_buffer(minor_status, dispatch, status_string);
#if 0
    } 

    else
       	return error(minor_status, GSS_S_BAD_STATUS, 0);
#endif
}

/*
 * Returns the set of mechanisms recognised by this configuration of pgss.
 */
OM_uint32
gss_indicate_mechs(minor_status, mech_set)
    OM_uint32 *minor_status;
    gss_OID_set *mech_set;
{
    OM_uint32 major;
    void *iter;
    gss_OID mech;
    gss_OID_set result;

    if ((major = init(minor_status)))
	return major;

    if ((major = gss_create_empty_oid_set(minor_status, &result)))
	return major;

    /* 
     * Iterate over the configuration instructions, adding their mechanism 
     * OIDs, to the result set.
     */
    iter = 0;
    while (_pgss_config_next(&iter, &mech)) {
	major = gss_add_oid_set_member(minor_status, mech, &result);
	if (major) {
	    (void)gss_release_oid_set(NULL, &result);
	    return major;
	}
    }

    *mech_set = result;
    return complete(minor_status);
}

/* Compares two names for equality */
OM_uint32
gss_compare_name(minor_status, name1, name2, name_equal)
    OM_uint32 *minor_status;
    const gss_name_t name1;
    const gss_name_t name2;
    int *name_equal;
{
    OM_uint32 major, minor, ignore, i, j;

    if ((major = init(minor_status)))
	return major;

    if (!name1 || !name2)
	return error(minor_status, 
		GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ, 0);

    if (name1->count == 0 && name2->count == 0) {
	/* Force a default-mech import */
	(void)get_any_mech_name(NULL, name1, NULL, NULL);
	(void)get_any_mech_name(NULL, name2, NULL, NULL);
    }
    if (name1->count > 0 && name2->count == 0)
	(void)get_mech_name(NULL, name2, name1->element[0].owner, NULL);
    if (name2->count > 0 && name1->count == 0)
	(void)get_mech_name(NULL, name1, name2->element[0].owner, NULL);

    for (i = 0; i < name1->count; i++)
	for (j = 0; j < name2->count; j++)
	    if (name1->element[i].owner == name2->element[j].owner &&
		    name1->element[i].owner->gss_compare_name)
	    {
		major = (*name1->element[i].owner->gss_compare_name)(&minor,
		    name1->element[i].name, name2->element[j].name, name_equal);
		if (minor_status)
		    *minor_status = minor;
		return major;
	    }

    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

/* Display a name in a human-readable way */
OM_uint32
gss_display_name(minor_status, input_name, output_name_buffer, output_name_type)
    OM_uint32 *minor_status;
    const gss_name_t input_name;
    gss_buffer_t output_name_buffer;
    gss_OID *output_name_type;
{
    OM_uint32 major, minor;
    gss_OID mech;
    struct pgss_dispatch *dispatch;
    gss_OID type;

    if ((major = init(minor_status)))
	return major;

    if (input_name)
	return error(minor_status, 
		GSS_S_BAD_NAME | GSS_S_CALL_INACCESSIBLE_READ, 0);
    if (output_name_buffer)
	return error(minor_status, 
		GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_WRITE, 0);

    if (input_name->count == 0) {
	mech = _pgss_get_default_mech();
	if (!mech)
	    return error(minor_status, GSS_S_BAD_MECH, 0); /* XXX */
	if ((major = find_dispatch(minor_status, mech, &dispatch)))
	    return major;
	if ((major = get_mech_name(minor_status, input_name, dispatch, NULL)))
	    return major;
    }

    dispatch = input_name->element[0].owner;
    if (!dispatch->gss_display_name)
	return error(minor_status, GSS_S_UNAVAILABLE, 0);

    if ((major = (*dispatch->gss_display_name)(&minor,
	input_name->element[0].name, output_name_buffer, 
	output_name_type ? &type : NULL)))
    {
	if (minor_status)
	    *minor_status = minor;
	return major;
    }

    major = copyout_buffer(minor_status, dispatch, output_name_buffer);
    if (!major && output_name_type)
	*output_name_type = type;

    return major;
}

OM_uint32
gss_import_name(minor_status, input_name_buffer, input_name_type, output_name)
    OM_uint32 *minor_status;
    const gss_buffer_t input_name_buffer;
    const gss_OID input_name_type;
    gss_name_t *output_name;
{
    OM_uint32 major;

    if ((major = init(minor_status)))
	return major;

    return alloc_name(minor_status, input_name_buffer, input_name_type,
	    output_name);
}

OM_uint32
gss_export_name(minor_status, input_name, exported_name)
    OM_uint32 *minor_status;
    const gss_name_t input_name;
    gss_buffer_t exported_name;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

OM_uint32
gss_release_name(minor_status, input_name)
    OM_uint32 *minor_status;
    gss_name_t *input_name;
{
    OM_uint32 major;

    if ((major = init(minor_status)))
	return major;

    free_name(input_name);
    return complete(minor_status);
}

OM_uint32
gss_release_buffer(minor_status, buffer)
    OM_uint32 *minor_status;
    gss_buffer_t buffer;
{
    OM_uint32 major;

    if ((major = init(minor_status)))
	return major;

    if (buffer && buffer->value)
	free(buffer->value);
    zero_buffer(buffer);
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
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
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
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
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
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
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
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
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
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

OM_uint32
gss_export_sec_context(minor_status, context_handle, interprocess_token)
    OM_uint32 *minor_status;
    gss_ctx_id_t *context_handle;
    gss_buffer_t interprocess_token;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

OM_uint32
gss_import_sec_context(minor_status, interprocess_token, context_handle)
    OM_uint32 *minor_status;
    const gss_buffer_t interprocess_token;
    gss_ctx_id_t *context_handle;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

/*
 * Allocates storage for an empty gss_OID_set.
 * (Mechanism independent)
 */
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

/* 
 * Adds a gss_OID to a gss_OID_set, re-allocating the set if needed.
 * (Mechanism-independent)
 */
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

    if (member_oid == GSS_C_NO_OID) 
	return error(minor_status, 
		GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_READ, 0);
   
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
    return complete(minor_status);
}

OM_uint32
gss_inquire_names_for_mech(minor_status, mechanism, name_types)
    OM_uint32 *minor_status;
    const gss_OID mechanism;
    gss_OID_set *name_types;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

OM_uint32
gss_inquire_mechs_for_name(minor_status, input_name, mech_types)
    OM_uint32 *minor_status;
    const gss_name_t input_name;
    gss_OID_set *mech_types;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

OM_uint32
gss_canonicalize_name(minor_status, input_name, mech_type, output_name)
    OM_uint32 *minor_status;
    const gss_name_t input_name;
    const gss_OID mech_type;
    gss_name_t *output_name;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

OM_uint32
gss_duplicate_name(minor_status, src_name, dest_name)
    OM_uint32 *minor_status;
    const gss_name_t src_name;
    gss_name_t *dest_name;
{
    /* TBD */
    return error(minor_status, GSS_S_UNAVAILABLE, 0);
}

/*
 * Deprecated GSSv1 functions: map to new GSSv2 operations.
 * If the underlying provider only does GSSv1, then the mapping will
 * be reversed.
 */

OM_uint32
gss_sign(minor_status, context_handle, qop_req, message_buffer,
        message_token)
    OM_uint32 *minor_status;
    gss_ctx_id_t context_handle;
    int qop_req;
    gss_buffer_t message_buffer;
    gss_buffer_t message_token;
{
    return gss_get_mic(minor_status, context_handle, qop_req, message_buffer, 
        message_token);
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
    return gss_verify_mic(minor_status, context_handle, message_buffer, 
        token_buffer, qop_state);
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
    return gss_wrap(minor_status, context_handle, conf_req_flag, 
	(gss_qop_t)qop_req, input_message_buffer, conf_state, 
	output_message_buffer);
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
    OM_uint32 major;
    gss_qop_t qop;
    
    major = gss_unwrap(minor_status, context_handle, input_message_buffer, 
        output_message_buffer, conf_state, qop_state ? &qop : NULL);
    if (qop_state && !GSS_ERROR(major))
	*qop_state = (int)qop;
    return major;
}

/* Deprecated non-standard functions */

OM_uint32
gss_str_to_oid(minor_status, oid_str, oid_return)
    OM_uint32 *minor_status;
    gss_buffer_t oid_str;
    gss_OID *oid_return;
{
    gss_buffer_desc der_buf;
    gss_OID oid;

    if (!oid_str)
	return error(minor_status, 
		GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_READ, 0);

    zero_buffer(&der_buf);
    *oid_return = GSS_C_NO_OID;

    switch (_pgss_str_to_oid(oid_str, &der_buf)) {
    case -1:
	return failure_from_errno(minor_status, ENOMEM);
    case 0:
	return error(minor_status, 
		GSS_S_FAILURE | GSS_S_CALL_BAD_STRUCTURE, 0);
    }

    oid = new(gss_OID_desc);
    if (!oid) {
	(void)gss_release_buffer(NULL, &der_buf);
	return failure_from_errno(minor_status, ENOMEM);
    }

    oid->elements = der_buf.value;
    oid->length = der_buf.length;
    *oid_return = oid;
    return complete(minor_status);
}

OM_uint32
gss_release_oid(minor_status, oid)
    OM_uint32 *minor_status;
    gss_OID *oid;
{
    if (*oid) {
	free((*oid)->elements);
	free(*oid);
	*oid = GSS_C_NO_OID;
    }
    return complete(minor_status);
}

OM_uint32
gss_oid_to_str(minor_status, oid, str)
    OM_uint32 *minor_status;
    gss_OID oid;
    gss_buffer_t str;
{
    if (!oid)
	return error(minor_status, 
		GSS_S_FAILURE | GSS_S_CALL_INACCESSIBLE_READ, 0);
    zero_buffer(str);

    switch(_pgss_oid_to_str(oid, str)) {
    case -1:
	return failure_from_errno(minor_status, ENOMEM);
    case 0:
	return error(minor_status, 
		GSS_S_FAILURE | GSS_S_CALL_BAD_STRUCTURE, 0);
    }

    return complete(minor_status);
}

