/**
 ** PHP Extension for Quest Software, Inc. Vintela Authentication Services.
 **
 ** Copyright (c) 2006, 2007 Quest Software, Inc.
 **
 **/

#define SPE_DEBUG

#ifdef __cplusplus
extern "C" {
#endif

#include "zend.h"
#include "zend_API.h"
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_vas.h"

typedef struct group    sys_group_t;

/*
 * These TSRMLS_ definitions should already be available now, but with older
 * PHP under Red Hat are not. This affects the last argument in the wrapped
 * (zif) function argument list defined by INTERNAL_FUNCTION_PARAMETERS. These
 * #define out the executor_globals (search in this file on this term).
 */
#ifndef TSRMLS_D
# define TSRMLS_D
#endif
#ifndef TSRMLS_DC
# define TSRMLS_DC
#endif
#ifndef TSRMLS_C
# define TSRMLS_C
#endif
#ifndef TSRMLS_CC
# define TSRMLS_CC
#endif

#ifdef __cplusplus
}
#endif

#define PHP_vas_ctx_t_RES_NAME "vas_ctx_t"
static int              le_vas_ctx_t;
static zend_class_entry *vas_CVAS_passwd_entry;
static zend_class_entry *vas_CVAS_err_info_entry;

ZEND_DECLARE_MODULE_GLOBALS(vas)

#ifdef SPE_DEBUG
# define ZEND_PRINTF    zend_printf
void SPEPRINTF( const char *format, ... );
void SPEPRINTF( const char *format, ... )
{
    va_list ap;
    va_start( ap, format );
    vprintf( format, ap );
    va_end( ap );
}
#else
# define ZEND_PRINTF    SPEPRINTF
void SPEPRINTF( void *arg, ... );
void SPEPRINTF( void *arg, ... )
{
    /*EMPTY*/
}
#endif

#ifdef SPE_DEBUG
# define SPE_zend_error zend_error
#else
# define SPE_zend_error(a, b, c)
#endif

static void vas_attrs_t_free( vas_ctx_t *ctx, vas_attrs_t *object )
{
    vas_attrs_free( ctx, object );
}

static void vas_id_t_free( vas_ctx_t *ctx, vas_id_t *object )
{
    vas_id_free( ctx, object );
}

static void vas_auth_t_free( vas_ctx_t *ctx, vas_auth_t *object )
{
    vas_auth_free( ctx, object );
}

static void vas_user_t_free( vas_ctx_t *ctx, vas_user_t *object )
{
    vas_user_free( ctx, object );
}

static void vas_group_t_free( vas_ctx_t *ctx, vas_group_t *object )
{
    vas_group_free( ctx, object );
}

static void sys_group_t_free( vas_ctx_t *ctx, sys_group_t *object )
{
    /* This is standard struct group including its string pointers which
     * vas_group_get_grinfo() has allocated in a single, continguous buffer.
     */
    free( object );
}

static void vas_service_t_free( vas_ctx_t *ctx, vas_service_t *object )
{
    vas_service_free( ctx, object );
}

static void vas_computer_t_free( vas_ctx_t *ctx, vas_computer_t *object )
{
    vas_computer_free( ctx, object );
}

static void gss_release_cred_internal( vas_ctx_t *ctx, gss_cred_id_t* cred_handle )
{
    OM_uint32 minor_status;
    gss_release_cred( &minor_status, cred_handle );
}

static void gss_delete_sec_context_internal( vas_ctx_t *ctx, gss_ctx_id_t* cred_handle )
{
    /* These are now deleted when the ctx is deleted and deinitialize is called
     * OM_uint32 minor_status;
     * gss_delete_sec_context(&minor_status, cred_handle, GSS_C_NO_BUFFER);
     */
}

#if 0
static void gss_release_buffer_internal( vas_ctx_t *ctx, gss_buffer_t buffer )
{
  /* Note that the gss_release_buffer is actually done when this object is
   * created.
   */
  efree(buffer->value);
}
#endif

static void krb5_free_keyblock_internal( vas_ctx_t *ctx, krb5_keyblock *key )
{
    krb5_context kctx;
    vas_krb5_get_context( ctx, &kctx );

    krb5_free_keyblock( kctx, key );
}

static void krb5_free_context_internal( vas_ctx_t *ctx, krb5_context *kctx )
{
    /*EMPTY*/
}

static void krb5_free_principal_internal( vas_ctx_t *ctx, krb5_principal *princ )
{
    /*EMPTY*/
}

static void krb5_free_ccache_internal( vas_ctx_t *ctx, krb5_ccache *cc )
{
    /*EMPTY*/
}

static void krb5_free_creds_internal( vas_ctx_t *ctx, krb5_creds *creds )
{
    krb5_context kctx;
    vas_krb5_get_context( ctx, &kctx );

    krb5_free_creds( kctx, creds );
}

static void free_ldap_internal( vas_ctx_t *ctx, LDAP *ld )
{
    ldap_unbind( ld );
}

/* SPE_vas_groups_list_t represents a linked list of vas_group_t ** pointers.
 * These are the return values from vas_user_get_groups(). That function
 * returns a vector of vas_group_t's and we copy the groups into our resources.
 * These resources must be free'd by calling vas_group_free_groups() or there
 * will be a leak of the ** pointers.
 *
 * We will defer the free until we finally free the ctx.
 */
typedef struct SPE_vas_groups_list_t
{
    vas_group_t                  **groups;
    struct SPE_vas_groups_list_t *next;
} SPE_vas_groups_list_t;

/* SPE_vas_gss_ctx_list_t is similar to the groups list above but has a
 * different purpose. It has been discovered that if a gss_ctx_id_t is released
 * before its associated gss_cred_id_t(s) that the release of the cred_id_t(s)
 * will fault. This defers the releasing of the gss_ctx_id_t(s).
 */
typedef struct SPE_vas_gss_ctx_list_t
{
    gss_ctx_id_t                  gssctx;
    struct SPE_vas_gss_ctx_list_t *next;
} SPE_vas_gss_ctx_list_t;

typedef struct
{
    vas_ctx_t              *ctx;
    unsigned int           referenceCount;
    SPE_vas_groups_list_t  *groups_list;
    unsigned char          freeGSS;  /* set true if calling vas_gss_deinitialize */
    SPE_vas_gss_ctx_list_t *gssctx_list;
} SPE_vas_ctx_t;

static void SPE_add_groups( SPE_vas_ctx_t *ctx, vas_group_t **groups )
{
  SPE_vas_groups_list_t *g =
      ( SPE_vas_groups_list_t * ) emalloc( sizeof( SPE_vas_groups_list_t ) );

  g->next = ctx->groups_list;
  g->groups = groups;
  ctx->groups_list = g;
}

static void SPE_free_groups( SPE_vas_ctx_t *ctx )
{
    SPE_vas_groups_list_t *p = ctx->groups_list;

    while( p )
    {
        SPE_vas_groups_list_t *n = p->next;
        ZEND_PRINTF( "_____Freeing groups at %p (%p)\n", p, p->groups );
        vas_group_free_groups( ctx->ctx, p->groups );
        efree( p );
        p = n;
    }
}

static void SPE_add_gss_ctx( SPE_vas_ctx_t *ctx, gss_ctx_id_t gssctx )
{
    SPE_vas_gss_ctx_list_t *g =
        ( SPE_vas_gss_ctx_list_t * )emalloc( sizeof( SPE_vas_gss_ctx_list_t ) );

    ZEND_PRINTF( "_____Adding gssctx %p to list\n", gssctx );
    g->next = ctx->gssctx_list;
    g->gssctx = gssctx;
    ctx->gssctx_list = g;
}

static void SPE_remove_gss_ctx( SPE_vas_ctx_t *ctx, gss_ctx_id_t gssctx )
{
    SPE_vas_gss_ctx_list_t *prev = NULL;
    SPE_vas_gss_ctx_list_t *next = ctx->gssctx_list;

    ZEND_PRINTF( "_____Removing gssctx %p from list\n", gssctx );

startover:
    for( next = ctx->gssctx_list; next; prev = next, next = next->next )
    {
        if( next->gssctx == gssctx )
        {
            if( prev )
            {  /* delete item in middle */
                prev->next = next->next;
                efree( next );
                next = prev;
            }
            else
            {
                ctx->gssctx_list = next->next;
                efree( next );
                goto startover;
            }
        }
    }
}

static void SPE_free_gss_ctx( SPE_vas_ctx_t *ctx )
{
    SPE_vas_gss_ctx_list_t *p = ctx->gssctx_list;

    while( p )
    {
        OM_uint32 minor_status;
        SPE_vas_gss_ctx_list_t *n = p->next;

        ZEND_PRINTF( "_____Freeing gss_ctx_id %p at %p\n", p, p->gssctx );
        gss_delete_sec_context( &minor_status, &( p->gssctx ), GSS_C_NO_BUFFER );
        efree( p );
        p = n;
    }
}

static vas_err_t SPE_vas_ctx_alloc( SPE_vas_ctx_t **vc )
{
    vas_ctx_t *ctx = NULL;
    vas_err_t err = vas_ctx_alloc( &ctx );

    if( err == VAS_ERR_SUCCESS )
    {
        *vc = ( SPE_vas_ctx_t * ) emalloc( sizeof( SPE_vas_ctx_t ) );

        ( *vc )->referenceCount = 1;
        ( *vc )->ctx            = ctx;
        ( *vc )->groups_list    = NULL;
        ( *vc )->freeGSS        = 0;
        ( *vc )->gssctx_list    = NULL;
        ZEND_PRINTF( "_____Allocated SPE_vas_ctx %p (%p)\n", *vc, ctx );
    }
    return err;
}

static void SPE_vas_ctx_free( SPE_vas_ctx_t *spe_vas_ctx )
{
    ZEND_PRINTF( "_____Cleaning up SPE_vas_ctx_free %p, reference count %d\n",
               spe_vas_ctx, spe_vas_ctx->referenceCount );

    if( spe_vas_ctx && spe_vas_ctx->referenceCount > 0 )
    {
        if( --spe_vas_ctx->referenceCount == 0 )
        {
            ZEND_PRINTF( "_____Cleaning up vas_ctx_free on %p (%p)\n",
                       spe_vas_ctx, spe_vas_ctx->ctx );

            SPE_free_groups( spe_vas_ctx );
            SPE_free_gss_ctx( spe_vas_ctx );

            if( spe_vas_ctx->freeGSS )
                vas_gss_deinitialize( spe_vas_ctx->ctx );

            vas_ctx_free( spe_vas_ctx->ctx );
            efree( spe_vas_ctx );
        }
    }

    ZEND_PRINTF( "_____Free done (%p)\n", spe_vas_ctx );
}

static void php_vas_ctx_t_dtor( zend_rsrc_list_entry *rsrc TSRMLS_DC )
{
    SPE_vas_ctx_t *spe_vas_ctx = ( SPE_vas_ctx_t* ) rsrc->ptr;

    ZEND_PRINTF( "_____Cleaning up vas_ctx_dtor (%p)\n", spe_vas_ctx );

    SPE_vas_ctx_free( spe_vas_ctx );
}

#define SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER( TYPE, FREE )                \
    static char *PHP_##TYPE##_RES_NAME = #TYPE;                             \
    static int le_##TYPE;                                                   \
    typedef struct                                                          \
    {                                                                       \
        SPE_vas_ctx_t *ctx;                                                 \
        TYPE           raw;                                                 \
        unsigned char  noFree;                                              \
    } SPE_##TYPE;                                                           \
    static void php_##TYPE##_dtor( zend_rsrc_list_entry *rsrc TSRMLS_DC )   \
    {                                                                       \
        SPE_##TYPE *thing = ( SPE_##TYPE * ) rsrc->ptr;                     \
        ZEND_PRINTF( "_____Cleaning up " #TYPE "_dtor %p, noFree=%d\n",     \
                   thing, thing->noFree );                                  \
        if( thing && thing->raw )                                           \
        {                                                                   \
            if( thing->noFree == 0 )                                        \
            {                                                               \
                FREE( thing->ctx->ctx, &( thing->raw ) );                   \
            }                                                               \
            SPE_vas_ctx_free( thing->ctx );                                 \
            efree( thing );                                                 \
        }                                                                   \
    }

#define SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER_BY_VALUE( TYPE, FREE )       \
    static char* PHP_##TYPE##_RES_NAME = #TYPE;                             \
    static int le_##TYPE;                                                   \
    typedef struct                                                          \
    {                                                                       \
        SPE_vas_ctx_t *ctx;                                                 \
        TYPE          raw;                                                  \
        unsigned char noFree;                                               \
    } SPE_##TYPE;                                                           \
    static void php_##TYPE##_dtor( zend_rsrc_list_entry *rsrc TSRMLS_DC )   \
    {                                                                       \
        SPE_##TYPE *thing = ( SPE_##TYPE * ) rsrc->ptr;                     \
        ZEND_PRINTF( "_____Cleaning up " #TYPE "_dtor %p, noFree=%d\n",     \
                   thing, thing->noFree );                                  \
        if( thing && thing->raw )                                           \
        {                                                                   \
            if( thing->noFree == 0 )                                        \
            {                                                               \
                FREE( thing->ctx->ctx, thing->raw );                        \
            }                                                               \
            SPE_vas_ctx_free(thing->ctx);                                   \
            efree( thing );                                                 \
        }                                                                   \
    }

#define SPE_DECLARE_DTOR_USING_CTX2( TYPE, FREE )                           \
    static char *PHP_##TYPE##_RES_NAME = #TYPE;                             \
    static int le_##TYPE;                                                   \
    typedef struct                                                          \
    {                                                                       \
        SPE_vas_ctx_t *ctx;                                                 \
        TYPE          *raw;                                                 \
        unsigned char noFree;                                               \
    } SPE_##TYPE;                                                           \
    static void php_##TYPE##_dtor( zend_rsrc_list_entry *rsrc TSRMLS_DC )   \
    {                                                                       \
        SPE_##TYPE *thing = ( SPE_##TYPE* ) rsrc->ptr;                      \
        ZEND_PRINTF( "_____Cleaning up " #TYPE "_dtor %p, noFree=%d\n",     \
                   thing, thing->noFree );                                  \
        if( thing && thing->raw )                                           \
        {                                                                   \
            if( thing->noFree == 0 )                                        \
            {                                                               \
                FREE( thing->ctx->ctx, thing->raw );                        \
            }                                                               \
            SPE_vas_ctx_free( thing->ctx );                                 \
            efree( thing );                                                 \
        }                                                                   \
    }

#define SPE_DECLARE_DTOR_USING_CTX( TYPE )                                  \
    SPE_DECLARE_DTOR_USING_CTX2( TYPE, TYPE##_free )

#define SPE_REGISTER_DTOR( TYPE )                                           \
    le_##TYPE = zend_register_list_destructors_ex( php_##TYPE##_dtor, NULL, \
                        PHP_##TYPE##_RES_NAME, module_number )

#define SPE_CONS_VALUE( VARIABLE, TYPE, VAR )                               \
    {                                                                       \
        SPE_##TYPE *thing;                                                  \
        thing         = ( SPE_##TYPE * ) emalloc( sizeof( SPE_##TYPE ) );   \
        thing->ctx    = ctx; thing->ctx->referenceCount++;                  \
        thing->raw    = VAR;                                                \
        thing->noFree = 0;                                                  \
        ZEND_REGISTER_RESOURCE( VARIABLE, thing, le_##TYPE );               \
    }

#define SPE_CONS_RETURN_VALUE( TYPE, VAR )                                  \
    {                                                                       \
        SPE_CONS_VALUE( return_value, TYPE, VAR );                          \
    }

#define SPE_CHECK_ARGS( n )                                                 \
    {                                                                       \
        int argbase = 0;                                                    \
        if( this_ptr && this_ptr->type==IS_OBJECT ) { argbase++; }          \
        if( ZEND_NUM_ARGS() + argbase != ( n ) ) { WRONG_PARAM_COUNT; }     \
    }

/*  || ( zend_get_parameters_array_ex( 1 - argbase, args ) != SUCCESS ) */

#define SPE_SET_VAS_ERR( code )                                             \
    {                                                                       \
        VAS_G( g_vas_err ) = ( code );                                      \
    }

#define SPE_SET_VAS_ERR2( code, minor )                                     \
    {                                                                       \
        VAS_G( g_vas_err ) = ( code );                                      \
        VAS_G( g_vas_err_minor ) = ( minor );                               \
    }

#define SPE_CHOKE_PARAMS()                                                  \
    {                                                                       \
        SPE_zend_error( E_WARNING, "Invalid option parameters %s()",        \
                        get_active_function_name( TSRMLS_C ) );             \
        SPE_SET_VAS_ERR( VAS_ERR_INVALID_PARAM );                           \
        /* Throw INVALID_PARAM error on ctx */                              \
        vas_id_alloc( ctx->ctx, NULL, NULL );                               \
    }

#define RAW( x ) ( ( ( x ) == NULL ) ? NULL : ( x )->raw )

SPE_DECLARE_DTOR_USING_CTX( vas_attrs_t );
SPE_DECLARE_DTOR_USING_CTX( vas_id_t );
SPE_DECLARE_DTOR_USING_CTX( vas_auth_t );
SPE_DECLARE_DTOR_USING_CTX( vas_user_t );
SPE_DECLARE_DTOR_USING_CTX( vas_group_t );
SPE_DECLARE_DTOR_USING_CTX( sys_group_t );
SPE_DECLARE_DTOR_USING_CTX( vas_service_t );
SPE_DECLARE_DTOR_USING_CTX( vas_computer_t );

SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER( gss_cred_id_t, gss_release_cred_internal );
SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER( gss_ctx_id_t, gss_delete_sec_context_internal );
/* SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER_BY_VALUE( gss_buffer_t, gss_release_buffer_internal ); */
SPE_DECLARE_DTOR_USING_CTX2( krb5_keyblock, krb5_free_keyblock_internal );
SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER( krb5_context, krb5_free_context_internal );
SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER( krb5_principal, krb5_free_principal_internal );
SPE_DECLARE_DTOR_USING_CTX2_NO_POINTER( krb5_ccache, krb5_free_ccache_internal );
SPE_DECLARE_DTOR_USING_CTX2( krb5_creds, krb5_free_creds_internal );
SPE_DECLARE_DTOR_USING_CTX2( LDAP, free_ldap_internal );

/*
extern gss_OID GSS_C_NT_USER_NAME;
extern gss_OID GSS_C_NT_MACHINE_UID_NAME;
extern gss_OID GSS_C_NT_STRING_UID_NAME;
extern gss_OID GSS_C_NT_HOSTBASED_SERVICE_X;
extern gss_OID GSS_C_NT_HOSTBASED_SERVICE;
extern gss_OID GSS_C_NT_ANONYMOUS;
extern gss_OID GSS_C_NT_EXPORT_NAME;
extern gss_OID GSS_SPNEGO_MECHANISM;
*/

#if PHP_MAJOR_VERSION == 5
/* TODO: php5 doesn't have these definitions, but perhaps this is done
 * differently there? See definition of macro ZEND_VAS2() for PHP-5.
 */
#define BYREF_NONE          0
#define BYREF_FORCE         1
#define BYREF_ALLOW         2
#define BYREF_FORCE_REST    3

#endif

static unsigned char vas_id_get_name_arginfo[] =
    { 4, BYREF_ALLOW, BYREF_ALLOW, BYREF_FORCE, BYREF_FORCE };

static unsigned char vas_info_domains_arginfo[] =
    { 4, BYREF_ALLOW, BYREF_ALLOW, BYREF_FORCE, BYREF_FORCE };

static unsigned char vas_info_forest_root_arginfo[] =
    { 3, BYREF_ALLOW, BYREF_FORCE, BYREF_FORCE };

static unsigned char vas_info_joined_domain_arginfo[] =
    { 3, BYREF_ALLOW, BYREF_FORCE, BYREF_FORCE };

static unsigned char vas_name_to_dn_arginfo[] =
    { 7, BYREF_ALLOW, BYREF_ALLOW, BYREF_ALLOW, BYREF_ALLOW, BYREF_ALLOW,
         BYREF_FORCE, BYREF_FORCE };

static unsigned char vas_gss_spnego_initiate_arginfo[] =
    { 9, BYREF_ALLOW, BYREF_ALLOW, BYREF_ALLOW, BYREF_FORCE, BYREF_ALLOW,
         BYREF_ALLOW, BYREF_ALLOW, BYREF_ALLOW, BYREF_FORCE };

static unsigned char vas_gss_spnego_accept_arginfo[] =
    { 9, BYREF_ALLOW, BYREF_ALLOW, BYREF_FORCE, BYREF_FORCE, BYREF_FORCE,
         BYREF_ALLOW, BYREF_ALLOW, BYREF_FORCE, BYREF_FORCE };

static unsigned char vas_gss_krb5_get_subkey_arginfo[] =
    { 3, BYREF_ALLOW, BYREF_ALLOW, BYREF_FORCE };

ZEND_VAS_ARG_INFO( vas_err_internal );
ZEND_VAS_ARG_INFO( vas_err_minor_internal );
ZEND_VAS_ARG_INFO( vas_ctx_alloc );
ZEND_VAS_ARG_INFO( vas_ctx_set_option );
ZEND_VAS_ARG_INFO( vas_ctx_get_option );
ZEND_VAS_ARG_INFO( vas_id_alloc );
ZEND_VAS_ARG_INFO( vas_id_get_ccache_name );
ZEND_VAS_ARG_INFO( vas_id_get_keytab_name );
ZEND_VAS_ARG_INFO( vas_id_get_name );
ZEND_VAS_ARG_INFO( vas_id_get_user );
ZEND_VAS_ARG_INFO( vas_id_is_cred_established );
ZEND_VAS_ARG_INFO( vas_id_establish_cred_password );
ZEND_VAS_ARG_INFO( vas_id_establish_cred_keytab );
ZEND_VAS_ARG_INFO( vas_id_renew_cred );
ZEND_VAS_ARG_INFO( vas_auth );
ZEND_VAS_ARG_INFO( vas_auth_with_password );
ZEND_VAS_ARG_INFO( vas_attrs_alloc );
ZEND_VAS_ARG_INFO( vas_attrs_find );
ZEND_VAS_ARG_INFO( vas_attrs_find_continue );
ZEND_VAS_ARG_INFO( vas_attrs_set_option );
ZEND_VAS_ARG_INFO( vas_vals_get_string );
ZEND_VAS_ARG_INFO( vas_vals_get_integer );
ZEND_VAS_ARG_INFO( vas_vals_get_binary );
ZEND_VAS_ARG_INFO( vas_vals_get_anames );
ZEND_VAS_ARG_INFO( vas_vals_get_dn );
ZEND_VAS_ARG_INFO( vas_name_to_principal );
ZEND_VAS_ARG_INFO( vas_name_to_dn );
ZEND_VAS_ARG_INFO( vas_info_forest_root );
ZEND_VAS_ARG_INFO( vas_info_joined_domain );
ZEND_VAS_ARG_INFO( vas_info_site );
ZEND_VAS_ARG_INFO( vas_info_domains );
ZEND_VAS_ARG_INFO( vas_info_servers );
ZEND_VAS_ARG_INFO( vas_prompt_for_cred_string );
ZEND_VAS_ARG_INFO( vas_err_get_code );
ZEND_VAS_ARG_INFO( vas_err_get_string );
ZEND_VAS_ARG_INFO( vas_err_clear );
ZEND_VAS_ARG_INFO( vas_err_get_info );
ZEND_VAS_ARG_INFO( vas_err_info_get_string );
ZEND_VAS_ARG_INFO( vas_err_get_cause_by_type );
ZEND_VAS_ARG_INFO( vas_user_init );
ZEND_VAS_ARG_INFO( vas_user_is_member );
ZEND_VAS_ARG_INFO( vas_user_get_groups );
ZEND_VAS_ARG_INFO( vas_user_get_attrs );
ZEND_VAS_ARG_INFO( vas_user_get_dn );
ZEND_VAS_ARG_INFO( vas_user_get_sam_account_name );
ZEND_VAS_ARG_INFO( vas_user_get_sid );
ZEND_VAS_ARG_INFO( vas_user_get_upn );
ZEND_VAS_ARG_INFO( vas_user_get_pwinfo );
ZEND_VAS_ARG_INFO( vas_user_get_krb5_client_name );
ZEND_VAS_ARG_INFO( vas_user_get_account_control );
ZEND_VAS_ARG_INFO( vas_user_check_access );
ZEND_VAS_ARG_INFO( vas_user_check_conflicts );
ZEND_VAS_ARG_INFO( vas_group_init );
ZEND_VAS_ARG_INFO( vas_group_has_member );
ZEND_VAS_ARG_INFO( vas_group_get_attrs );
ZEND_VAS_ARG_INFO( vas_group_get_dn );
ZEND_VAS_ARG_INFO( vas_group_get_sid );
#if VAS_API_IS(4,2)
ZEND_VAS_ARG_INFO( vas_group_get_grinfo );
#endif
ZEND_VAS_ARG_INFO( vas_service_init );
ZEND_VAS_ARG_INFO( vas_service_get_attrs );
ZEND_VAS_ARG_INFO( vas_service_get_dn );
ZEND_VAS_ARG_INFO( vas_service_get_krb5_client_name );
ZEND_VAS_ARG_INFO( vas_service_get_spns );
ZEND_VAS_ARG_INFO( vas_service_get_upn );
ZEND_VAS_ARG_INFO( vas_computer_init );
ZEND_VAS_ARG_INFO( vas_computer_is_member );
ZEND_VAS_ARG_INFO( vas_computer_get_attrs );
ZEND_VAS_ARG_INFO( vas_computer_get_dn );
ZEND_VAS_ARG_INFO( vas_computer_get_dns_hostname );
ZEND_VAS_ARG_INFO( vas_computer_get_sid );
ZEND_VAS_ARG_INFO( vas_computer_get_spns );
ZEND_VAS_ARG_INFO( vas_computer_get_sam_account_name );
ZEND_VAS_ARG_INFO( vas_computer_get_upn );
ZEND_VAS_ARG_INFO( vas_computer_get_krb5_client_name );
ZEND_VAS_ARG_INFO( vas_computer_get_host_spn );
ZEND_VAS_ARG_INFO( vas_computer_get_account_control );
#if HAVE_DECL_VAS_NAME_COMPARE
ZEND_VAS_ARG_INFO( vas_name_compare );
ZEND_VAS_ARG_INFO( vas_user_compare );
/*
ZEND_VAS_ARG_INFO( vas_group_compare );
ZEND_VAS_ARG_INFO( vas_service_compare );
ZEND_VAS_ARG_INFO( vas_computer_compare );
 */
#endif
ZEND_VAS_ARG_INFO( vas_gss_initialize );
ZEND_VAS_ARG_INFO( vas_gss_acquire_cred );
ZEND_VAS_ARG_INFO( vas_gss_auth );
ZEND_VAS_ARG_INFO( vas_gss_spnego_initiate );
ZEND_VAS_ARG_INFO( vas_gss_spnego_accept );
ZEND_VAS_ARG_INFO( vas_gss_krb5_get_subkey );
ZEND_VAS_ARG_INFO( new_gss_buffer_desc );
ZEND_VAS_ARG_INFO( delete_gss_buffer_desc );
ZEND_VAS_ARG_INFO( new_gss_OID_desc );
ZEND_VAS_ARG_INFO( delete_gss_OID_desc );
ZEND_VAS_ARG_INFO( new_gss_OID_set_desc );
ZEND_VAS_ARG_INFO( delete_gss_OID_set_desc );
ZEND_VAS_ARG_INFO( new_gss_channel_bindings_struct );
ZEND_VAS_ARG_INFO( delete_gss_channel_bindings_struct );
#if 0
ZEND_VAS_ARG_INFO( gss_c_nt_user_name_set );
ZEND_VAS_ARG_INFO( gss_c_nt_user_name_get );
ZEND_VAS_ARG_INFO( gss_c_nt_machine_uid_name_set );
ZEND_VAS_ARG_INFO( gss_c_nt_machine_uid_name_get );
ZEND_VAS_ARG_INFO( gss_c_nt_string_uid_name_set );
ZEND_VAS_ARG_INFO( gss_c_nt_string_uid_name_get );
ZEND_VAS_ARG_INFO( gss_c_nt_hostbased_service_x_set );
ZEND_VAS_ARG_INFO( gss_c_nt_hostbased_service_x_get );
ZEND_VAS_ARG_INFO( gss_c_nt_hostbased_service_set );
ZEND_VAS_ARG_INFO( gss_c_nt_hostbased_service_get );
ZEND_VAS_ARG_INFO( gss_c_nt_anonymous_set )
ZEND_VAS_ARG_INFO( gss_c_nt_anonymous_get );
ZEND_VAS_ARG_INFO( gss_c_nt_export_name_set );
ZEND_VAS_ARG_INFO( gss_c_nt_export_name_get );
ZEND_VAS_ARG_INFO( gss_spnego_mechanism_set );
ZEND_VAS_ARG_INFO( gss_spnego_mechanism_get );
#endif
ZEND_VAS_ARG_INFO( gss_acquire_cred );
ZEND_VAS_ARG_INFO( gss_add_cred );
ZEND_VAS_ARG_INFO( gss_inquire_cred );
ZEND_VAS_ARG_INFO( gss_inquire_cred_by_mech );
ZEND_VAS_ARG_INFO( gss_init_sec_context );
ZEND_VAS_ARG_INFO( gss_accept_sec_context );
ZEND_VAS_ARG_INFO( gss_process_context_token );
ZEND_VAS_ARG_INFO( gss_context_time );
ZEND_VAS_ARG_INFO( gss_inquire_context );
ZEND_VAS_ARG_INFO( gss_wrap_size_limit );
ZEND_VAS_ARG_INFO( gss_export_sec_context );
ZEND_VAS_ARG_INFO( gss_import_sec_context );
ZEND_VAS_ARG_INFO( gss_get_mic );
ZEND_VAS_ARG_INFO( gss_verify_mic );
ZEND_VAS_ARG_INFO( gss_wrap );
ZEND_VAS_ARG_INFO( gss_unwrap );
ZEND_VAS_ARG_INFO( gss_sign );
ZEND_VAS_ARG_INFO( gss_verify );
ZEND_VAS_ARG_INFO( gss_seal );
ZEND_VAS_ARG_INFO( gss_unseal );
ZEND_VAS_ARG_INFO( gss_import_name );
ZEND_VAS_ARG_INFO( gss_display_name );
ZEND_VAS_ARG_INFO( gss_compare_name );
ZEND_VAS_ARG_INFO( gss_release_name );
ZEND_VAS_ARG_INFO( gss_inquire_names_for_mech );
ZEND_VAS_ARG_INFO( gss_inquire_mechs_for_name );
ZEND_VAS_ARG_INFO( gss_canonicalize_name );
ZEND_VAS_ARG_INFO( gss_export_name );
ZEND_VAS_ARG_INFO( gss_duplicate_name );
ZEND_VAS_ARG_INFO( gss_display_status );
ZEND_VAS_ARG_INFO( gss_create_empty_oid_set );
ZEND_VAS_ARG_INFO( gss_add_oid_set_member );
ZEND_VAS_ARG_INFO( gss_test_oid_set_member );
ZEND_VAS_ARG_INFO( gss_release_oid_set );
ZEND_VAS_ARG_INFO( gss_release_buffer );
ZEND_VAS_ARG_INFO( gss_indicate_mechs );
ZEND_VAS_ARG_INFO( vas_krb5_get_context );
ZEND_VAS_ARG_INFO( vas_krb5_get_principal );
ZEND_VAS_ARG_INFO( vas_krb5_get_ccache );
ZEND_VAS_ARG_INFO( vas_krb5_get_credentials );
ZEND_VAS_ARG_INFO( vas_krb5_validate_credentials );
ZEND_VAS_ARG_INFO( vas_ldap_init_and_bind );
ZEND_VAS_ARG_INFO( vas_ldap_set_attributes );

#if VAS_API_IS(4,1)
ZEND_VAS_ARG_INFO( vas_auth_check_client_membership );
ZEND_VAS_ARG_INFO( vas_auth_get_client_groups );
ZEND_VAS_ARG_INFO( vas_attrs_get_option );
ZEND_VAS_ARG_INFO( vas_user_get_domain );
ZEND_VAS_ARG_INFO( vas_group_get_domain );
ZEND_VAS_ARG_INFO( vas_service_get_domain );
ZEND_VAS_ARG_INFO( vas_computer_get_domain );
#elif VAS_API_IS(4,0)
ZEND_VAS_ARG_INFO( vas_auth_is_client_membership );
ZEND_VAS_ARG_INFO( vas_user_get_realm );
ZEND_VAS_ARG_INFO( vas_group_get_realm );
ZEND_VAS_ARG_INFO( vas_service_get_realm );
ZEND_VAS_ARG_INFO( vas_computer_get_realm );
#endif

/*
 * Entry subsection
 *
 * Every user-visible function must have an entry here. This introduces them to
 * Zend by name as it should appear in PHP (the expected, VAS API name) and the
 * underlying, implementation name (which, for now, is the same but prefixed by
 * zif_, Zend-compliant internal function, according to Zend/PHP policy).
 *
 * http://devzone.zend.com/manual/view/page/zend.structure.html
 *
 * This document covers only php4 and there are differences introduced in php5
 * which we have attempted to compensate for here.
 */
function_entry vas_functions[] =
{
    /* these pass in an array to give information... */
    ZEND_VAS2( vas_id_get_name,         vas_id_get_name_arginfo )
    ZEND_VAS2( vas_name_to_dn,          vas_name_to_dn_arginfo )
    ZEND_VAS2( vas_info_forest_root,    vas_info_forest_root_arginfo )
    ZEND_VAS2( vas_info_joined_domain,  vas_info_joined_domain_arginfo )
    ZEND_VAS2( vas_info_domains,        vas_info_domains_arginfo )
    ZEND_VAS2( vas_gss_spnego_initiate, vas_gss_spnego_initiate_arginfo )
    ZEND_VAS2( vas_gss_spnego_accept,   vas_gss_spnego_accept_arginfo )
    ZEND_VAS2( vas_gss_krb5_get_subkey, vas_gss_krb5_get_subkey_arginfo )

    ZEND_VAS( vas_err_internal )
    ZEND_VAS( vas_err_minor_internal )
    ZEND_VAS( vas_ctx_alloc )
    ZEND_VAS( vas_ctx_set_option )
    ZEND_VAS( vas_ctx_get_option )
    ZEND_VAS( vas_id_alloc )
    ZEND_VAS( vas_id_get_ccache_name )
    ZEND_VAS( vas_id_get_keytab_name )
    ZEND_VAS( vas_id_get_user )
    ZEND_VAS( vas_id_is_cred_established )
    ZEND_VAS( vas_id_establish_cred_password )
    ZEND_VAS( vas_id_establish_cred_keytab )
    ZEND_VAS( vas_id_renew_cred )
    ZEND_VAS( vas_auth )
    ZEND_VAS( vas_auth_with_password )
    ZEND_VAS( vas_attrs_alloc )
    ZEND_VAS( vas_attrs_find )
    ZEND_VAS( vas_attrs_find_continue )
    ZEND_VAS( vas_attrs_set_option )
    ZEND_VAS( vas_vals_get_string )
    ZEND_VAS( vas_vals_get_integer )
    ZEND_VAS( vas_vals_get_binary )
    ZEND_VAS( vas_vals_get_anames )
    ZEND_VAS( vas_vals_get_dn )
    ZEND_VAS( vas_name_to_principal )
    ZEND_VAS( vas_info_site )
    ZEND_VAS( vas_info_servers )
    ZEND_VAS( vas_prompt_for_cred_string )
    ZEND_VAS( vas_err_get_code )
    ZEND_VAS( vas_err_get_string )
    ZEND_VAS( vas_err_clear )
    ZEND_VAS( vas_err_get_info )
    ZEND_VAS( vas_err_info_get_string )
    ZEND_VAS( vas_err_get_cause_by_type )
    ZEND_VAS( vas_user_init )
    ZEND_VAS( vas_user_is_member )
    ZEND_VAS( vas_user_get_groups )
    ZEND_VAS( vas_user_get_attrs )
    ZEND_VAS( vas_user_get_dn )
    ZEND_VAS( vas_user_get_sam_account_name )
    ZEND_VAS( vas_user_get_sid )
    ZEND_VAS( vas_user_get_upn )
    ZEND_VAS( vas_user_get_pwinfo )
    ZEND_VAS( vas_user_get_krb5_client_name )
    ZEND_VAS( vas_user_get_account_control )
    ZEND_VAS( vas_user_check_access )
    ZEND_VAS( vas_user_check_conflicts )
    ZEND_VAS( vas_group_init )
    ZEND_VAS( vas_group_has_member )
    ZEND_VAS( vas_group_get_attrs )
    ZEND_VAS( vas_group_get_dn )
    ZEND_VAS( vas_group_get_sid )
#if VAS_API_IS(4,2)
    ZEND_VAS( vas_group_get_grinfo )
#endif
    ZEND_VAS( vas_service_init )
    ZEND_VAS( vas_service_get_attrs )
    ZEND_VAS( vas_service_get_dn )
    ZEND_VAS( vas_service_get_krb5_client_name )
    ZEND_VAS( vas_service_get_spns )
    ZEND_VAS( vas_service_get_upn )
    ZEND_VAS( vas_computer_init )
    ZEND_VAS( vas_computer_is_member )
    ZEND_VAS( vas_computer_get_attrs )
    ZEND_VAS( vas_computer_get_dn )
    ZEND_VAS( vas_computer_get_dns_hostname )
    ZEND_VAS( vas_computer_get_sid )
    ZEND_VAS( vas_computer_get_spns )
    ZEND_VAS( vas_computer_get_sam_account_name )
    ZEND_VAS( vas_computer_get_upn )
    ZEND_VAS( vas_computer_get_krb5_client_name )
    ZEND_VAS( vas_computer_get_host_spn )
    ZEND_VAS( vas_computer_get_account_control )
#if HAVE_DECL_VAS_NAME_COMPARE
    ZEND_VAS( vas_name_compare )
    ZEND_VAS( vas_user_compare )
/*
    ZEND_VAS( vas_group_compare )
    ZEND_VAS( vas_service_compare )
    ZEND_VAS( vas_computer_compare )
 */
#endif

    ZEND_VAS( vas_gss_initialize )
    ZEND_VAS( vas_gss_acquire_cred )
    ZEND_VAS( vas_gss_auth )
    ZEND_VAS( vas_krb5_get_context )
    ZEND_VAS( vas_krb5_get_principal )
    ZEND_VAS( vas_krb5_get_ccache )
    ZEND_VAS( vas_krb5_get_credentials )
    ZEND_VAS( vas_krb5_validate_credentials )
    ZEND_VAS( vas_ldap_init_and_bind )
    ZEND_VAS( vas_ldap_set_attributes )

#if 0
    /* these are as yet unimplemented... */
    ZEND_VAS( gss_c_nt_user_name_set )
    ZEND_VAS( gss_c_nt_user_name_get )
    ZEND_VAS( gss_c_nt_machine_uid_name_set )
    ZEND_VAS( gss_c_nt_machine_uid_name_get )
    ZEND_VAS( gss_c_nt_string_uid_name_set )
    ZEND_VAS( gss_c_nt_string_uid_name_get )
    ZEND_VAS( gss_c_nt_hostbased_service_x_set )
    ZEND_VAS( gss_c_nt_hostbased_service_x_get )
    ZEND_VAS( gss_c_nt_hostbased_service_set )
    ZEND_VAS( gss_c_nt_hostbased_service_get )
    ZEND_VAS( gss_c_nt_anonymous_set )
    ZEND_VAS( gss_c_nt_anonymous_get )
    ZEND_VAS( gss_c_nt_export_name_set )
    ZEND_VAS( gss_c_nt_export_name_get )
    ZEND_VAS( gss_spnego_mechanism_set )
    ZEND_VAS( gss_spnego_mechanism_get )
#endif

    ZEND_VAS( gss_acquire_cred )
    ZEND_VAS( gss_add_cred )
    ZEND_VAS( gss_inquire_cred )
    ZEND_VAS( gss_inquire_cred_by_mech )
    ZEND_VAS( gss_init_sec_context )
    ZEND_VAS( gss_accept_sec_context )
    ZEND_VAS( gss_process_context_token )
    ZEND_VAS( gss_context_time )
    ZEND_VAS( gss_inquire_context )
    ZEND_VAS( gss_wrap_size_limit )
    ZEND_VAS( gss_export_sec_context )
    ZEND_VAS( gss_import_sec_context )
    ZEND_VAS( gss_get_mic )
    ZEND_VAS( gss_verify_mic )
    ZEND_VAS( gss_wrap )
    ZEND_VAS( gss_unwrap )
    ZEND_VAS( gss_sign )
    ZEND_VAS( gss_verify )
    ZEND_VAS( gss_seal )
    ZEND_VAS( gss_unseal )
    ZEND_VAS( gss_import_name )
    ZEND_VAS( gss_display_name )
    ZEND_VAS( gss_compare_name )
    ZEND_VAS( gss_release_name )
    ZEND_VAS( gss_inquire_names_for_mech )
    ZEND_VAS( gss_inquire_mechs_for_name )
    ZEND_VAS( gss_canonicalize_name )
    ZEND_VAS( gss_export_name )
    ZEND_VAS( gss_duplicate_name )
    ZEND_VAS( gss_display_status )
    ZEND_VAS( gss_create_empty_oid_set )
    ZEND_VAS( gss_add_oid_set_member )
    ZEND_VAS( gss_test_oid_set_member )
    ZEND_VAS( gss_release_oid_set )
    ZEND_VAS( gss_release_buffer )
    ZEND_VAS( gss_indicate_mechs )

#if VAS_API_IS(4,1)
    ZEND_VAS( vas_auth_check_client_membership )
    ZEND_VAS( vas_auth_get_client_groups )
    ZEND_VAS( vas_attrs_get_option )
    ZEND_VAS( vas_user_get_domain )
    ZEND_VAS( vas_group_get_domain )
    ZEND_VAS( vas_service_get_domain )
    ZEND_VAS( vas_computer_get_domain )

    /* Deprecated aliases for backward compat */
    ZEND_VAS_ALIAS( vas_auth_check_client_membership, 
		    vas_auth_is_client_membership )
    ZEND_VAS_ALIAS( vas_user_get_domain, vas_user_get_realm )
    ZEND_VAS_ALIAS( vas_group_get_domain, vas_group_get_realm )
    ZEND_VAS_ALIAS( vas_service_get_domain, vas_service_get_realm )
    ZEND_VAS_ALIAS( vas_computer_get_domain, vas_computer_get_realm )

#elif VAS_API_IS(4,0)
    ZEND_VAS( vas_auth_is_client_membership )
    ZEND_VAS( vas_user_get_realm )
    ZEND_VAS( vas_group_get_realm )
    ZEND_VAS( vas_service_get_realm )
    ZEND_VAS( vas_computer_get_realm )
#endif

#if PHP_MAJOR_VERSION == 4
    { /* fname */          NULL,
      /* handler */        NULL,
      /* func_arg_types */ NULL }
#elif PHP_MAJOR_VERSION == 5
    { /* fname */          NULL,
      /* handler */        NULL,
      /* arg_info */       NULL,
      /* num_args */       0,
      /* flags */          0 }
#endif
};

zend_module_entry vas_module_entry =
{
#if ZEND_MODULE_API_NO > 20010900
    STANDARD_MODULE_HEADER,
#endif
    "vas",
    vas_functions,
    PHP_MINIT(vas),
    PHP_MSHUTDOWN(vas),
    PHP_RINIT(vas),
    PHP_RSHUTDOWN(vas),
    PHP_MINFO(vas),
#if ZEND_MODULE_API_NO > 20010900
    NO_VERSION_YET,
#endif
    STANDARD_MODULE_PROPERTIES
};


/*
 * Wrapped-implementation section
 *
 * Each function needs a definition and, for PHP-5, a filled-in arg_info
 * structure. In each of these functions, there are 5 or 6 arguments (depending
 * on whether this is built for PHP-4 or PHP-5). Most are accessed only through
 * special macros and some are only seen in this code after preprocessing the
 * macros out. Except as marked, each of these is in both PHP-4 and PHP-5. They
 * are:
 *
 * ht                Number of arguments passed to Zend, obtained only using
 *                   ZEND_NUM_ARGS().
 * return_value      Used to pass return values from this function back to PHP
 *                   using predefined macros.
 * return_value_ptr  (PHP-5) Don't know what this does. It is this argument
 *                   smack in the middle of the list that caused these bindings
 *                   not to compile for PHP-5.
 * (Returning values is discussed in:
 * http://devzone.zend.com/manual/view/page/zend.returning.html.)
 * this_ptr          Gains access to the object in which function is contained,
 *                   if used within an object. The VAS APIs aren't
 *                   object-oriented, so this isn't specially used, but some
 *                   macros in use actually touch it.
 * return_value_used Flag indicating whether the return value of the guts of
 *                   this function will be consumed by the PHP calling code, 0
 *                   for won't be used, 1 indicates that it will be expected.
 * executor_globals  Points to global settings of the Zend engine used only if
 *                   creating new variables (which VAS doesn't do). Because at
 *                   the time of the original implementation, Red Hat platform
 *                   implementations of PHP didn't support this argument, it
 *                   doesn't appear in INTERNAL_FUNCTION_PARAMETERS (defined in
 *                   zend.h).
 */
ZEND_VAS_NAMED_FUNC( vas_err_internal )
{
    RETURN_LONG( VAS_G( g_vas_err ) );
}

ZEND_VAS_NAMED_FUNC( vas_err_minor_internal )
{
    RETURN_LONG( VAS_G( g_vas_err_minor ) );
}

ZEND_VAS_NAMED_FUNC( vas_ctx_alloc )
{
    SPE_vas_ctx_t *newContext = NULL;
    vas_err_t err;

    SPE_CHECK_ARGS( 0 );

    err = SPE_vas_ctx_alloc( &newContext );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        ZEND_REGISTER_RESOURCE( return_value, newContext, le_vas_ctx_t );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_ctx_set_option )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx, *zarg1 = NULL, *zarg2 = NULL, *zarg3 = NULL,
                    *zarg4 = NULL, *zarg5 = NULL, **zargX = NULL;
    vas_err_t       err;
    long            option;

    /* Make sure there are at least three arguments. */
    {
        int argbase=0;
        if( this_ptr && this_ptr->type == IS_OBJECT ) { argbase++; }
        if( ZEND_NUM_ARGS() + argbase < 3 ) { WRONG_PARAM_COUNT; }
    }

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rl|zzzzz",
           &zctx, &option, &zarg1, &zarg2, &zarg3, &zarg4, &zarg5 ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1, PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    switch( option )
    {
#define S1ARG zarg1 && !zarg2
#define S2ARG zarg1 && zarg2 && !zarg3
#define S3ARG zarg1 && zarg2 && zarg3 && !zarg4
#define S4ARG zarg1 && zarg2 && zarg3 && zarg4 && !zarg5

    case VAS_CTX_OPTION_DEFAULT_REALM:
        if( S1ARG && Z_TYPE_P( zarg1 ) == IS_STRING )
        {
            char    *realm = Z_STRVAL_P( zarg1 );
            err = vas_ctx_set_option( ctx->ctx, option, realm );
            SPE_SET_VAS_ERR( err );
            zend_printf(
"WARNING: vas_ctx_set_option(ctx, VAS_CTX_OPTION_DEFAULT_REALM, ...)\n"
" --may break VAS on this host.\n" );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;
    case VAS_CTX_OPTION_SITE_AND_FOREST_ROOT:
        /* the option is two strings... */
        if( S2ARG &&
             ( Z_TYPE_P(zarg1) == IS_STRING || Z_TYPE_P( zarg1 ) == IS_NULL ) &&
             ( Z_TYPE_P(zarg2) == IS_STRING || Z_TYPE_P( zarg2 ) == IS_NULL ) )
        {
            char    *site = ( Z_TYPE_P( zarg1 ) == IS_STRING )
                                    ? Z_STRVAL_P( zarg1 )
                                    : NULL;
            char    *forest = ( Z_TYPE_P( zarg2 ) == IS_STRING )
                                    ? Z_STRVAL_P( zarg2 )
                                    : NULL;
            err = vas_ctx_set_option( ctx->ctx, option, site, forest );
            SPE_SET_VAS_ERR( err );
            zend_printf(
"WARNING: vas_ctx_set_option(ctx, VAS_CTX_OPTION_SITE_AND_FOREST_ROOT, ...)\n"
" --may break VAS on this host.\n" );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;
    case VAS_CTX_OPTION_ADD_SERVER:
        if( S4ARG &&
             ( Z_TYPE_P( zarg1 ) == IS_STRING )   &&    /* (cannot be nil) */
             ( Z_TYPE_P( zarg2 ) == IS_STRING
                || Z_TYPE_P( zarg2 ) == IS_NULL ) &&
             ( Z_TYPE_P( zarg3 ) == IS_STRING
                || Z_TYPE_P( zarg3 ) == IS_NULL ) &&
             ( Z_TYPE_P( zarg4 ) == IS_LONG ) )
        {
            char    *host = Z_STRVAL_P( zarg1 );
            char    *domain = ( Z_TYPE_P( zarg2 ) == IS_STRING )
                                    ? Z_STRVAL_P( zarg2 )
                                    : NULL;
            char    *site = ( Z_TYPE_P( zarg3 ) == IS_STRING )
                                    ? Z_STRVAL_P( zarg3 )
                                    : NULL;
            long    srvinfo = Z_LVAL_P( zarg4 );
            err = vas_ctx_set_option(ctx->ctx, option, host, domain, site, srvinfo);
            SPE_SET_VAS_ERR( err );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;

    case VAS_CTX_OPTION_USE_GSSAPI_AUTHZ:
    case VAS_CTX_OPTION_USE_TCP_ONLY:
    case VAS_CTX_OPTION_USE_DNSSRV:
    case VAS_CTX_OPTION_USE_SRVINFO_CACHE:
    case VAS_CTX_OPTION_USE_SERVER_REFERRALS:
    case VAS_CTX_OPTION_USE_VASCACHE:
    case VAS_CTX_OPTION_USE_VASCACHE_IPC:
#if VAS_API_IS(4,2)

        /* TODO: these need to be implemented. The C implementation is here;
         * compare to previously implemented options for binding.
         */
    case VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING:
        if( S1ARG &&
             ( Z_TYPE_P(zarg1) == IS_STRING || Z_TYPE_P( zarg1 ) == IS_NULL ) )
        {
            char    *sep = ( Z_TYPE_P( zarg1 ) == IS_STRING )
                                ? Z_STRVAL_P( zarg1 )
                                : NULL;
            err = vas_ctx_set_option( ctx->ctx, option, sep );
            SPE_SET_VAS_ERR( err );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;

# if HAVE_VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND /* 3.0.3.38 */
    case VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND:
        /* setting the Boolean options... */
        if( S1ARG && Z_TYPE_P( zarg1 ) == IS_LONG )
        {
            long    __bool_value = Z_LVAL_P( zarg1 );
            err = vas_ctx_set_option( ctx->ctx, option, __bool_value );
            SPE_SET_VAS_ERR( err );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;
# endif

# if HAVE_VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT /* 4.2 */
    case VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT:
        /* setting time_t option... */
        if( S1ARG && Z_TYPE_P( zarg1 ) == IS_LONG )
        {
            time_t    timeout = Z_LVAL_P( zarg1 );
            err = vas_ctx_set_option( ctx->ctx, option, timeout );
            SPE_SET_VAS_ERR( err );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;
# endif

#endif /* VAS_API_IS(4,2) */

#if 0 /* 4.3 */
    case VAS_CTX_OPTION_DOMAIN_NAMING_CONTEXT:
        /* the option is a string and a string list... */
        zargX = ( zval ** ) zarg2;  /* recast zarg2 for char **value */

        if( S2ARG &&
            ( Z_TYPE_P(zarg1) == IS_STRING || Z_TYPE_P( zarg1 ) == IS_NULL ) &&
            ( Z_TYPE_PP(zargX) == IS_STRING || Z_TYPE_PP( zargX ) == IS_NULL ) )
        {
            char    *domain = ( Z_TYPE_P( zarg1 ) == IS_STRING )
                                ? Z_STRVAL_P( zarg1 )
                                : NULL;
            char    *value = ( Z_TYPE_PP( zargX ) == IS_STRING )
                                ? Z_STRVAL_PP( zargX )
                                : NULL;
            err = vas_ctx_set_option( ctx->ctx, option, domain, value );
            SPE_SET_VAS_ERR( err );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;
#endif

    default:
        SPE_zend_error( E_WARNING, "Invalid option specified %s()",
                        get_active_function_name( TSRMLS_C ) );
        SPE_SET_VAS_ERR( VAS_ERR_INVALID_PARAM );
        break;
    }
    RETURN_LONG( VAS_G( g_vas_err ) );
}

ZEND_VAS_NAMED_FUNC( vas_ctx_get_option )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_t       err;
    long            option;
    int             intvalue;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rl",
                                    &zctx, &option ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    switch( option )
    {
        case VAS_CTX_OPTION_USE_TCP_ONLY:
        case VAS_CTX_OPTION_USE_GSSAPI_AUTHZ:
        case VAS_CTX_OPTION_USE_SRVINFO_CACHE:
        case VAS_CTX_OPTION_USE_DNSSRV:
        case VAS_CTX_OPTION_USE_VASCACHE:
        case VAS_CTX_OPTION_USE_VASCACHE_IPC:
        case VAS_CTX_OPTION_USE_SERVER_REFERRALS:
#if VAS_API_IS(4,2)
        case VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING:
# if HAVE_VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND /* 3.0.3.38 */
        case VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND:
# endif
# if HAVE_VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT		 /* 3.1.1.39 */
        case VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT:
# endif
#endif
            err = vas_ctx_get_option( ctx->ctx, option, &intvalue );
            SPE_SET_VAS_ERR( err );
            if( err == VAS_ERR_SUCCESS )
            {
                RETURN_LONG( intvalue );
            }
            break;

        case VAS_CTX_OPTION_ADD_SERVER:
        case VAS_CTX_OPTION_DEFAULT_REALM:
        case VAS_CTX_OPTION_SITE_AND_FOREST_ROOT:
#if 0
        case VAS_CTX_OPTION_DOMAIN_NAMING_CONTEXT:
#endif
            SPE_zend_error( E_WARNING,
                            "Unimplemented get-option specified--"
                            "see documentation, %s()",
                            get_active_function_name( TSRMLS_C ) );
            SPE_SET_VAS_ERR( VAS_ERR_INVALID_PARAM );
            RETURN_NULL();
        default:
            SPE_zend_error( E_WARNING,
                            "Invalid option specified %s()",
                            get_active_function_name( TSRMLS_C ) );
            SPE_SET_VAS_ERR( VAS_ERR_INVALID_PARAM );
            RETURN_NULL();
            break;
    }
}

ZEND_VAS_NAMED_FUNC( vas_id_alloc )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_t       err;
    char            *name = NULL;
    int             name_len;
    vas_id_t        *id = NULL;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rs",
                                    &zctx, &name, &name_len ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    ZEND_PRINTF( "_____vas_id_alloc: ctx = %p\n", ctx->ctx );
    ZEND_PRINTF( "_____vas_id_alloc: name = %s, length = %d\n", name, name_len);

    err = vas_id_alloc( ctx->ctx, name, &id );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_id_t, id );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_id_get_ccache_name )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid;
    vas_err_t       err;
    char            *name = NULL;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                    &zctx, &zid ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_id_get_ccache_name( ctx->ctx, RAW( id ), &name );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING(name, 1);
        free(name);
    }
    else
    {
        RETVAL_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_id_get_keytab_name )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid;
    vas_err_t       err;
    char            *name = NULL;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                    &zctx, &zid ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_id_get_keytab_name( ctx->ctx, RAW( id ), &name );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( name, 1 );
        free( name );
    }
    else
    {
        RETVAL_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_id_get_name )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zId, *zprinc, *zdn;
    vas_err_t       err;
    char            *princ = NULL, *dn = NULL;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrzz",
                                    &zctx, &zId, &zprinc, &zdn ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_id_get_name( ctx->ctx, RAW( id ), &princ, &dn );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        ZVAL_STRING( zprinc, princ, 1 );
        ZVAL_STRING( zdn, dn, 1 );
        free( princ );
        free( dn );
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_id_get_user )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zId;
    vas_err_t       err;
    vas_user_t      *user = NULL;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                    &zctx, &zId ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_id_get_user( ctx->ctx, RAW( id ), &user );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_user_t, user );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_id_is_cred_established )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zId;
    vas_err_t       err;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                    &zctx, &zId ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_id_is_cred_established( ctx->ctx, RAW( id ) );

    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_id_establish_cred_password )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid;
    vas_err_t       err;
    long            credFlags;
    const char      *pw;
    int             pw_len;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrls",
                            &zctx, &zid, &credFlags, &pw, &pw_len ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_id_establish_cred_password( ctx->ctx, RAW( id ), credFlags, pw );

    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_id_establish_cred_keytab )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid;
    vas_err_t       err;
    long            credFlags;
    const char      *keytab;
    int             szkeytab;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrls",
                    &zctx, &zid, &credFlags, &keytab, &szkeytab ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t *, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    if( *keytab == '\0' )
    {
        keytab = NULL;
    }
    err = vas_id_establish_cred_keytab( ctx->ctx, RAW( id ), credFlags, keytab );

    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_id_renew_cred )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zId;
    vas_err_t       err;
    long            credFlags;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrl",
                                &zctx, &zId, &credFlags ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_id_renew_cred( ctx->ctx, RAW( id ), credFlags );

    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_auth )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *idClient;
    SPE_vas_id_t    *idServer;
    vas_err_t       err;
    vas_auth_t      *auth = NULL;
    zval            *zctx, *zClient, *zServer;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrr", &zctx, &zClient, &zServer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1, PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( idClient, SPE_vas_id_t*, &zClient, -1, PHP_vas_id_t_RES_NAME, le_vas_id_t );
    ZEND_FETCH_RESOURCE( idServer, SPE_vas_id_t*, &zServer, -1, PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_auth( ctx->ctx, idClient->raw, idServer->raw, &auth );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_auth_t, auth );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_auth_with_password )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *idServer;
    zval            *zctx, *zServer;
    vas_err_t       err;
    vas_auth_t      *auth = NULL;
    const char      *szClientName, *szClientPass;
    int             lClientName, lClientPass;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rssr",
                &zctx, &szClientName, &lClientName, &szClientPass,
                &lClientPass, &zServer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( idServer, SPE_vas_id_t*, &zServer, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_auth_with_password( ctx->ctx, szClientName, szClientPass,
                                idServer->raw, &auth );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_auth_t, auth );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_auth_check_client_membership )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_auth_t  *auth;
    zval            *zctx, *zid, *zauth;
    vas_err_t       err;
    const char      *szGroup;
    int             lGroup;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzrs",
                        &zctx, &zid, &zauth, &szGroup, &lGroup ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( auth, SPE_vas_auth_t *, &zauth, -1,
                                PHP_vas_auth_t_RES_NAME, le_vas_auth_t );

    err = vas_auth_check_client_membership( ctx->ctx, RAW( id ),
                                auth->raw, szGroup );

    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

#if VAS_API_IS(4,1)
ZEND_VAS_NAMED_FUNC( vas_auth_get_client_groups )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_auth_t  *auth;
    zval            *zctx, *zid, *zauth;
    vas_err_t       err;
    vas_group_t     **groups = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zauth) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( auth, SPE_vas_auth_t*, &zauth, -1,
                            PHP_vas_auth_t_RES_NAME, le_vas_auth_t );

    err = vas_auth_get_client_groups( ctx->ctx, RAW( id ), auth->raw, &groups );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert strvals into a PHP vector thing, then free it. */
        array_init( return_value );

        for( i = 0; groups[i]; i++ )
        {
            zval* g;
            SPE_vas_group_t* thing;
            thing = ( SPE_vas_group_t* )emalloc( sizeof( SPE_vas_group_t ) );
            thing->ctx = ctx;
            thing->ctx->referenceCount++;
            thing->raw = groups[i];
            thing->noFree = 1;     /* SEE COMMENT BELOW */

            ALLOC_INIT_ZVAL( g );
            ZEND_REGISTER_RESOURCE( g, thing, le_vas_group_t );

            add_next_index_zval( return_value, g );
        }
        /* vas_group_free_groups(ctx->ctx, groups);
         *
         * We copied the group's from the groups array, so we can't just
         * free them as above.  Defer the free until the ctx is free'ed. */
      SPE_add_groups( ctx, groups );

      return;
    }
    else
    {
        RETURN_NULL();
    }
}
#endif /* VAS_API_IS(4,1) */

ZEND_VAS_NAMED_FUNC( vas_attrs_alloc )
{
    SPE_vas_ctx_t *ctx;
    SPE_vas_id_t  *id = NULL;
    vas_attrs_t   *attrs = NULL;
    vas_err_t     err;
    zval          *zctx, *zid;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rz",
                                    &zctx, &zid ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                    PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    err = vas_attrs_alloc( ctx->ctx, RAW( id ), &attrs );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_attrs_t, attrs );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_attrs_find )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_attrs_t *attrs;
    zval            *zanames, *zctx, *zattrs, **data;
    int             l, anames_count, anames_index = 0;
    const char      *uri, *scope, *base, *filter;
    vas_err_t       err;
    HashTable       *htanames;
    HashPosition    panames;
    const char      **anames = NULL;

    SPE_CHECK_ARGS( 7 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrssssa",
            &zctx, &zattrs, &uri, &l, &scope, &l, &base, &l, &filter,
            &l, &zanames ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                                PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );
    /* anames parameter is optional*/

    /* Create the anames array */
    htanames = Z_ARRVAL_P( zanames );
    anames_count = zend_hash_num_elements( htanames );
    anames = emalloc( ( anames_count + 1 ) * sizeof( const char* ) );

    for( zend_hash_internal_pointer_reset_ex( htanames, &panames );
          zend_hash_get_current_data_ex( htanames, ( void** )&data, &panames ) == SUCCESS;
          zend_hash_move_forward_ex( htanames, &panames ) )
    {
        if( Z_TYPE_PP( data ) == IS_STRING )
        {
            anames[anames_index++] = Z_STRVAL_PP( data );
        }
    }
    anames[anames_index++] = NULL;  /* Make sure null terminated.*/

    /* Make the call.*/
    err = vas_attrs_find( ctx->ctx, attrs->raw, uri, scope, base, filter, anames );

    SPE_SET_VAS_ERR( err );
    efree( anames );
    RETURN_NULL();
}

ZEND_VAS_NAMED_FUNC( vas_attrs_find_continue )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_attrs_t *attrs;
    zval            *zctx, *zattrs;
    vas_err_t       err;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                &zctx, &zattrs ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                            PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    err = vas_attrs_find_continue( ctx->ctx, attrs->raw );

    SPE_SET_VAS_ERR( err );
    RETURN_NULL();
}

ZEND_VAS_NAMED_FUNC( vas_attrs_set_option )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_attrs_t *attrs;
    zval            *zctx, *zattrs, *zvalue;
    vas_err_t       err;
    long            option;
    char            *strvalue = NULL;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrlz",
                                &zctx, &zattrs, &option, &zvalue ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                                PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    switch( option )
    {
    case VAS_ATTRS_B64_ENCODE_ATTRS:
        if( Z_TYPE_P( zvalue ) == IS_STRING || Z_TYPE_P( zvalue ) == IS_NULL )
        {
            if( Z_TYPE_P( zvalue ) == IS_STRING )
            {
                strvalue = Z_STRVAL_P( zvalue );
            }
            else
            {
                strvalue = NULL;
            }
            err = vas_attrs_set_option( ctx->ctx, attrs->raw, option, strvalue );
            SPE_SET_VAS_ERR( err );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;
    case VAS_ATTRS_OPTION_SEARCH_TIMEOUT:
    case VAS_ATTRS_OPTION_LDAP_PAGESIZE:
        if( Z_TYPE_P( zvalue ) == IS_LONG )
        {
            err = vas_attrs_set_option( ctx->ctx, attrs->raw, option,
                                                        Z_LVAL_P( zvalue ) );
            SPE_SET_VAS_ERR( err );
        }
        else
        {
            SPE_CHOKE_PARAMS();
        }
        break;
    default:
        SPE_zend_error( E_WARNING, "Invalid option specified %s()",
                                get_active_function_name( TSRMLS_C ) );
        SPE_SET_VAS_ERR( VAS_ERR_INVALID_PARAM );
        break;
    }
    RETURN_NULL();
}

#if VAS_API_IS(4,1)
ZEND_VAS_NAMED_FUNC( vas_attrs_get_option )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_attrs_t *attrs;
    zval            *zctx, *zattrs;
    vas_err_t       err;
    long            option;
    int             intvalue;
    char            *strvalue = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rrl",
                                &zctx, &zattrs, &option ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                                PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    switch( option )
    {
    case VAS_ATTRS_B64_ENCODE_ATTRS:
        err = vas_attrs_get_option( ctx->ctx, attrs->raw, option, &strvalue );
        SPE_SET_VAS_ERR( err );
        if( err == VAS_ERR_SUCCESS )
        {
            if( strvalue == NULL )
            {
                RETVAL_NULL();
            }
            else
            {
                RETVAL_STRING( strvalue, 1 );
            }

            /* SPE, DRK -- if you do this free (which you should) the heap
             * will get wrecked.
               free(strvalue); */
        }
        break;
    case VAS_ATTRS_OPTION_SEARCH_TIMEOUT:
    case VAS_ATTRS_OPTION_LDAP_PAGESIZE:
        err = vas_attrs_get_option( ctx->ctx, attrs->raw, option, &intvalue );
        SPE_SET_VAS_ERR( err );
        if( err == VAS_ERR_SUCCESS )
        {
            RETVAL_LONG( intvalue );
        }
        break;
    default:
        SPE_zend_error( E_WARNING, "Invalid option specified %s()",
                            get_active_function_name( TSRMLS_C ) );
        SPE_SET_VAS_ERR( VAS_ERR_INVALID_PARAM );
        RETVAL_NULL();
        break;
    }
}
#endif /* VAS_API_IS(4,1) */

ZEND_VAS_NAMED_FUNC( vas_vals_get_string )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_attrs_t *attrs;
    zval            *zctx, *zattrs;
    vas_err_t       err;
    const char      *aname;
    int             count = 0, aname_len;
    char            **strvals = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrs",
                        &zctx, &zattrs, &aname, &aname_len ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                        PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    err = vas_vals_get_string( ctx->ctx, attrs->raw, aname, &strvals, &count );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert strvals into a PHP vector thing, then free it. */
        array_init(return_value);
        for( i = 0; i < count; i++ )
        {
            add_next_index_string( return_value, strvals[i], 1 );
        }
        vas_vals_free_string(ctx->ctx, strvals, count);
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_vals_get_integer )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_attrs_t *attrs;
    zval            *zctx, *zattrs;
    vas_err_t       err;
    const char      *aname;
    int             count = 0, aname_len;
    int             *intvals = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrs",
                            &zctx, &zattrs, &aname, &aname_len ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                            PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    err = vas_vals_get_integer( ctx->ctx, attrs->raw, aname, &intvals, &count );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert intvals into a PHP vector thing, then free it. */
        array_init(return_value);
        for( i = 0; i < count; i++ )
        {
            add_next_index_long( return_value, intvals[i] );
        }
        vas_vals_free_integer(ctx->ctx, intvals, count);
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_vals_get_binary )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_attrs_t     *attrs;
    zval                *zctx, *zattrs;
    const char          *aname;
    int                 count = 0, aname_len;
    vas_err_t           err;
    vas_val_binary_t    *binvals = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrs",
                            &zctx, &zattrs, &aname, &aname_len ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                        PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    err = vas_vals_get_binary( ctx->ctx, attrs->raw, aname, &binvals, &count );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert intvals into a PHP vector thing, then free it.*/
        array_init( return_value );

        for( i = 0; i < count; i++ )
        {
            add_next_index_stringl( return_value, binvals[i].data, binvals[i].size, 1 );
        }
        vas_vals_free_binary( ctx->ctx, binvals, count );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_vals_get_anames )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_attrs_t     *attrs;
    zval                *zctx, *zattrs;
    const char          *aname;
    int                 count = 0, aname_len;
    vas_err_t           err;
    char                **anames = NULL;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                &zctx, &zattrs ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                            PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    err = vas_vals_get_anames( ctx->ctx, attrs->raw, &anames, &count );
    SPE_SET_VAS_ERR(err);

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert strvals into a PHP vector thing, then free it.*/
        array_init(return_value);
        for( i = 0; i < count; i++ )
        {
            add_next_index_string( return_value, anames[i], 1 );
        }
        vas_vals_free_anames( ctx->ctx, anames, count );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_vals_get_dn )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_attrs_t *attrs;
    zval            *zctx, *zattrs;
    vas_err_t       err;
    char            *dn = NULL;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                &zctx, &zattrs ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( attrs, SPE_vas_attrs_t*, &zattrs, -1,
                        PHP_vas_attrs_t_RES_NAME, le_vas_attrs_t );

    err = vas_vals_get_dn( ctx->ctx, attrs->raw, &dn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( dn, 1 );
        vas_vals_free_dn( ctx->ctx, dn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_name_to_principal )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    const char      *szName;
    int             lName;
    vas_err_t       err;
    long            hint, flags;
    char            *nameout = NULL;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rsll",
                        &zctx, &szName, &lName, &hint, &flags ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_name_to_principal( ctx->ctx, szName, hint, flags, &nameout );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( nameout, 1 );
        free(nameout);
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_name_to_dn )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid, *znameout, *zdomainout;
    const char      *szName;
    int             lName;
    vas_err_t       err;
    long            hint, flags;
    char            *nameout = NULL, *domainout = NULL;

    SPE_CHECK_ARGS( 7 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzsllzz",
            &zctx, &zid, &szName, &lName, &hint, &flags,
            &znameout, &zdomainout ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    err = vas_name_to_dn( ctx->ctx, RAW( id ), szName, hint, flags,
                            &nameout, &domainout );

    SPE_SET_VAS_ERR( err );

    if(err == VAS_ERR_SUCCESS)
    {
        ZVAL_STRING( znameout, nameout, 1 );
        ZVAL_STRING( zdomainout, domainout, 1 );
        free( nameout );
        free( domainout );
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_info_forest_root )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx, *zroot, *zrootdn;
    vas_err_t       err;
    char            *root = NULL, *rootdn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzz",
                                &zctx, &zroot, &zrootdn ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_info_forest_root( ctx->ctx, &root, &rootdn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        ZVAL_STRING( zroot, root, 1 );
        ZVAL_STRING( zrootdn, rootdn, 1 );
        free( root );
        free( rootdn );
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_info_joined_domain )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx, *zdomain, *zdomaindn;
    vas_err_t       err;
    char            *domain = NULL, *domaindn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzz",
                                &zctx, &zdomain, &zdomaindn ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_info_joined_domain( ctx->ctx, &domain, &domaindn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        ZVAL_STRING( zdomain, domain, 1 );
        ZVAL_STRING( zdomaindn, domaindn, 1 );
        free( domain );
        free( domaindn );
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_info_site )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_t       err;
    char            *site = NULL;

    SPE_CHECK_ARGS( 1 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "r", &zctx) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_info_site( ctx->ctx, &site );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( site, 1 );
        free( site );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_info_domains )
{
    SPE_vas_id_t    *id = NULL;
    SPE_vas_ctx_t   *ctx;
    zval            *zctx, *zId, *zdomains, *zdomains_dn;
    vas_err_t       err;
    char            **domains = NULL, **domains_dn = NULL;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzzz",
                        &zctx, &zId, &zdomains, &zdomains_dn ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zId ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }

    err = vas_info_domains( ctx->ctx, RAW( id ), &domains, &domains_dn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        convert_to_array( zdomains );
        zend_hash_clean( Z_ARRVAL_P( zdomains ) );
        for( i = 0; domains[i] != NULL; i++ )
        {
            add_next_index_string( zdomains, domains[i], 1 );
        }
        vas_info_domains_free( ctx->ctx, domains );
        convert_to_array( zdomains_dn );
        zend_hash_clean( Z_ARRVAL_P( zdomains_dn ) );
        for( i = 0; domains_dn[i] != NULL; i++ )
        {
            add_next_index_string( zdomains_dn, domains_dn[i], 1 );
        }
        vas_info_domains_free( ctx->ctx, domains_dn );
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_info_servers )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_t       err;
    const char      *szDomain, *szSite;
    int             lDomain, lSite;
    long            srvinfo;
    char            **servers = NULL;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rssl",
                    &zctx, &szDomain, &lDomain,
                    &szSite, &lSite, &srvinfo ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_info_servers( ctx->ctx,
                            *szDomain == '\0' ? NULL : szDomain,
                            *szSite == '\0' ? NULL : szSite,
                            ( vas_srvinfo_type_t ) srvinfo,
                            &servers );
    SPE_SET_VAS_ERR(err);

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert strvals into a PHP vector thing, then free it. */
        array_init(return_value);
        for( i = 0; servers[i] != NULL; i++ )
        {
            add_next_index_string( return_value, servers[i], 1 );
        }
        vas_info_servers_free( ctx->ctx, servers );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_prompt_for_cred_string )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_t       err;
    const char      *szprompt, *szverify;
    int             lprompt, lverify;
    char            *credstr = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rss",
                &zctx, &szprompt, &lprompt, &szverify, &lverify ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_prompt_for_cred_string( ctx->ctx, szprompt, szverify, &credstr );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( credstr, 1 );
        free( credstr );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_err_get_code )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_t       code;

    SPE_CHECK_ARGS( 1 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "r", &zctx ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1, PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    code = vas_err_get_code( ctx->ctx );
    RETURN_LONG( code );
}

ZEND_VAS_NAMED_FUNC( vas_err_get_string )
{
    zval            *zctx;
    SPE_vas_ctx_t   *ctx;
    const char      *s;
    long            with_cause;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rl",
                                &zctx, &with_cause ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    s = vas_err_get_string( ctx->ctx, with_cause );
    RETURN_STRING( ( char* ) s, 1 );
}

ZEND_VAS_NAMED_FUNC( vas_err_clear )
{
    zval            *zctx;
    SPE_vas_ctx_t   *ctx;
    vas_err_t       err;

    SPE_CHECK_ARGS( 1 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "r", &zctx) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_err_clear( ctx->ctx );
    SPE_SET_VAS_ERR( err );
    RETURN_NULL();
}

#if 0
/** VAS error information type used to describe the details of an error
 * condition.  For more information see documentation about error handling
 * and error handling functions such as: vas_err_get_info().
 */
class CVAS_err_info
{
   var $code;     /*!< Error code */
   var $type;     /*!< Type of error -- vas_err_type_t */
   var $cause;    /*!< Pointer to the cause */
   var $message;  /*!< Error message string */
};
#endif

static void add_err_cause_to_zval( vas_err_info_t *err, zval *z TSRMLS_DC )
{
    zval            *cause;
    vas_err_info_t  *c = err->cause;

    object_init_ex( z, vas_CVAS_err_info_entry );

    MAKE_STD_ZVAL( cause );
    array_init( cause );

    for( c = err->cause; c; c = c->cause )
    {
        zval* zcause;
        MAKE_STD_ZVAL( zcause );

        add_property_long( zcause, "code", c->code );
        add_property_long( zcause, "type", c->type );
        add_property_string( zcause, "message", c->message, 1 );

        add_next_index_zval( cause, zcause );
    }
    add_property_long( z, "code", err->code );
    add_property_long( z, "type", err->type );
    add_property_zval( z, "cause", cause );
    add_property_string( z, "message", err->message, 1 );
}

ZEND_VAS_NAMED_FUNC( vas_err_get_info )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_info_t  *err = NULL;

    SPE_CHECK_ARGS( 1 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "r", &zctx ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_err_get_info( ctx->ctx );

    if( err )
    {
        add_err_cause_to_zval( err, return_value TSRMLS_CC );
        vas_err_info_free( err );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_err_info_get_string )
{
    SPE_vas_ctx_t   *ctx;
    zval            **z, *zctx, *zerr;
    long            with_cause;
    vas_err_info_t  *err;
    char            *s = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rOl",
                    &zctx, &zerr, vas_CVAS_err_info_entry,
                    &with_cause ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = ( vas_err_info_t* )emalloc( sizeof( vas_err_info_t ) );

    memset( err, sizeof( *err ), 0 );

    if( zend_hash_find( Z_OBJPROP_P( zerr ), "code", sizeof( "code" ), ( void** )&z ) != FAILURE )
    {
        err->code = Z_LVAL_PP( z );
    }
    if( zend_hash_find( Z_OBJPROP_P( zerr ), "type", sizeof( "type" ), ( void** )&z ) != FAILURE )
    {
        err->type = Z_LVAL_PP( z );
    }
    /* This is a simplification so I don't have to track through nested structures.
     * Hopefully that is OK.*/
    err->cause = NULL;

    if( zend_hash_find( Z_OBJPROP_P( zerr ), "message", sizeof( "message" ), ( void** )&z ) != FAILURE )
    {
        err->message = Z_STRVAL_PP( z );
    }
    s = vas_err_info_get_string( ctx->ctx, err, with_cause );

    efree( err );

    if( s != NULL )
    {
        RETVAL_STRING( s, 1 );
        free( s );
    }
    else
    {
        RETVAL_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_err_get_cause_by_type )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    long            type;
    vas_err_info_t  *err;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rl",
                                    &zctx, &type ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_err_get_cause_by_type( ctx->ctx, type );

    if( err )
    {
        add_err_cause_to_zval( err, return_value TSRMLS_CC );
        vas_err_info_free( err );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_init )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zId;
    vas_user_t      *user = NULL;
    vas_err_t       err;
    int             flags, lName;
    const char      *szName;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzsl",
                        &zctx, &zId, &szName, &lName, &flags ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zId ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t *, &zId, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }

    err = vas_user_init( ctx->ctx, RAW( id ), szName, flags, &user );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_user_t, user );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_is_member )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    SPE_vas_group_t *group;
    zval            *zctx, *zid, *zuser, *zgroup;
    vas_err_t       err;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzrr",
                                &zctx, &zid, &zuser, &zgroup ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t *, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                            PHP_vas_group_t_RES_NAME, le_vas_group_t );

    err = vas_user_is_member( ctx->ctx, RAW(id), user->raw, group->raw );
    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_user_get_groups )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    vas_group_t     **groups = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                            &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                        PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_groups( ctx->ctx, RAW( id ), user->raw, &groups );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert strvals into a PHP vector thing, then free it.*/
        array_init( return_value );
        for( i = 0; groups[i]; i++ )
        {
            zval* g;
            SPE_vas_group_t* thing;
            thing = ( SPE_vas_group_t* )emalloc( sizeof( SPE_vas_group_t ) );
            thing->ctx = ctx;
            thing->ctx->referenceCount++;
            thing->raw = groups[i];
            thing->noFree = 1;     /* SEE COMMENT BELOW */

            ALLOC_INIT_ZVAL( g );
            ZEND_REGISTER_RESOURCE( g, thing, le_vas_group_t );

            add_next_index_zval( return_value, g );
        }
        /* vas_group_free_groups(ctx->ctx, groups);
         *
         * We copied the group's from the groups array, so we can't just
         * free them as above.  Defer the free until the ctx is free'ed.*/
        SPE_add_groups( ctx, groups );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_attrs )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser, *zanames, **data;
    vas_err_t       err;
    const char      **anames = NULL;
    vas_attrs_t     *attrs = NULL;
    HashTable       *htanames;
    HashPosition    panames;
    int             anames_count, anames_index = 0;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzra",
                                &zctx, &zid, &zuser, &zanames ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t *, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t *, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    /*DRK test to make sure this works when null!!*/
    if( ! ZVAL_IS_NULL( zanames ) )
    {
        /* Create the anames array */
        htanames = Z_ARRVAL_P( zanames );
        anames_count = zend_hash_num_elements( htanames );
        anames = emalloc( ( anames_count + 1 ) * sizeof( const char* ) );

        for( zend_hash_internal_pointer_reset_ex( htanames, &panames );
              zend_hash_get_current_data_ex( htanames, ( void** )&data, &panames ) == SUCCESS;
              zend_hash_move_forward_ex( htanames, &panames ) )
        {
            if( Z_TYPE_PP( data ) == IS_STRING )
            {
                anames[anames_index++] = Z_STRVAL_PP( data );
            }
        }
        anames[anames_index++] = NULL;  /* Make sure null terminated.*/
    }

    err = vas_user_get_attrs( ctx->ctx, RAW( id ), user->raw, anames, &attrs );
    SPE_SET_VAS_ERR( err );

    if( anames )
    {
        efree( anames );
    }
    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_attrs_t, attrs );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_dn )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    char            *dn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_dn( ctx->ctx, RAW( id ), user->raw, &dn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( dn, 1 );
        free( dn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

#if VAS_API_IS(4,1)
ZEND_VAS_NAMED_FUNC( vas_user_get_domain )
#elif VAS_API_IS(4,0)
ZEND_VAS_NAMED_FUNC( vas_user_get_realm )
#endif
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    char            *domain = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t *, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t *, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t *, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

#if VAS_API_IS(4,1)
    err = vas_user_get_domain( ctx->ctx, RAW( id ), user->raw, &domain );
#elif VAS_API_IS(4,0)
    err = vas_user_get_realm( ctx->ctx, RAW( id ), user->raw, &domain );
#endif
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( domain, 1 );
        free( domain );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_sam_account_name )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    char            *sam = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_sam_account_name( ctx->ctx, RAW( id ), user->raw, &sam );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( sam, 1 );
        free( sam );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_sid )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    char            *sid = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_sid( ctx->ctx, RAW( id ), user->raw, &sid );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( sid, 1 );
        free( sid );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_upn )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    char            *upn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_upn( ctx->ctx, RAW( id ), user->raw, &upn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( upn, 1 );
        free( upn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_pwinfo )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    struct passwd   *pwd = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }

    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }

    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                                PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_pwinfo( ctx->ctx, RAW( id ), user->raw, &pwd );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        object_init_ex( return_value, vas_CVAS_passwd_entry );

        add_property_string( return_value, "pw_name",   pwd->pw_name,   1 );
        add_property_string( return_value, "pw_passwd", pwd->pw_passwd, 1 );
        add_property_long(   return_value, "pw_uid",    pwd->pw_uid );
        add_property_long(   return_value, "pw_gid",    pwd->pw_gid );
        add_property_string( return_value, "pw_gecos",  pwd->pw_gecos,  1 );
        add_property_string( return_value, "pw_dir",    pwd->pw_dir,    1 );
        add_property_string( return_value, "pw_shell",  pwd->pw_shell,  1 );

        free( pwd );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_krb5_client_name )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    char            *client_name = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_krb5_client_name( ctx->ctx, RAW( id ),
                            user->raw, &client_name );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( client_name, 1 );
        free( client_name );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_get_account_control )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zid, *zuser;
    vas_err_t       err;
    int             account_control;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_get_account_control( ctx->ctx, RAW( id ), user->raw, &account_control );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_LONG( account_control );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_user_check_access )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zsrv, *zuser;
    vas_err_t       err;
    const char      *szService = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrz", &zctx, &zuser, &zsrv ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    if( Z_TYPE_P( zsrv ) == IS_STRING )
    {
        szService = Z_STRVAL_P( zsrv );
    }

    err = vas_user_check_access( ctx->ctx, user->raw, szService );
    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_user_check_conflicts )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_user_t  *user;
    zval            *zctx, *zuser;
    vas_err_t       err;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                &zctx, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_check_conflicts( ctx->ctx, user->raw );
    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_group_init )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    zval            *zctx, *zId;
    vas_group_t     *group = NULL;
    vas_err_t       err;
    int             flags, lName;
    const char      *szName;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzsl",
                            &zctx, &zId, &szName, &lName, &flags ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zId ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    err = vas_group_init( ctx->ctx, RAW( id ), szName, flags, &group );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_group_t, group );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_group_has_member )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_user_t  *user;
    SPE_vas_group_t *group;
    zval            *zctx, *zid, *zgroup, *zuser;
    vas_err_t       err;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzrr",
                                &zctx, &zid, &zgroup, &zuser ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                            PHP_vas_group_t_RES_NAME, le_vas_group_t );
    ZEND_FETCH_RESOURCE( user, SPE_vas_user_t*, &zuser, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_group_has_member( ctx->ctx, RAW( id ), group->raw, user->raw );
    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_group_get_attrs )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_group_t *group;
    zval            *zctx, *zid, *zgroup, *zanames, **data;
    vas_err_t       err;
    const char      **anames;
    vas_attrs_t     *attrs = NULL;
    HashTable       *htanames;
    HashPosition    panames;
    int             anames_count, anames_index = 0;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzra",
                            &zctx, &zid, &zgroup, &zanames ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                            PHP_vas_group_t_RES_NAME, le_vas_group_t );
    /* Create the anames array */
    htanames = Z_ARRVAL_P( zanames );
    anames_count = zend_hash_num_elements( htanames );
    anames = emalloc( ( anames_count + 1 ) * sizeof( const char* ) );

    for( zend_hash_internal_pointer_reset_ex( htanames, &panames );
          zend_hash_get_current_data_ex( htanames, ( void** ) &data, &panames ) == SUCCESS;
          zend_hash_move_forward_ex( htanames, &panames ) )
    {
        if( Z_TYPE_PP( data ) == IS_STRING )
        {
            anames[anames_index++] = Z_STRVAL_PP( data );
        }
    }
    anames[anames_index++] = NULL;  /* Make sure null terminated.*/

    err = vas_group_get_attrs( ctx->ctx, RAW( id ), group->raw, anames, &attrs );
    SPE_SET_VAS_ERR( err );
    efree( anames );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_attrs_t, attrs );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_group_get_dn )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_group_t *group;
    zval            *zctx, *zid, *zgroup;
    vas_err_t       err;
    char            *dn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                    &zctx, &zid, &zgroup ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                                PHP_vas_group_t_RES_NAME, le_vas_group_t );

    err = vas_group_get_dn( ctx->ctx, RAW( id ), group->raw, &dn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( dn, 1 );
        free( dn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

#if VAS_API_IS(4,1)
ZEND_VAS_NAMED_FUNC( vas_group_get_domain )
#elif VAS_API_IS(4,0)
ZEND_VAS_NAMED_FUNC( vas_group_get_realm )
#endif
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_group_t *group;
    zval            *zctx, *zid, *zgroup;
    vas_err_t       err;
    char            *domain = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zgroup ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                            PHP_vas_group_t_RES_NAME, le_vas_group_t );

#if VAS_API_IS(4,1)
    err = vas_group_get_domain( ctx->ctx, RAW( id ), group->raw, &domain );
#elif VAS_API_IS(4,0)
    err = vas_group_get_realm( ctx->ctx, RAW( id ), group->raw, &domain );
#endif
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( domain, 1 );
        free( domain );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_group_get_sid )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_group_t *group;
    zval            *zctx, *zid, *zgroup;
    vas_err_t       err;
    char            *sid = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                            &zctx, &zid, &zgroup) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                            PHP_vas_group_t_RES_NAME, le_vas_group_t );

    err = vas_group_get_sid( ctx->ctx, RAW( id ), group->raw, &sid );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( sid, 1 );
        free( sid );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

#if VAS_API_IS(4,2)
ZEND_VAS_NAMED_FUNC( vas_group_get_grinfo )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    SPE_vas_group_t *group;
    zval            *zctx, *zid, *zgroup;
    vas_err_t       err;
    struct group    *grp = NULL;

    SPE_CHECK_ARGS( 3 );

    /* TODO: I still don't know what this "rzr" is that I stole from the
     * function immediately preceeding.
     */
    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                            &zctx, &zid, &zgroup) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                            PHP_vas_group_t_RES_NAME, le_vas_group_t );

    err = vas_group_get_grinfo( ctx->ctx, RAW( id ), group->raw, &grp );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( sys_group_t, grp );
    }
    else
    {
        RETURN_NULL();
    }
}
#endif /* VAS_API_IS(4,2) */

ZEND_VAS_NAMED_FUNC( vas_service_init )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zId;
    vas_service_t   *service = NULL;
    vas_err_t       err;
    int             flags, lName;
    const char      *szName;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzsl",
                        &zctx, &zId, &szName, &lName, &flags ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                    PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zId ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                        PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }

    err = vas_service_init( ctx->ctx, RAW( id ), szName, flags, &service );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_service_t, service );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_service_get_attrs )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_service_t   *service;
    zval                *zctx, *zid, *zservice, *zanames, **data;
    vas_err_t           err;
    const char          **anames;
    vas_attrs_t         *attrs;
    HashTable           *htanames;
    HashPosition        panames;
    int                 anames_count, anames_index = 0;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzra",
                            &zctx, &zid, &zservice, &zanames ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( service, SPE_vas_service_t*, &zservice, -1,
                        PHP_vas_service_t_RES_NAME, le_vas_service_t );
    /* Create the anames array */
    htanames = Z_ARRVAL_P( zanames );
    anames_count = zend_hash_num_elements( htanames );
    anames = emalloc( ( anames_count + 1 ) * sizeof( const char* ) );

    for( zend_hash_internal_pointer_reset_ex( htanames, &panames );
          zend_hash_get_current_data_ex( htanames, ( void** ) &data, &panames ) == SUCCESS;
          zend_hash_move_forward_ex( htanames, &panames ) )
    {
        if( Z_TYPE_PP( data ) == IS_STRING )
        {
            anames[anames_index++] = Z_STRVAL_PP( data );
        }
    }
    anames[anames_index++] = NULL;  /* Make sure null terminated.*/

    err = vas_service_get_attrs( ctx->ctx, RAW( id ), service->raw, anames, &attrs );
    SPE_SET_VAS_ERR( err );
    efree( anames );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_attrs_t, attrs );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_service_get_dn )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_service_t   *service;
    zval                *zctx, *zid, *zservice;
    vas_err_t           err;
    char                *dn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                    &zctx, &zid, &zservice ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( service, SPE_vas_service_t*, &zservice, -1,
                                PHP_vas_service_t_RES_NAME, le_vas_service_t );

    err = vas_service_get_dn( ctx->ctx, RAW( id ), service->raw, &dn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( dn, 1 );
        free( dn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

#if VAS_API_IS(4,1)
ZEND_VAS_NAMED_FUNC( vas_service_get_domain )
#elif VAS_API_IS(4,0)
ZEND_VAS_NAMED_FUNC( vas_service_get_realm )
#endif
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_service_t   *service;
    zval                *zctx, *zid, *zservice;
    vas_err_t           err;
    char                *domain = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zservice ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( service, SPE_vas_service_t*, &zservice, -1,
                            PHP_vas_service_t_RES_NAME, le_vas_service_t );

#if VAS_API_IS(4,1)
    err = vas_service_get_domain( ctx->ctx, RAW( id ), service->raw, &domain );
#elif VAS_API_IS(4,0)
    err = vas_service_get_realm( ctx->ctx, RAW( id ), service->raw, &domain );
#endif
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( domain, 1 );
        free( domain );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_service_get_krb5_client_name )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_service_t   *service;
    zval                *zctx, *zid, *zservice;
    vas_err_t           err;
    char                *client_name = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zservice ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( service, SPE_vas_service_t*, &zservice, -1,
                            PHP_vas_service_t_RES_NAME, le_vas_service_t );

    err = vas_service_get_krb5_client_name( ctx->ctx, RAW( id ),
                            service->raw, &client_name );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( client_name, 1 );
        free( client_name );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_service_get_spns )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_service_t   *service;
    zval                *zctx, *zid, *zservice;
    vas_err_t           err;
    char                **spns = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zservice ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( service, SPE_vas_service_t*, &zservice, -1,
                            PHP_vas_service_t_RES_NAME, le_vas_service_t );

    err = vas_service_get_spns( ctx->ctx, RAW( id ), service->raw, &spns );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert strvals into a PHP vector thing, then free it.*/
        array_init(return_value);
        for( i = 0; spns[i]; i++ )
        {
            add_next_index_string( return_value, spns[i], 1 );
            free( spns[i] );
        }
        free( spns );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_service_get_upn )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_service_t   *service;
    zval                *zctx, *zid, *zservice;
    vas_err_t           err;
    char                *upn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zservice ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( service, SPE_vas_service_t*, &zservice, -1,
                            PHP_vas_service_t_RES_NAME, le_vas_service_t );

    err = vas_service_get_upn( ctx->ctx, RAW( id ), service->raw, &upn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( upn, 1 );
        free( upn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_init )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zId;
    vas_computer_t  *computer = NULL;
    vas_err_t       err;
    int             flags, lName;
    const char      *szName;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzsl",
                            &zctx, &zId, &szName, &lName, &flags ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zId ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zId, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }

    err = vas_computer_init( ctx->ctx, RAW( id ), szName, flags, &computer );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_computer_t, computer );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_is_member )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    SPE_vas_group_t     *group;
    zval                *zctx, *zid, *zcomputer, *zgroup;
    vas_err_t           err;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzrr",
                            &zctx, &zid, &zcomputer, &zgroup ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                        PHP_vas_computer_t_RES_NAME, le_vas_computer_t );
    ZEND_FETCH_RESOURCE( group, SPE_vas_group_t*, &zgroup, -1,
                        PHP_vas_group_t_RES_NAME, le_vas_group_t );

    err = vas_computer_is_member( ctx->ctx, RAW( id ), computer->raw, group->raw );
    SPE_SET_VAS_ERR( err );
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_attrs )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer, *zanames, **data;
    vas_err_t           err;
    const char          **anames;
    vas_attrs_t         *attrs = NULL;
    HashTable           *htanames;
    HashPosition        panames;
    int                 anames_count, anames_index = 0;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzra",
                            &zctx, &zid, &zcomputer, &zanames ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                        PHP_vas_computer_t_RES_NAME, le_vas_computer_t );
    /* Create the anames array */
    htanames = Z_ARRVAL_P( zanames );
    anames_count = zend_hash_num_elements( htanames );
    anames = emalloc( ( anames_count + 1 ) * sizeof( const char* ) );

    for( zend_hash_internal_pointer_reset_ex( htanames, &panames );
          zend_hash_get_current_data_ex( htanames, ( void** ) &data, &panames ) == SUCCESS;
          zend_hash_move_forward_ex( htanames, &panames ) )
    {
        if( Z_TYPE_PP( data ) == IS_STRING )
        {
            anames[anames_index++] = Z_STRVAL_PP( data );
        }
    }
    anames[anames_index++] = NULL;  /* Make sure null terminated.*/

    err = vas_computer_get_attrs( ctx->ctx, RAW( id ), computer->raw, anames, &attrs );
    SPE_SET_VAS_ERR( err );
    efree( anames );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_attrs_t, attrs );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_dn )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *dn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                            &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1, PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_dn( ctx->ctx, RAW( id ), computer->raw, &dn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( dn, 1 );
        free(dn);
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_dns_hostname )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *dns_hostname = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                            PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_dns_hostname( ctx->ctx, RAW( id ),
                            computer->raw, &dns_hostname );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( dns_hostname, 1 );
        free( dns_hostname );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

#if VAS_API_IS(4,1)
ZEND_VAS_NAMED_FUNC( vas_computer_get_domain )
#elif VAS_API_IS(4,0)
ZEND_VAS_NAMED_FUNC( vas_computer_get_realm )
#endif
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *domain = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                            PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

#if VAS_API_IS(4,1)
    err = vas_computer_get_domain( ctx->ctx, RAW( id ), computer->raw, &domain );
#elif VAS_API_IS(4,0)
    err = vas_computer_get_realm( ctx->ctx, RAW( id ), computer->raw, &domain );
#endif
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( domain, 1 );
        free( domain );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_sid )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *sid = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                            PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_sid( ctx->ctx, RAW( id ), computer->raw, &sid );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( sid, 1 );

        /* SPE, DRK -- if you do this free (which you should) the heap get wrecked.
         * free(sid); */
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_spns )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                **spns = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                            PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_spns( ctx->ctx, RAW( id ), computer->raw, &spns );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        int i;
        /* convert strvals into a PHP vector thing, then free it.*/
        array_init( return_value );
        for( i = 0; spns[i]; i++ )
        {
            add_next_index_string( return_value, spns[i], 1 );
            free( spns[i] );
        }
        free( spns );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_sam_account_name )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *sam = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                            PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_sam_account_name( ctx->ctx, RAW( id ),
                            computer->raw, &sam );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( sam, 1 );
        free( sam );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_upn )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *upn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                            &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                            PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_upn( ctx->ctx, RAW( id ), computer->raw, &upn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( upn, 1 );
        free( upn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_krb5_client_name )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *client_name = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                    &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                                PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_krb5_client_name( ctx->ctx, RAW( id ),
                                computer->raw, &client_name );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( client_name, 1 );
        free( client_name );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_host_spn )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    char                *host_spn = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                    &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                                PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_host_spn( ctx->ctx, RAW( id ), computer->raw,
                                &host_spn );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_STRING( host_spn, 1 );
        free( host_spn );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_computer_get_account_control )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_vas_computer_t  *computer;
    zval                *zctx, *zid, *zcomputer;
    vas_err_t           err;
    int                 account_control = 0;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzr",
                                    &zctx, &zid, &zcomputer ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    ZEND_FETCH_RESOURCE( computer, SPE_vas_computer_t*, &zcomputer, -1,
                            PHP_vas_computer_t_RES_NAME, le_vas_computer_t );

    err = vas_computer_get_account_control( ctx->ctx, RAW( id ),
                            computer->raw, &account_control );
    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        RETVAL_LONG( account_control );
        return;
    }
    else
    {
        RETURN_NULL();
    }
}

#if HAVE_DECL_VAS_NAME_COMPARE
ZEND_VAS_NAMED_FUNC( vas_name_compare )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid;
    const char      *szName_a, *szName_b;
    vas_err_t       err;
    long            hint, flags;

    SPE_CHECK_ARGS( 7 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzsllzz",
            &zctx, &zid, &szName_a, &szName_b, &hint, &flags ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }

    err = vas_name_compare( ctx->ctx, RAW( id ), szName_a, szName_b,
                        hint, flags );

    SPE_SET_VAS_ERR( err );

    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_user_compare )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_user_t  *user_a, *user_b;
    zval            *zctx, *zid, *zuser_a, *zuser_b;
    vas_err_t       err;

    SPE_CHECK_ARGS( 7 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzsllzz",
            &zctx, &zuser_a, &zuser_b ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( user_a, SPE_vas_user_t*, &zuser_a, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );
    ZEND_FETCH_RESOURCE( user_b, SPE_vas_user_t*, &zuser_b, -1,
                            PHP_vas_user_t_RES_NAME, le_vas_user_t );

    err = vas_user_compare( ctx->ctx, user_a->raw, user_b->raw );

    SPE_SET_VAS_ERR( err );

    RETURN_LONG( err );
}
#endif /* HAVE_DECL_VAS_NAME_COMPARE */

ZEND_VAS_NAMED_FUNC( vas_gss_initialize )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid;
    vas_err_t       err;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rz",
                                    &zctx, &zid ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    err = vas_gss_initialize( ctx->ctx, RAW( id ) );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        ctx->freeGSS = 1;
    }
    RETURN_NULL();
}

struct gss_cred_id_t_desc_struct;

ZEND_VAS_NAMED_FUNC( vas_gss_acquire_cred )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    gss_cred_id_t   cred = NULL;
    zval            *zctx, *zid;
    vas_err_t       err;
    OM_uint32       minor_status;
    int             usage;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rzl",
                                    &zctx, &zid, &usage ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                    PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    err = vas_gss_acquire_cred( ctx->ctx, RAW( id ), &minor_status,
                                    usage, &cred );

    SPE_SET_VAS_ERR2( err, minor_status );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( gss_cred_id_t, cred );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_gss_auth )
{
    SPE_vas_ctx_t       *ctx;
    SPE_gss_cred_id_t   *cred;
    SPE_gss_ctx_id_t    *context;
    zval                *zctx, *zcred, *zcontext;
    vas_err_t           err;
    OM_uint32           minor_status = 0;
    vas_auth_t          *auth = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrr",
                                &zctx, &zcred, &zcontext ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( cred, SPE_gss_cred_id_t*, &zcred, -1,
                            PHP_gss_cred_id_t_RES_NAME, le_gss_cred_id_t );
    ZEND_FETCH_RESOURCE( context, SPE_gss_ctx_id_t*, &zcontext, -1,
                            PHP_gss_ctx_id_t_RES_NAME, le_gss_ctx_id_t );

    err = vas_gss_auth( ctx->ctx, cred->raw, context->raw, &auth );
    SPE_SET_VAS_ERR2( err, minor_status );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_auth_t, auth );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_gss_spnego_initiate )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_gss_ctx_id_t    *gssctx = NULL;
    zval                *zctx, *zid, *zreserved, *zgssctx, *zouttoken;
    const char          *szIntoken, *szName;
    int                 lIntoken, lName, flags, encoding;
    OM_uint32           err;
    gss_buffer_t        real_intoken = NULL;
    gss_buffer_desc     outtoken = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t        mygssctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t        mygssctx_in = GSS_C_NO_CONTEXT;

    SPE_CHECK_ARGS( 9 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC,
                                "rrzzsllsz",
                                &zctx,
                                &zid,
                                &zreserved,
                                &zgssctx,
                                &szName,
                                &lName,
                                &flags,
                                &encoding,
                                &szIntoken,
                                &lIntoken,
                                &zouttoken ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    /*Ignore Reserved*/
    if( ! ZVAL_IS_NULL( zgssctx ) )
    {
        if( Z_TYPE_P( zgssctx ) != IS_LONG || Z_LVAL_P( zgssctx ) != 0 )
        {
            ZEND_FETCH_RESOURCE( gssctx, SPE_gss_ctx_id_t*, &zgssctx, -1,
                                   PHP_gss_ctx_id_t_RES_NAME, le_gss_ctx_id_t );
            mygssctx = gssctx->raw;
        }
    }
    if( lIntoken != 0 )
    {
        real_intoken = emalloc( sizeof( *real_intoken ) );
        real_intoken->length = lIntoken;
        real_intoken->value = ( void* )szIntoken;
    }
    mygssctx_in = mygssctx;

    err = vas_gss_spnego_initiate( ctx->ctx,
                                   id->raw,
                                   NULL,
                                   &mygssctx,
                                   szName,
                                   flags,
                                   encoding,
                                   real_intoken,
                                   &outtoken );
    if( real_intoken )
    {
        efree( real_intoken );
    }
    /* If accept eats out gssctx, don't double free.*/
    if( mygssctx != mygssctx_in )
    {
        if( mygssctx_in )
        {
            SPE_remove_gss_ctx( ctx, mygssctx_in );
        }
        if( mygssctx )
        {
            SPE_add_gss_ctx( ctx, mygssctx );
            SPE_CONS_VALUE( zgssctx, gss_ctx_id_t, mygssctx );
        }
    }
    if( ! GSS_ERROR( err ) )
    {
        /* Success, so deal with the outtoken.
         *
         * The semanitcs of spnego_initiate say that outtoken must be free'ed
         * before a subsequent call to spnego_initiate. In PHP, the only way
         * we can guarentee that is by freeing it now and duplicating the data.*/
        OM_uint32 minor_status;

        /* SEPARATE_ZVAL_IF_NOT_REF(&zouttoken);*/
        ZVAL_STRINGL( zouttoken, outtoken.value, outtoken.length, 1 );
        gss_release_buffer( &minor_status, &outtoken );
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_gss_spnego_accept )
{
    SPE_vas_ctx_t       *ctx;
    SPE_vas_id_t        *id = NULL;
    SPE_gss_ctx_id_t    *gssctx = NULL;
    zval                *zctx, *zid, *zauth, *zgssctx;
    zval                *zflags, *zouttoken, *zdeleg_cred;
    const char          *szIntoken;
    int                 lIntoken, encoding;
    OM_uint32           flags, err;
    gss_buffer_t        real_intoken = NULL;
    gss_buffer_desc     outtoken = GSS_C_EMPTY_BUFFER;
    vas_auth_t          *myauth = NULL;
    gss_ctx_id_t        mygssctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t        mygssctx_in = GSS_C_NO_CONTEXT;
    gss_cred_id_t       deleg_cred = GSS_C_NO_CREDENTIAL;

    SPE_CHECK_ARGS( 9 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrzzzlszz",
                                &zctx,
                                &zid,
                                &zauth,
                                &zgssctx,
                                &zflags,
                                &encoding,
                                &szIntoken,
                                &lIntoken,
                                &zouttoken,
                                &zdeleg_cred ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    if( ! ZVAL_IS_NULL( zgssctx ) )
    {
        if( Z_TYPE_P( zgssctx ) != IS_LONG || Z_LVAL_P( zgssctx ) != 0 )
        {
            ZEND_FETCH_RESOURCE( gssctx, SPE_gss_ctx_id_t*, &zgssctx, -1,
                                PHP_gss_ctx_id_t_RES_NAME, le_gss_ctx_id_t );
            mygssctx = gssctx->raw;
        }
    }
    if( ! ZVAL_IS_NULL( zdeleg_cred ) )
    {
        if( Z_TYPE_P( zdeleg_cred ) != IS_LONG || Z_LVAL_P( zdeleg_cred ) != 0 )
        {
            deleg_cred = ( gss_cred_id_t )1;
        }
    }
    if( lIntoken != 0 )
    {
        real_intoken = emalloc( sizeof( *real_intoken ) );
        real_intoken->length = lIntoken;
        real_intoken->value = ( void* )szIntoken;
    }
    mygssctx_in = mygssctx;

    err = vas_gss_spnego_accept( ctx->ctx,
                                 id->raw,
                                 &myauth,
                                 &mygssctx,
                                 &flags,
                                 encoding,
                                 real_intoken,
                                 &outtoken,
                                 (deleg_cred == GSS_C_NO_CREDENTIAL)
                                    ? NULL : &deleg_cred );
    if( real_intoken )
    {
        efree( real_intoken );
    }
    /* If accept eats out gssctx, don't double free. */
    if( mygssctx != mygssctx_in )
    {
        if( mygssctx_in )
        {
            SPE_remove_gss_ctx( ctx, mygssctx_in );
        }
        if( mygssctx )
        {
            SPE_add_gss_ctx( ctx, mygssctx );
            SPE_CONS_VALUE( zgssctx, gss_ctx_id_t, mygssctx );
        }
    }
    if( ! GSS_ERROR( err ) )
    {
        /* Success, so deal with the outtoken.
         *
         * The semanitcs of spnego_initiate say that outtoken must be free'ed
         * before a subsequent call to spnego_initiate. In PHP, the only way
         * we can guarentee that is by freeing it now and duplicating the data.*/
        OM_uint32 minor_status;

        /*SEPARATE_ZVAL_IF_NOT_REF(&zouttoken);*/
        ZVAL_STRINGL( zouttoken, outtoken.value, outtoken.length, 1 );

        gss_release_buffer( &minor_status, &outtoken );
        /* The rest of the out parameters: auth, gssctx, flags, deleg_cred.*/
        if( ! ZVAL_IS_NULL( zauth ) )
        {
            SPE_CONS_VALUE( zauth, vas_auth_t, myauth );
        }
        else
        {
            vas_auth_free( ctx->ctx, myauth );
        }
        ZVAL_LONG( zflags, flags );

        if( deleg_cred != GSS_C_NO_CREDENTIAL )
        {
            SPE_CONS_VALUE( zdeleg_cred, gss_cred_id_t, deleg_cred );
        }
#if 0
        {
            OM_uint32 err;
            gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
            gss_name_t client_name = NULL;
            /* Find the user name.*/
            err = gss_inquire_context( &minor_status,
                                       mygssctx,
                                       &client_name,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL );
            if( err != GSS_S_COMPLETE )
            {
                goto done;
            }

            /* Convert the client's name into a visible string */
            err = gss_display_name( &minor_status, client_name, &buf, NULL );
            if( err != GSS_S_COMPLETE )
            {
                goto done;
            }

            printf( "User name is: %s\n", ( const char* )buf.value );

            gss_release_buffer( &minor_status, &buf );
done:

            if( client_name != NULL )
            {
                gss_release_name( &minor_status, &client_name );
            }
        }
#endif
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( vas_gss_krb5_get_subkey )
{
    SPE_vas_ctx_t       *ctx;
    SPE_gss_ctx_id_t    *gssctx;
    zval                *zctx, *zgssctx, *zkey;
    OM_uint32           err;
    krb5_keyblock       *key = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrz",
                                    &zctx, &zgssctx, &zkey ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( gssctx, SPE_gss_ctx_id_t*, &zgssctx, -1,
                                PHP_gss_ctx_id_t_RES_NAME, le_gss_ctx_id_t );

    err = vas_gss_krb5_get_subkey( ctx->ctx, gssctx->raw, &key );

    if( err == GSS_S_COMPLETE )
    {
        SPE_CONS_VALUE( zkey, krb5_keyblock, key );
    }
    RETURN_LONG( err );
}

ZEND_VAS_NAMED_FUNC( new_gss_buffer_desc )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( delete_gss_buffer_desc )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( new_gss_OID_desc )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( delete_gss_OID_desc )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( new_gss_OID_set_desc )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( delete_gss_OID_set_desc )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( new_gss_channel_bindings_struct )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( delete_gss_channel_bindings_struct )
{
    /*IMPLEMENT*/
}

#if 0
ZEND_VAS_NAMED_FUNC( gss_c_nt_user_name_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_user_name_get )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_machine_uid_name_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_machine_uid_name_get )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_string_uid_name_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_string_uid_name_get )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_hostbased_service_x_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_hostbased_service_x_get )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_hostbased_service_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_hostbased_service_get )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_anonymous_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_anonymous_get )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_export_name_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_c_nt_export_name_get )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_spnego_mechanism_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_spnego_mechanism_get )
{
    /*IMPLEMENT*/
}
#endif

ZEND_VAS_NAMED_FUNC( gss_acquire_cred )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_add_cred )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_inquire_cred )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_inquire_cred_by_mech )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_init_sec_context )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_accept_sec_context )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_process_context_token )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_context_time )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_inquire_context )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_wrap_size_limit )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_export_sec_context )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_import_sec_context )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_get_mic )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_verify_mic )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_wrap )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_unwrap )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_sign )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_verify )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_seal )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_unseal )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_import_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_display_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_compare_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_release_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_inquire_names_for_mech )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_inquire_mechs_for_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_canonicalize_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_export_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_duplicate_name )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_display_status )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_create_empty_oid_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_add_oid_set_member )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_test_oid_set_member )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_release_oid_set )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_release_buffer )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( gss_indicate_mechs )
{
    /*IMPLEMENT*/
}

ZEND_VAS_NAMED_FUNC( vas_krb5_get_context )
{
    SPE_vas_ctx_t   *ctx;
    zval            *zctx;
    vas_err_t       err;
    krb5_context    krb5ctx;

    SPE_CHECK_ARGS( 1 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "r",
                                        &zctx ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                    PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );

    err = vas_krb5_get_context( ctx->ctx, &krb5ctx );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( krb5_context, krb5ctx );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_krb5_get_principal )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id;
    zval            *zctx, *zid;
    vas_err_t       err;
    krb5_principal  krb5princ;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                        &zctx, &zid ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                    PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                    PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_krb5_get_principal( ctx->ctx, id->raw, &krb5princ );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( krb5_principal, krb5princ );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_krb5_get_ccache )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id;
    zval            *zctx, *zid;
    vas_err_t       err;
    krb5_ccache     krb5cc;

    SPE_CHECK_ARGS( 2 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rr",
                                    &zctx, &zid ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_krb5_get_ccache( ctx->ctx, id->raw, &krb5cc );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( krb5_ccache, krb5cc );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_krb5_get_credentials )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id;
    zval            *zctx, *zid;
    vas_err_t       err;
    const char      *szTarget;
    int             lTarget;
    long            addtocache;
    krb5_creds      *creds;

    SPE_CHECK_ARGS( 4 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrsl",
                    &zctx, &zid, &szTarget, &lTarget, &addtocache ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                                PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );

    err = vas_krb5_get_credentials( ctx->ctx, id->raw,
                        lTarget == 0 ? NULL : szTarget, addtocache, &creds );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( krb5_creds, creds );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_krb5_validate_credentials )
{
    SPE_vas_ctx_t   *ctx;
    SPE_krb5_creds  *creds;
    zval            *zctx, *zcreds;
    vas_err_t       err;
    const char      *szKeytab;
    int             lKeytab;
    vas_auth_t      *auth = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrs",
                            &zctx, &zcreds, &szKeytab, &lKeytab ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                        PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    ZEND_FETCH_RESOURCE( creds, SPE_krb5_creds*, &zcreds, -1,
                        PHP_krb5_creds_RES_NAME, le_krb5_creds );

    err = vas_krb5_validate_credentials( ctx->ctx, creds->raw, szKeytab, &auth );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( vas_auth_t, auth );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_ldap_init_and_bind )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid;
    vas_err_t       err;
    const char      *szUri;
    int             lUri;
    LDAP            *ld = NULL;

    SPE_CHECK_ARGS( 3 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrs",
                                &zctx, &zid, &szUri, &lUri ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                                PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    err = vas_ldap_init_and_bind( ctx->ctx, id ? id->raw : NULL, szUri, &ld );

    SPE_SET_VAS_ERR( err );

    if( err == VAS_ERR_SUCCESS )
    {
        SPE_CONS_RETURN_VALUE( LDAP, ld );
    }
    else
    {
        RETURN_NULL();
    }
}

ZEND_VAS_NAMED_FUNC( vas_ldap_set_attributes )
{
    SPE_vas_ctx_t   *ctx;
    SPE_vas_id_t    *id = NULL;
    zval            *zctx, *zid, *zmods, **dataArray, **dataObject;
    vas_err_t       err = VAS_ERR_SUCCESS;
    const char      *szUri, *szDn;
    int             lUri, lDn;
    HashTable       *htmods;
    HashPosition    pmods;
    LDAPMod         **mods = NULL;
    int             mods_index = 0, mods_count;

    SPE_CHECK_ARGS( 5 );

    if( zend_parse_parameters( ZEND_NUM_ARGS() TSRMLS_CC, "rrssz",
                &zctx, &zid, &szUri, &lUri, &szDn, &lDn, &zmods ) == FAILURE )
    {
        RETURN_NULL();
    }
    ZEND_FETCH_RESOURCE( ctx, SPE_vas_ctx_t*, &zctx, -1,
                            PHP_vas_ctx_t_RES_NAME, le_vas_ctx_t );
    if( ! ZVAL_IS_NULL( zid ) )
    {
        ZEND_FETCH_RESOURCE( id, SPE_vas_id_t*, &zid, -1,
                            PHP_vas_id_t_RES_NAME, le_vas_id_t );
    }
    /* Create the mods array.
     * Test with null mod_values--should be OK--pass null mod_values.
     */
    if( Z_TYPE_P( zmods ) != IS_ARRAY )
    {
        err = VAS_ERR_INVALID_PARAM;
    }
    else
    {
        htmods = Z_ARRVAL_P( zmods );
        mods_count = zend_hash_num_elements( htmods );
        mods = emalloc( ( mods_count + 1 ) * sizeof( LDAPMod* ) );

        for( zend_hash_internal_pointer_reset_ex( htmods, &pmods );
              zend_hash_get_current_data_ex( htmods, ( void** )&dataArray,
                                            &pmods ) == SUCCESS;
              zend_hash_move_forward_ex( htmods, &pmods ) )
        {
            if( Z_TYPE_PP( dataArray ) == IS_OBJECT )
            {
                zend_class_entry* o = Z_OBJCE_P( *dataArray );

                /* See if it's the right type.*/
                if( strcmp( o->name, "cvas_ldapmod" ) != 0 )
                {
                    err = VAS_ERR_INVALID_PARAM;
                    continue;
                }
                /* Allocate memory.*/
                LDAPMod* m = mods[mods_index++] = emalloc( sizeof( LDAPMod ) );

                /* set the struct to 0 for cleanup health later.*/
                memset( m, 0, sizeof( *m ) );

                /* get mod_op*/
                if( zend_hash_find( Z_OBJPROP_PP( dataArray ),
                                    "mod_op",
                                    sizeof( "mod_op" ),
                                    ( void** )&dataObject ) == FAILURE )
                {
                    err = VAS_ERR_INVALID_PARAM;
                    continue;
                }
                if( Z_TYPE_PP( dataObject ) != IS_LONG )
                {
                    err = VAS_ERR_INVALID_PARAM;
                    continue;
                }
                m->mod_op = Z_LVAL_PP( dataObject );

                /* get mod_type*/
                if( zend_hash_find( Z_OBJPROP_PP( dataArray ),
                                    "mod_type",
                                    sizeof( "mod_type" ),
                                    ( void** )&dataObject ) == FAILURE )
                {
                    err = VAS_ERR_INVALID_PARAM;
                    continue;
                }
                if( Z_TYPE_PP( dataObject ) != IS_STRING )
                {
                    err = VAS_ERR_INVALID_PARAM;
                    continue;
                }
                m->mod_type = Z_STRVAL_PP( dataObject );
                ZEND_PRINTF( "m->mod_type: %s\n", m->mod_type );

                /* get mod_values--array of strings */
                if( zend_hash_find( Z_OBJPROP_PP( dataArray ),
                                    "mod_values",
                                    sizeof( "mod_values" ),
                                    ( void** )&dataObject ) == FAILURE )
                {
                    err = VAS_ERR_INVALID_PARAM;
                    continue;
                }
                if( Z_TYPE_PP( dataObject ) == IS_NULL )
                {
                    m->mod_values = NULL;
                    ZEND_PRINTF( "m->mod_values: NULL\n" );
                }
                else if( Z_TYPE_PP( dataObject ) != IS_ARRAY )
                {
                    err = VAS_ERR_INVALID_PARAM;
                    continue;
                }
                else
                {
                    zval** value;
                    HashTable* htvalues = Z_ARRVAL_PP( dataObject );
                    HashPosition pvalues;
                    int values_count = zend_hash_num_elements( htvalues );
                    int values_index = 0;

                    m->mod_values = emalloc( ( values_count + 1 )
                                                * sizeof( const char * ) );

                    for( zend_hash_internal_pointer_reset_ex( htvalues,
                                                              &pvalues );
                          zend_hash_get_current_data_ex( htvalues,
                                      ( void** ) &value, &pvalues ) == SUCCESS;
                          zend_hash_move_forward_ex( htvalues, &pvalues ) )
                    {
                        m->mod_values[values_index++] = Z_STRVAL_PP( value );
                        ZEND_PRINTF( "_____m->mod_values = %s\n",
                                     Z_STRVAL_PP( value ) );
                    }
                    m->mod_values[values_index++] = NULL;
                }
            }
        }
        mods[mods_index++] = NULL;  /* Make sure null terminated.*/
    }

    if( err == VAS_ERR_SUCCESS )
    {
        err = vas_ldap_set_attributes( ctx->ctx,
                                       ( id ) ? id->raw : NULL,
                                       szUri,
                                       szDn,
                                       mods );
    }

    /* Free the mods structure. The docs say to call ldap_mods_free, but we
     * can't do that since they can't call efree().
     *
     * Note that all the strings are pointers into the PHP data structures
     * so we don't free those.
     */
    if( mods )
    {
        LDAPMod** m;

        for( m = mods; *m != NULL; m++ )
        {
            LDAPMod* mod = *m;

            if( mod->mod_values )
            {
                efree( mod->mod_values );
            }
            efree( mod );
        }
        efree( mods );
    }
    SPE_SET_VAS_ERR( err );

    RETURN_NULL();
}

/* end zif_ section */

/* init section */
#ifdef __cplusplus
extern "C" {
#endif
ZEND_GET_MODULE( vas )
#ifdef __cplusplus
}
#endif

static void php_vas_init_globals( zend_vas_globals* vas_globals )
{
    /* EMPTY */
}

PHP_MSHUTDOWN_FUNCTION( vas )
{
    return SUCCESS;
}

PHP_MINIT_FUNCTION( vas )
{
    zend_class_entry ce;

    INIT_CLASS_ENTRY( ce, "CVAS_passwd", NULL );
    vas_CVAS_passwd_entry = zend_register_internal_class( &ce TSRMLS_CC );

    INIT_CLASS_ENTRY( ce, "CVAS_err_info", NULL );
    vas_CVAS_err_info_entry = zend_register_internal_class( &ce TSRMLS_CC );

    SPE_REGISTER_DTOR( vas_ctx_t );
    SPE_REGISTER_DTOR( vas_attrs_t );
    SPE_REGISTER_DTOR( vas_id_t );
    SPE_REGISTER_DTOR( vas_auth_t );
    SPE_REGISTER_DTOR( vas_user_t );
    SPE_REGISTER_DTOR( vas_group_t );
    SPE_REGISTER_DTOR( vas_service_t );
    SPE_REGISTER_DTOR( vas_computer_t );
    SPE_REGISTER_DTOR( gss_cred_id_t );
    SPE_REGISTER_DTOR( gss_ctx_id_t );
    /*SPE_REGISTER_DTOR( gss_buffer_t );*/
    SPE_REGISTER_DTOR( krb5_keyblock );
    SPE_REGISTER_DTOR( krb5_context );
    SPE_REGISTER_DTOR( krb5_principal );
    SPE_REGISTER_DTOR( krb5_ccache );
    SPE_REGISTER_DTOR( krb5_creds );
    SPE_REGISTER_DTOR( LDAP );

    ZEND_INIT_MODULE_GLOBALS( vas, php_vas_init_globals, NULL );

    return SUCCESS;
}

PHP_RINIT_FUNCTION( vas )
{
    /* Convenience macro for registering a persistent VAS constant */
#define REGISTER_LONG_VAS_CONSTANT(c) \
    REGISTER_LONG_CONSTANT(#c, (c), CONST_CS | CONST_PERSISTENT )

    REGISTER_LONG_VAS_CONSTANT(VAS_ID_FLAG_USE_MEMORY_CCACHE);
    REGISTER_LONG_VAS_CONSTANT(VAS_ID_FLAG_KEEP_COPY_OF_CRED);
    REGISTER_LONG_VAS_CONSTANT(VAS_ID_FLAG_DO_NOT_DERIVE_KEYTAB);
    REGISTER_LONG_VAS_CONSTANT(VAS_ID_FLAG_NO_INITIAL_TGT);
#if HAVE_VAS_ID_FLAG_DERIVE_FILE_CCACHE_FROM_ID /* 3.1.0.47 */
    REGISTER_LONG_VAS_CONSTANT(VAS_ID_FLAG_DERIVE_FILE_CCACHE_FROM_ID);
#endif
    REGISTER_LONG_VAS_CONSTANT(VAS_ID_CRED_FLAG_RENEWABLE);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_FLAG_NO_CACHE);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_FLAG_NO_LDAP);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_FLAG_NO_IMPLICIT);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_FLAG_NO_DNS_EXPAND);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_FLAG_FOREST_SCOPE);

    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_BAD_ERR);

    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_SUCCESS);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_FAILURE);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_KRB5);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_KPASSWD);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_LDAP);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_INVALID_PARAM);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_NO_MEMORY);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_ACCESS);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_NOT_FOUND);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_THREAD);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_CONFIG);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_INTERNAL);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_EXISTS);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_DNS);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_CRED_EXPIRED);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_CRED_NEEDED);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_MORE_VALS);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_TIMEDOUT);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_INCOMPLETE);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_TYPE_VAS);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_TYPE_SYS);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_TYPE_KRB5);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_TYPE_KPASSWD);
    REGISTER_LONG_VAS_CONSTANT(VAS_ERR_TYPE_LDAP);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_DEFAULT_REALM);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_SITE_AND_FOREST_ROOT);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_ADD_SERVER);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_USE_TCP_ONLY);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_USE_GSSAPI_AUTHZ);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_USE_SRVINFO_CACHE);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_USE_DNSSRV);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_USE_VASCACHE);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_USE_VASCACHE_IPC);
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_USE_SERVER_REFERRALS);
#if VAS_API_IS(4,2)
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_SEPARATOR_IN_ERROR_MESSAGE_STRING);
#if HAVE_VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND /* 3.0.3.38 */
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_SRVINFO_DETECT_ONLY_UNTIL_FOUND);
#endif
#if HAVE_VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT /* 3.1.0.47 */
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_DNS_FAILURE_TIMELIMIT);
#endif
#endif /* VAS_API_IS(4,2) */
#if 0
    REGISTER_LONG_VAS_CONSTANT(VAS_CTX_OPTION_DOMAIN_NAMING_CONTEXT);
#endif

    REGISTER_LONG_VAS_CONSTANT(VAS_ATTRS_OPTION_SEARCH_TIMEOUT);
    REGISTER_LONG_VAS_CONSTANT(VAS_ATTRS_OPTION_LDAP_PAGESIZE);
    REGISTER_LONG_VAS_CONSTANT(VAS_ATTRS_B64_ENCODE_ATTRS);
    REGISTER_LONG_VAS_CONSTANT(VAS_SRVINFO_TYPE_ANY);
    REGISTER_LONG_VAS_CONSTANT(VAS_SRVINFO_TYPE_DC);
    REGISTER_LONG_VAS_CONSTANT(VAS_SRVINFO_TYPE_PDC);
    REGISTER_LONG_VAS_CONSTANT(VAS_SRVINFO_TYPE_GC);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_TYPE_UNKNOWN);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_TYPE_USER);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_TYPE_GROUP);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_TYPE_SERVICE);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_TYPE_HOST);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_TYPE_DN);
    REGISTER_LONG_VAS_CONSTANT(VAS_NAME_TYPE_SID);
    REGISTER_LONG_VAS_CONSTANT(VAS_GSS_SPNEGO_ENCODING_DER);
    REGISTER_LONG_VAS_CONSTANT(VAS_GSS_SPNEGO_ENCODING_BASE64);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_UNSPEC);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_LOCAL);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_INET);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_IMPLINK);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_PUP);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_CHAOS);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_NS);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_NBS);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_ECMA);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_DATAKIT);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_CCITT);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_SNA);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_DECnet);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_DLI);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_LAT);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_HYLINK);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_APPLETALK);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_BSC);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_DSS);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_OSI);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_X25);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_INET6);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_AF_NULLADDR);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_DELEG_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_MUTUAL_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_REPLAY_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_SEQUENCE_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_CONF_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_INTEG_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_ANON_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_PROT_READY_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_TRANS_FLAG);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_BOTH);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_INITIATE);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_ACCEPT);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_GSS_CODE);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_MECH_CODE);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_QOP_DEFAULT);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_INDEFINITE);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_CALLING_ERROR_OFFSET);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_ROUTINE_ERROR_OFFSET);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_SUPPLEMENTARY_OFFSET);
    REGISTER_LONG_VAS_CONSTANT(GSS_C_NO_CONTEXT);	/* XXX not a long */
    REGISTER_LONG_VAS_CONSTANT(GSS_C_NO_CREDENTIAL);	/* XXX not a long */
    REGISTER_STRING_CONSTANT(  "GSS_C_NO_BUFFER",
                            "",                   CONST_CS | CONST_PERSISTENT );
    REGISTER_LONG_VAS_CONSTANT(GSS_S_CALL_INACCESSIBLE_READ);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_CALL_INACCESSIBLE_WRITE);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_CALL_BAD_STRUCTURE);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_MECH);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_NAME);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_NAMETYPE);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_BINDINGS);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_STATUS);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_MIC);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_SIG);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_NO_CRED);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_NO_CONTEXT);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_DEFECTIVE_TOKEN);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_DEFECTIVE_CREDENTIAL);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_CREDENTIALS_EXPIRED);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_CONTEXT_EXPIRED);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_FAILURE);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_BAD_QOP);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_UNAUTHORIZED);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_UNAVAILABLE);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_DUPLICATE_ELEMENT);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_NAME_NOT_MN);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_CONTINUE_NEEDED);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_DUPLICATE_TOKEN);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_OLD_TOKEN);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_UNSEQ_TOKEN);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_GAP_TOKEN);
    REGISTER_LONG_VAS_CONSTANT(GSS_S_COMPLETE);
    REGISTER_LONG_VAS_CONSTANT(LDAP_MOD_ADD);
    REGISTER_LONG_VAS_CONSTANT(LDAP_MOD_DELETE);
    REGISTER_LONG_VAS_CONSTANT(LDAP_MOD_REPLACE);
    REGISTER_LONG_VAS_CONSTANT(LDAP_MOD_BVALUES);
/* end cinit subsection */

/* vinit subsection */
/* end vinit subsection */

   /*SPE*/
    memset( &( VAS_G( g_vas_err ) ),       sizeof( VAS_G( g_vas_err ) ), 0 );
    memset( &( VAS_G( g_vas_err_minor ) ), sizeof( VAS_G( g_vas_err_minor ) ), 0 );

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION( vas )
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION( vas )
{
}
/* end init section */
