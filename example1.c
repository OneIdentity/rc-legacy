#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include </opt/quest/include/vas.h>

static void die( const char *format, ... )
{
  va_list ap;

  va_start( ap, format );
  vprintf( format, ap );
  va_end( ap );
  exit( 1 );
}

int main(int argc, char **argv)
{
  const char  *username = "jdoe";
  const char  *password = "jdoepassword";
  const char  *groupname;
  vas_ctx_t   *ctx;
  vas_id_t    *id;
  vas_group_t *group;
  vas_user_t  *user;
  vas_err_t   err;

  // groupname = "CN=Users,CN=Builtin,DC=example,DC=com";
  groupname = "Test Users";

  err = vas_ctx_alloc( &ctx );
  if( err != VAS_ERR_SUCCESS ) die("vas_ctx_alloc failed %d\n", err );

  // auth
  err = vas_id_alloc( ctx, username, &id );
  if( err != VAS_ERR_SUCCESS ) die("vas_id_alloc failed %d\n", err );

  err = vas_id_establish_cred_password( ctx, id, VAS_ID_FLAG_USE_MEMORY_CCACHE, password );
  if( err != VAS_ERR_SUCCESS ) die("vas_id_establish_cred_password failed %d\n", err );

  // see if in group
  err = vas_group_init( ctx, id, groupname, 0, &group );
  if( err != VAS_ERR_SUCCESS ) die("vas_group_init failed %d\n", err );

  err = vas_user_init( ctx, id, username, 0, &user );
  if( err != VAS_ERR_SUCCESS ) die("vas_user_init failed %d\n", err );

  err = vas_group_has_member( ctx, id, group, user );
  if( err != VAS_ERR_SUCCESS ) die("vas_group_has_member failed %d\n", err );

  return 0;
}
