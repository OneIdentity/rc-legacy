<?

include("test.php");

function t_vas_ldap_init_and_bind()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $ldap = vas_ldap_init_and_bind($c, $i, "DC://");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($ldap, "LDAP");
}

runTest("t_vas_ldap_init_and_bind");

?>
