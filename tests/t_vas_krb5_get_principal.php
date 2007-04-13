<?

include("test.php");

function t_vas_krb5_get_principal()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $krb5 = vas_krb5_get_principal($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($krb5, "krb5_principal");
}

runTest("t_vas_krb5_get_principal");

?>
