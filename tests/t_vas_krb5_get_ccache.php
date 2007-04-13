<?

include("test.php");

function t_vas_krb5_get_ccache()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $krb5 = vas_krb5_get_ccache($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($krb5, "krb5_ccache");
}

runTest("t_vas_krb5_get_ccache");

?>
