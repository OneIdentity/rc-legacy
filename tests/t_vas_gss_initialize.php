<?

include("test.php");

function t_vas_gss_initialize()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_gss_initialize($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
}

runTest("t_vas_gss_initialize");

?>
