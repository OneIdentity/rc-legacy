<?

include("test.php");

function t_vas_id_renew_cred()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  /* NOTE: NOTE: Fails when root! */
  if (vas_err() == VAS_ERR_SUCCESS) return 100;

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  vas_id_renew_cred( $c, $i, 0 );
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
}

runTest("t_vas_id_renew_cred");

?>
