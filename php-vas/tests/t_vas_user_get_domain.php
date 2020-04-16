<?

include("test.php");

function t_vas_user_get_domain()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_domain($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != "DAN.VAS") return 103;
}

runTest("t_vas_user_get_domain");

?>
