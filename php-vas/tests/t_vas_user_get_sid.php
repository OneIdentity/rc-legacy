<?

include("test.php");

function t_vas_user_get_sid()
{
  global $username;
  global $credflags;
  global $password;
  global $usersid;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_sid($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != $usersid) return 103;
}

runTest("t_vas_user_get_sid");

?>
