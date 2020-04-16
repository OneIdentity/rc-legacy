<?

include("test.php");

function t_vas_auth_with_password()
{
  global $username;
  global $credflags;
  global $password;

  /* NOTE: NOTE: MUST BE ROOT TO RUN THIS TEST!!!!! */

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_id_alloc($c, "host/");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $a = vas_auth_with_password($c, $username, "wrong password", $computer);
  if (vas_err() == VAS_ERR_SUCCESS) return 101;

  vas_id_establish_cred_keytab($c, $computer, VAS_ID_FLAG_USE_MEMORY_CCACHE, null);

  $a = vas_auth_with_password($c, $username, $password, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  return testResource($a, "vas_auth_t");
}

runTest("t_vas_auth_with_password");

?>
