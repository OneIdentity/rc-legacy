<?

include("test.php");

function t_vas_auth_check_client_membership()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  /* NOTE: NOTE: MUST BE ROOT TO RUN THIS TEST!!!!! */

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_id_alloc($c, "host/");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_id_establish_cred_keytab($c, $computer, VAS_ID_FLAG_USE_MEMORY_CCACHE, null);

  $a = vas_auth_with_password($c, $username, $password, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_auth_check_client_membership($c, $i, $a, "no group name");
  if ($err != vas_err()) return 99;
  if (vas_err() == VAS_ERR_SUCCESS) return 103;

  $err = vas_auth_check_client_membership($c, $i, $a, $groupname);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_SUCCESS) return 104;
}

runTest("t_vas_auth_check_client_membership");

?>
