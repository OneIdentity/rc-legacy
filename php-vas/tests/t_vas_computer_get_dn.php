<?

include("test.php");

function t_vas_computer_get_dn()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_dn($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "CN=DC1,OU=Domain Controllers,DC=example,DC=com") return 103;
}

runTest("t_vas_computer_get_dn");

?>
