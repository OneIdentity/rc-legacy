<?

include("test.php");

function t_vas_computer_is_member()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;
  global $dcgroup;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_computer_is_member($c, $i, $computer, $group);
  if ($err != vas_err()) return 103;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 104;

  $group = vas_group_init($c, $i, $dcgroup, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 201;

  $err = vas_computer_is_member($c, $i, $computer, $group);
  if ($err != vas_err()) return 203;
  if (vas_err() != VAS_ERR_SUCCESS) return 204;
}

runTest("t_vas_computer_is_member");

?>
