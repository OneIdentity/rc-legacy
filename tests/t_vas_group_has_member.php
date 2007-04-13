<?

include("test.php");

function t_vas_group_has_member()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_group_has_member($c, $i, $group, $user);
  if ($err != vas_err()) return 100;
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $user2 = vas_user_init($c, $i, "Administrator", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_group_has_member($c, $i, $group, $user2);
  if ($err != vas_err()) return 103;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 104;
}

runTest("t_vas_group_has_member");

?>
