<?

include("test.php");

function t_vas_user_is_member()
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

  $groupBad = vas_group_init($c, $i, "Administrators", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 105;

  $err = vas_user_is_member($c, $i, $user, $group);
  if ($err != VAS_ERR_SUCCESS) return 103;

  $err = vas_user_is_member($c, $i, $user, $groupBad);
  if ($err != VAS_ERR_NOT_FOUND) return 104;
}

runTest("t_vas_user_is_member");

?>
