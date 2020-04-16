<?

include("test.php");

function t_vas_group_init()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($group, "vas_group_t");
  if ($test) return $test;

  $group = vas_group_init($c, $i, "does not exist", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 103;
  if ($group != null) return 104;
}

runTest("t_vas_group_init");

?>
