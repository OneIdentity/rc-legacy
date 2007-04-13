<?

include("test.php");

function t_vas_group_get_dn()
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
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_group_get_dn($c, $i, $group);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != "CN=$groupname,DC=example,DC=com") return 103;
}

runTest("t_vas_group_get_dn");

?>
