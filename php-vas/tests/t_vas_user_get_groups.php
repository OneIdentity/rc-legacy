<?

include("test.php");

function t_vas_user_get_groups()
{
  global $username;
  global $credflags;
  global $password;

  $expectedGroups = array("Users", "testgroup", "Domain Users");

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $groups = vas_user_get_groups($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 103;

  foreach ($groups as $g)
  {
    $name = vas_group_get_dn($c, $i, $g);
    $pos = 0;
    foreach ($expectedGroups as $e)
    {
      if (strstr($name, $e) != false)
      {
	    array_splice($expectedGroups, $pos, 1);
	    break;
      }
      $pos++;
    }
  }
  if (count($expectedGroups) != 0) return 200;
}

runTest("t_vas_user_get_groups");

?>
