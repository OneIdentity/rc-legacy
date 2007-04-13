<?

include("test.php");

function t_vas_auth_get_client_groups()
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

  $g = vas_auth_get_client_groups($c, $i, $a);
  if (vas_err() != VAS_ERR_SUCCESS) return 103;

  if (!is_array($g)) return 104;
  if (count($g) < 2) return 105;

  return testResource($g[0], "vas_group_t");
}

runTest("t_vas_auth_get_client_groups");

?>
