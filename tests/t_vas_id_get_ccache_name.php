<?

include("test.php");

function t_vas_id_get_ccache_name()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $s = vas_id_get_ccache_name($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if (strpos($s, "MEMORY:vas-ccache") === false) return 101;
}

runTest("t_vas_id_get_ccache_name");

?>
