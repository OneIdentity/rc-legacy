<?

include("test.php");

function t_vas_id_get_keytab_name()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $s = vas_id_get_keytab_name($c, $i);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 100;  // we don't have one.
}

runTest("t_vas_id_get_keytab_name");

?>
