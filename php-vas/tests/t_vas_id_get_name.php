<?

include("test.php");

function t_vas_id_get_name()
{
  global $username;
  global $credflags;
  global $password;
  global $principal, $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $err = vas_id_get_name($c, $i, $p, $d);
  if ($err != vas_err()) return 101;
  if ($p != $principal) return 102;
  if ($d != "CN=$username,CN=Users,DC=dan,DC=vas") return 103;
}

runTest("t_vas_id_get_name");

?>
