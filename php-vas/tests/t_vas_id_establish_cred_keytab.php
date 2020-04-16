<?

include("test.php");

function t_vas_id_establish_cred_keytab()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  //
  // Can't really test the functionality here, so just test
  // the prototyping.  Tested in vas_auth()
  //
  $err = vas_id_establish_cred_keytab($c, $i, VAS_ID_FLAG_USE_MEMORY_CCACHE, null);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 101;

  $err = vas_id_establish_cred_keytab($c, $i, VAS_ID_FLAG_USE_MEMORY_CCACHE, "fubar");
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 101;
}

runTest("t_vas_id_establish_cred_keytab");

?>
