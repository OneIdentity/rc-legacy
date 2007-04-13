<?

include("test.php");

function t_vas_computer_init()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($computer, "vas_computer_t");
  if ($test) return $test;

  $computer = vas_computer_init($c, $i, "does not exist", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 103;
  if ($computer != null) return 104;
}

runTest("t_vas_computer_init");

?>
