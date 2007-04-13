<?

include("test.php");

function t_vas_id_get_user()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $user = vas_id_get_user($c, $i);

  return testResource($user, "vas_user_t");
}

runTest("t_vas_id_get_user");

?>
