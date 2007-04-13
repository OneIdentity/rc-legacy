<?

include("test.php");

function t_vas_attrs_alloc()
{
  global $username;
  global $password;
  global $credflags;

  $c = vas_ctx_alloc();
  $a = vas_attrs_alloc($c, null);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($a, "vas_attrs_t");
  if ($rv) return $rv;

  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  $a = vas_attrs_alloc($c, $i);

  $rv = testResource($a, "vas_attrs_t");
  if ($rv) return $rv;
}

runTest("t_vas_attrs_alloc");

?>
