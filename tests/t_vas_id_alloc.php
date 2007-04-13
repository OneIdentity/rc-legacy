<?

include("test.php");

function t_vas_id_alloc()
{
  global $username;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($i, "vas_id_t");
  if ($rv) return $rv;

  $i = null;
  $i = vas_id_alloc($c, null);

  $rv = testResource($i, "vas_id_t");
  if ($rv) return $rv;
}

runTest("t_vas_id_alloc");

?>
