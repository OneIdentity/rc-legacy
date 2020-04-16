<?

include("test.php");

function t_vas_ctx_alloc()
{
  $c = vas_ctx_alloc();
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($c, "vas_ctx_t");
}

runTest("t_vas_ctx_alloc");

?>
