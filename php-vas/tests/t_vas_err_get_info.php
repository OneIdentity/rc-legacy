<?

include("test.php");

function t_vas_err_get_info()
{
  $c = cause_invalid_param();

  $info = vas_err_get_info($c);

  $c = vas_ctx_alloc(); // to set vas_err() to success.

  return testStruct($info, array("code", "type", "cause", "message"));
}

runTest("t_vas_err_get_info");

?>
