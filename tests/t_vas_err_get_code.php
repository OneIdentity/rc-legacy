<?

include("test.php");

function t_vas_err_get_code()
{
  $c2 = vas_ctx_alloc();
  $c = cause_invalid_param();

  if (vas_err() != VAS_ERR_INVALID_PARAM) return 100;
  if (vas_err_get_code($c) != VAS_ERR_INVALID_PARAM) return 101;
  if (vas_err_get_code($c2) != VAS_ERR_SUCCESS) return 102;
}

runTest("t_vas_err_get_code");

?>
