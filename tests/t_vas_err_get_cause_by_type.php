<?

include("test.php");

function t_vas_err_get_cause_by_type()
{
  $c = cause_invalid_param();

  $info1 = vas_err_get_cause_by_type($c, VAS_ERR_TYPE_VAS);
  $info2 = vas_err_get_cause_by_type($c, VAS_ERR_TYPE_SYS);

  $c2 = vas_ctx_alloc(); // to set vas_err() to success.

  if ($info1 != null) return 101;
  if ($info2 != null) return 102;
}

runTest("t_vas_err_get_cause_by_type");

?>
