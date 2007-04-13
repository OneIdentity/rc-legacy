<?

include("test.php");

function t_vas_err_clear()
{
  $c = cause_invalid_param();

  if (vas_err() != VAS_ERR_INVALID_PARAM) return 100;

  vas_err_clear($c);

  if (vas_err() != VAS_ERR_SUCCESS) return 101;
}

runTest("t_vas_err_clear");

?>
