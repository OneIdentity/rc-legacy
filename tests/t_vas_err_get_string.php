<?

include("test.php");

function t_vas_err_get_string()
{
  $c = cause_invalid_param();

  $s1 = vas_err_get_string($c, 0);
  $s2 = vas_err_get_string($c, 1);

  // note that $s1 and $s2 seem to be the same with either with_clause
  if (stristr($s1, "VAS_ERR_INVALID_PARAM") === FALSE) return 100;
  if (stristr($s2, "VAS_ERR_INVALID_PARAM") === FALSE) return 101;
}

runTest("t_vas_err_get_string");

?>
