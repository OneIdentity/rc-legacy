<?

include("test.php");

function t_vas_err_info_get_string()
{
  $c = cause_invalid_param();

  $info = vas_err_get_info($c);

  $c2 = vas_ctx_alloc(); // to set vas_err() to success.

  $s1 = vas_err_info_get_string($c, $info, 0);

  if ( ($s1 != "VAS_ERR_INVALID_PARAM: id must not be NULL")
    && ($s1 != "VAS_ERR_INVALID_PARAM: at id.c:445 in vas_id_alloc\n   id must not be NULL" ) )
      return 101;
}

runTest("t_vas_err_info_get_string");

?>
