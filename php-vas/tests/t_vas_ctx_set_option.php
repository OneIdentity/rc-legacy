<?

include("test.php");

function t_vas_ctx_set_option()
{
  //
  // we can't test most of the options, so the goal is to test
  // the classes of parameters to the options.
  //
  $c = vas_ctx_alloc();
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  vas_ctx_set_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE, 0);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  $optNew = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  if ($optNew != 0) return 201;
  vas_ctx_set_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE, $opt);
  $optNew = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  if ($optNew != $opt) return 202;

  $err = vas_ctx_set_option($c, VAS_CTX_OPTION_DEFAULT_REALM, 0); // should be string
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 300;

  vas_ctx_set_option($c, VAS_CTX_OPTION_SITE_AND_FOREST_ROOT, "", 0);
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 400;

  $opt = vas_ctx_set_option($c, 55, null);
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 900;
}

runTest("t_vas_ctx_set_option");

?>
