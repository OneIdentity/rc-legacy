<?

include("test.php");

function t_vas_ctx_get_option()
{
  $c = vas_ctx_alloc();
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_DNSSRV);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_TCP_ONLY);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_GSSAPI_AUTHZ);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SERVER_REFERRALS);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, 55);
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 300;
}

runTest("t_vas_ctx_get_option");

?>
