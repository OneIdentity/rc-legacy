<?

include("test.php");

function t_vas_info_servers()
{
  $servers = vas_info_servers(vas_ctx_alloc(), null, null, VAS_SRVINFO_TYPE_ANY);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($servers[0] != "booger.dan.vas") return 101;

  $servers = vas_info_servers(vas_ctx_alloc(), null, "*", VAS_SRVINFO_TYPE_ANY);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if ($servers[0] != "booger.dan.vas") return 201;
}

runTest("t_vas_info_servers");

?>
