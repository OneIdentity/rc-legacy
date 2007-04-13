<?

include("test.php");

function t_vas_info_site()
{
  $site = vas_info_site(vas_ctx_alloc());

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($site != "Default-First-Site-Name") return 101;
}

runTest("t_vas_info_site");

?>
