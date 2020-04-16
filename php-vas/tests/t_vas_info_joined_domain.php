<?

include("test.php");

function t_vas_info_joined_domain()
{
  vas_info_joined_domain(vas_ctx_alloc(), $domain, $domain_dn);

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($domain != "dan.vas") return 101;
  if ($domain_dn != "DC=dan,DC=vas") return 102;
}

runTest("t_vas_info_joined_domain");

?>
