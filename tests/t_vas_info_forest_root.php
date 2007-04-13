<?

include("test.php");

function t_vas_info_forest_root()
{
  vas_info_forest_root(vas_ctx_alloc(), $forest_root, $forest_root_dn);

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($forest_root != "dan.vas") return 101;
  if ($forest_root_dn != "DC=dan,DC=vas") return 102;
}

runTest("t_vas_info_forest_root");

?>
