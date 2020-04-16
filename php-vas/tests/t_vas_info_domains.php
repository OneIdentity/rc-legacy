<?

include("test.php");

function t_vas_info_domains()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_info_domains($c, $i, $domains, $domains_dn);

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($domains[0] != "dan.vas") return 101;
  if ($domains_dn[0] != "DC=dan,DC=vas") return 102;
}

runTest("t_vas_info_domains");

?>
