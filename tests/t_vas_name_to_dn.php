<?

include("test.php");

function t_vas_name_to_dn()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_name_to_dn($c, $i, $username,
		 VAS_NAME_TYPE_UNKNOWN,
		 VAS_NAME_FLAG_NO_CACHE,
		 $nameout, $domainout);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  if ($nameout != "CN=testuser,CN=Users,DC=dan,DC=vas") return 102;
  if ($domainout != "DAN.VAS") return 103;
}

runTest("t_vas_name_to_dn");

?>
