<?

include("test.php");

function t_vas_service_get_spns()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $service = vas_service_init($c, $i, "ldap/DC1", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_service_get_spns($c, $i, $service);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  if (!array_search("DNS/dc1.example.com", $s)) return 103;
  if (!array_search("ldap/DC1", $s)) return 104;
  if (!array_search("HOST/DC1", $s)) return 105;
}

runTest("t_vas_service_get_spns");

?>
