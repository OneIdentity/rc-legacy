<?

include("test.php");

function t_vas_service_get_krb5_client_name()
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

  $s = vas_service_get_krb5_client_name($c, $i, $service);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "DC1$@DAN.VAS") return 301;
}

runTest("t_vas_service_get_krb5_client_name");

?>
