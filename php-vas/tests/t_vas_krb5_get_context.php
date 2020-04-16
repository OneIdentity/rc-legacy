<?

include("test.php");

function t_vas_krb5_get_context()
{
  $c = vas_ctx_alloc();

  $krb5 = vas_krb5_get_context($c);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($krb5, "krb5_context");
}

runTest("t_vas_krb5_get_context");

?>
