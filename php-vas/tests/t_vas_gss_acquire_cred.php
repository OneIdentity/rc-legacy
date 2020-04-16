<?

include("test.php");

function t_vas_gss_acquire_cred()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, "host/");

  vas_id_establish_cred_keytab( $c, $i, VAS_ID_FLAG_USE_MEMORY_CCACHE | VAS_ID_FLAG_KEEP_COPY_OF_CRED, null );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_gss_initialize($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $cred = vas_gss_acquire_cred($c, $i, GSS_C_INITIATE);

  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $rv = testResource($cred, "gss_cred_id_t");
  if ($rv) return $rv;
}

runTest("t_vas_gss_acquire_cred");

?>
