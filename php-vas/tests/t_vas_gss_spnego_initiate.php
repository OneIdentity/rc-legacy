<?

include("test.php");

function t_vas_gss_spnego_initiate()
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

  $gss_ctx = GSS_C_NO_CONTEXT;

  $gsserr = vas_gss_spnego_initiate($c, $i, null, $gss_ctx,
		"host/c2.example.com",
		0,
		VAS_GSS_SPNEGO_ENCODING_BASE64,
		GSS_C_NO_BUFFER,
		$out_token);

  //printf("gsserr = %x, out='%s'\n", $gsserr, $out_token);
  if (GSS_ERROR($gsserr))
  {
    //printf("vas_err = %s\n", vas_err_get_string($c, 1));
    return 200;
  }
  $rv = testResource($gss_ctx, "gss_ctx_id_t");
  if ($rv) return $rv;
}

runTest("t_vas_gss_spnego_initiate");

?>
