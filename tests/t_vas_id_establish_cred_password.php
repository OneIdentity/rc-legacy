<?

include("test.php");

function t_vas_id_establish_cred_password()
{
  global $username;
  global $password;
  global $credflags;

  $c = vas_ctx_alloc();
  $a = vas_attrs_alloc($c, null);

  $i = vas_id_alloc($c, $username);

    /* Establish the credential using one of the vas_id_establish_cred_TYPE calls.
     * In this case we use password and will pass the password in for the id.
     * The credflags is a flag which allows you to decide what is done with the
     * credential once it is valid.  The VAS_ID_FLAG_USE_MEMORY_CCACHE flag will cause
     * credential to be destroyed once the id is freed.  The
     * VAS_ID_FLAG_KEEP_COPY_OF_CRED flag will cause the credential to be stored to the
     * users cache and not require the user to authenticate again unless the cache
     * is cleared. */
  $err = vas_id_establish_cred_password( $c, $i, $credflags, null );
  if ($err != vas_err()) return 99;
  if (vas_err() == VAS_ERR_SUCCESS) return 101;

  vas_id_establish_cred_password( $c, $i, $credflags, "" );
  if (vas_err() == VAS_ERR_SUCCESS) return 101;

  vas_id_establish_cred_password( $c, $i, $credflags, "notCorrect" );
  if (vas_err() == VAS_ERR_SUCCESS) return 101;

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  //
  // This will fail if the cred has not been established.
  //
  $a = vas_attrs_alloc($c, $i);

  $rv = testResource($a, "vas_attrs_t");
  if ($rv) return $rv;
}

runTest("t_vas_id_establish_cred_password");

?>
