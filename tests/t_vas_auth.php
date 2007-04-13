<?

include("test.php");

function t_vas_auth()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();

  $server_id = vas_id_alloc($c, "host/");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

    /* Establish creds for the server ("host/") using the keytab.
     * We pass NULL in for the keytab to allow the VAS library to
     * use the default keytab for our service.  In the case case of
     * the "host/" principal we'll end up using
     * /etc/opt/quest/vas/host.keytab.
     *
     * We also use the AS_ID_FLAG_USE_MEMORY_CCACHE and
     * VAS_ID_FLAG_NO_INITIAL_TGT flags, because we don't need a file
     * credental cache and we don't need a TGT.
     */
  vas_id_establish_cred_keytab( $c, $server_id,
				VAS_ID_FLAG_USE_MEMORY_CCACHE | VAS_ID_FLAG_NO_INITIAL_TGT,
				null);

  /* NOTE: NOTE: MUST BE ROOT TO RUN THIS TEST!!!!! */

  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  /* Allocate our client id using the specified name */

  $client_id = vas_id_alloc($c, $username);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  /* Establish credentials for the client id */

  vas_id_establish_cred_password( $c,
				  $client_id,
				  0,
				  $password);
  if (vas_err() != VAS_ERR_SUCCESS) return 103;

  /* Perform the actual authentication */

  $auth = vas_auth( $c, $client_id, $server_id);
  if (vas_err() != VAS_ERR_SUCCESS) return 104;

  return testResource($auth, "vas_auth_t");
}

runTest("t_vas_auth");

?>
