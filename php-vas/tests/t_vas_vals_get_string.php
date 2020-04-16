<?

include("test.php");

function t_vas_vals_get_string()
{
  global $username;
  global $password;
  global $credflags;
  global $scope;
  global $search_base;
  global $attrs_names1;
  global $attrs_val1;
  global $uri;
  global $search_filter1;

  $c = vas_ctx_alloc();
  $a = vas_attrs_alloc($c, null);

  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  //
  // This will fail if the cred has not been established.
  //
  $a = vas_attrs_alloc($c, $i);

  $rv = testResource($a, "vas_attrs_t");
  if ($rv) return $rv;
  vas_attrs_find( $c, $a, $uri, $scope, $search_base, $search_filter1, $attrs_names1 );
  if( vas_err() != VAS_ERR_SUCCESS )
  {
    return 101;
  }
  while( vas_err() == VAS_ERR_SUCCESS )
  {
    do
    {
      /* Get an entry from the results, one at a time */
      $strvals[] = vas_vals_get_string ( $c, $a, $attrs_names1[0]);
    } while( vas_err() == VAS_ERR_MORE_VALS );

    /* The first vas_attrs_find may not return all of the possible results.
     * In many cases you only want to get the first entry so for performance
     * reasons this is the behavior.  If you want more than one result you
     * must request more items and loop again for the results. */
    vas_attrs_find_continue( $c, $a );
  }
  //
  // $strvals[0] should be the phone number
  //
  if ($strvals[0][0] != $attrs_val1) return 200;
}

runTest("t_vas_vals_get_string");

?>
