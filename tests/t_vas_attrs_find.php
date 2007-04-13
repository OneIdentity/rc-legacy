<?

include("test.php");

function t_vas_attrs_find()
{
  global $username;
  global $password;
  global $credflags;
  global $scope;
  global $search_base;
  global $attrs_names2;
  global $uri;
  global $search_filter2;

  $results_found = 0;

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
  //
  // Do the find.
  //
  /* Begin the search.  The URI argument specifies if we want to talk to a DC, GC, or you can
   * specify a specific server to access (such as DC://server1.example.com).  The scope is used
   * to specify where in the tree you want to search.  Attrs_names is a NULL terminated list
   * of attributes that we want to retrieve for the items that our search filter matches. */
  vas_attrs_find( $c, $a, $uri, $scope, $search_base, $search_filter2, $attrs_names2 );
  if( vas_err() != VAS_ERR_SUCCESS )
  {
    printf("Failure to find attrs.  Code %s\n", vas_err_get_string( $c, 1 ));
    printf("uri: $uri\n");
    printf("scope: $scope\n");
    printf("search_base: $search_base\n");
    printf("search_filter: $search_filter2\n");
    printf("attrs_names: "); print_r($attrs_names2); printf("\n");
    return 101;
  }
  while( vas_err() == VAS_ERR_SUCCESS )
  {
    do
    {
      /* Get an entry from the results, one at a time */
      $strvals = vas_vals_get_string ( $c, $a, $attrs_names2[0]);

      if(( vas_err() == VAS_ERR_SUCCESS || vas_err() == VAS_ERR_MORE_VALS )
         && count($strvals) )
	  {
	    $results_found++;
	    /* This is when we have a valid result and can process
	     * it however we need to */
	    /*
	    printf( "Item: " );
	    print_r($strvals);
	    printf("\n");
	    */
	  }
    } while( vas_err() == VAS_ERR_MORE_VALS );

    /* The first vas_attrs_find may not return all of the possible results.
     * In many cases you only want to get the first entry so for performance
     * reasons this is the behavior.  If you want more than one result you
     * must request more items and loop again for the results. */
    vas_attrs_find_continue( $c, $a );
  }
  //
  // There should be a lot of results.
  //
  if ($results_found < 10) return 109;
}

runTest("t_vas_attrs_find");

?>
