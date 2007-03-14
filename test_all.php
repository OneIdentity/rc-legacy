<?php

require "vas.php";

$warn = 0;
$error = 0;
//
// Our environment.
//
$username = "testuser";
$password = "test123";
$adminusername = "Administrator";
$adminpassword = "test123";
$uri = "DC://";
$scope = "sub";
$search_base  = "CN=Users,DC=dan,DC=vas";
$search_filter1 = "(&(ObjectClass=User)(sAMAccountName=testuser))";
$search_filter2 = "(objectClass=*)";
$attrs_name1 = "telephoneNumber";
$attrs_name2 = "cn";
$attrs_names1 = array($attrs_name1);
$attrs_names2 = array($attrs_name2);
  $attrs_val1 = "(206) 555-1212";
  $attrs_val2 = "testuser";
$credflags = VAS_ID_FLAG_USE_MEMORY_CCACHE;
$groupname = "testgroup";
$dcgroup = "Domain Controllers";
$principal = "testuser@dan.vas";
$userupn = "testuser@dan.vas";
$usersid = "S-1-5-21-2672905828-3419038426-2056116520-102273";
$groupsid = "S-1-5-21-2473201516-3199465966-3788853037-1121";
$dc1sid =  "S-1-5-21-2473201516-3199465966-3788853037-1003";
$computername = "dbone.dan.vas";

//
// Declare the test functions.
//
$t[] = "vas_ctx_alloc";
$t[] = "vas_ctx_set_option";
$t[] = "vas_ctx_get_option";
$t[] = "vas_id_alloc";
$t[] = "vas_id_get_ccache_name";
$t[] = "vas_id_get_keytab_name";
$t[] = "vas_id_get_name";
$t[] = "vas_id_get_user";
$t[] = "vas_id_is_cred_established";
$t[] = "vas_id_establish_cred_password";
$t[] = "vas_id_establish_cred_keytab";
$t[] = "vas_id_renew_cred";
$t[] = "vas_auth";
$t[] = "vas_auth_with_password";
$t[] = "vas_auth_check_client_membership";
$t[] = "vas_auth_get_client_groups";
$t[] = "vas_attrs_alloc";
$t[] = "vas_attrs_find";
$t[] = "vas_attrs_find_continue";
$t[] = "vas_attrs_set_option";
$t[] = "vas_attrs_get_option";
$t[] = "vas_vals_get_string";
$t[] = "vas_vals_get_integer";
$t[] = "vas_vals_get_binary";
$t[] = "vas_vals_get_anames";
$t[] = "vas_vals_get_dn";
$t[] = "vas_name_to_principal";
$t[] = "vas_name_to_dn";
$t[] = "vas_info_forest_root";
$t[] = "vas_info_joined_domain";
$t[] = "vas_info_site";
$t[] = "vas_info_domains";
$t[] = "vas_info_servers";
$t[] = "vas_prompt_for_cred_string";
$t[] = "vas_err_get_code";
$t[] = "vas_err_get_string";
$t[] = "vas_err_clear";
$t[] = "vas_err_get_info";
$t[] = "vas_err_info_get_string";
$t[] = "vas_err_get_cause_by_type";
$t[] = "vas_user_init";
$t[] = "vas_user_is_member";
$t[] = "vas_user_get_groups";
$t[] = "vas_user_get_attrs";
$t[] = "vas_user_get_dn";
$t[] = "vas_user_get_domain";
$t[] = "vas_user_get_sam_account_name";
$t[] = "vas_user_get_sid";
$t[] = "vas_user_get_upn";
$t[] = "vas_user_get_pwinfo";
$t[] = "vas_user_get_krb5_client_name";
$t[] = "vas_user_get_account_control";
$t[] = "vas_user_check_access";
$t[] = "vas_user_check_conflicts";
$t[] = "vas_group_init";
$t[] = "vas_group_has_member";
$t[] = "vas_group_get_attrs";
$t[] = "vas_group_get_dn";
$t[] = "vas_group_get_domain";
$t[] = "vas_group_get_sid";
$t[] = "vas_service_init";
$t[] = "vas_service_get_attrs";
$t[] = "vas_service_get_dn";
$t[] = "vas_service_get_domain";
$t[] = "vas_service_get_krb5_client_name";
$t[] = "vas_service_get_spns";
$t[] = "vas_service_get_upn";
$t[] = "vas_computer_init";
$t[] = "vas_computer_is_member";
$t[] = "vas_computer_get_attrs";
$t[] = "vas_computer_get_dn";
$t[] = "vas_computer_get_dns_hostname";
$t[] = "vas_computer_get_domain";
$t[] = "vas_computer_get_sid";
$t[] = "vas_computer_get_spns";
$t[] = "vas_computer_get_sam_account_name";
$t[] = "vas_computer_get_upn";
$t[] = "vas_computer_get_krb5_client_name";
$t[] = "vas_computer_get_host_spn";
$t[] = "vas_computer_get_account_control";
$t[] = "vas_gss_initialize";
$t[] = "vas_gss_acquire_cred";
$t[] = "vas_gss_auth";
$t[] = "vas_gss_spnego_initiate";
$t[] = "vas_gss_spnego_accept";
$t[] = "vas_gss_krb5_get_subkey";
/*
$t[] = "gss_acquire_cred";
$t[] = "gss_add_cred";
$t[] = "gss_inquire_cred";
$t[] = "gss_inquire_cred_by_mech";
$t[] = "gss_init_sec_context";
$t[] = "gss_accept_sec_context";
$t[] = "gss_process_context_token";
$t[] = "gss_context_time";
$t[] = "gss_inquire_context";
$t[] = "gss_wrap_size_limit";
$t[] = "gss_export_sec_context";
$t[] = "gss_import_sec_context";
$t[] = "gss_get_mic";
$t[] = "gss_verify_mic";
$t[] = "gss_wrap";
$t[] = "gss_unwrap";
$t[] = "gss_sign";
$t[] = "gss_verify";
$t[] = "gss_seal";
$t[] = "gss_unseal";
$t[] = "gss_import_name";
$t[] = "gss_display_name";
$t[] = "gss_compare_name";
$t[] = "gss_release_name";
$t[] = "gss_inquire_names_for_mech";
$t[] = "gss_inquire_mechs_for_name";
$t[] = "gss_canonicalize_name";
$t[] = "gss_export_name";
$t[] = "gss_duplicate_name";
$t[] = "gss_display_status";
$t[] = "gss_create_empty_oid_set";
$t[] = "gss_add_oid_set_member";
$t[] = "gss_test_oid_set_member";
$t[] = "gss_release_oid_set";
$t[] = "gss_release_buffer";
$t[] = "gss_indicate_mechs";
*/
$t[] = "vas_krb5_get_context";
$t[] = "vas_krb5_get_principal";
$t[] = "vas_krb5_get_ccache";
$t[] = "vas_krb5_get_credentials";
$t[] = "vas_krb5_validate_credentials";
$t[] = "vas_ldap_init_and_bind";
$t[] = "vas_ldap_set_attributes";

$cl[] = "vas_ldap_set_attributes1";
$cl[] = "vas_ldap_set_attributes2";
$cl[] = "vas_ldap_set_attributes3";
$cl[] = "vas_ldap_set_attributes4";

/////////////////////////////////////////////////////////////////////////////////
////                           T E S T s                                     ////
/////////////////////////////////////////////////////////////////////////////////

function t_vas_ctx_alloc()
{
  $c = vas_ctx_alloc();
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($c, "vas_ctx_t");
}

function t_vas_ctx_get_option()
{
  $c = vas_ctx_alloc();
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_DNSSRV);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_TCP_ONLY);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_GSSAPI_AUTHZ);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SERVER_REFERRALS);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if (!is_int($opt)) return 201;

  $opt = vas_ctx_get_option($c, 55);
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 300;
}

function t_vas_ctx_set_option()
{
  //
  // we can't test most of the options, so the goal is to test
  // the classes of parameters to the options.
  //
  $c = vas_ctx_alloc();
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $opt = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  vas_ctx_set_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE, 0);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  $optNew = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  if ($optNew != 0) return 201;
  vas_ctx_set_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE, $opt);
  $optNew = vas_ctx_get_option($c, VAS_CTX_OPTION_USE_SRVINFO_CACHE);
  if ($optNew != $opt) return 202;

  $err = vas_ctx_set_option($c, VAS_CTX_OPTION_DEFAULT_REALM, 0); // should be string
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 300;

  vas_ctx_set_option($c, VAS_CTX_OPTION_SITE_AND_FOREST_ROOT, "", 0);
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 400;

  $opt = vas_ctx_set_option($c, 55, null);
  if (vas_err() != VAS_ERR_INVALID_PARAM) return 900;
}

function t_vas_id_alloc()
{
  global $username;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($i, "vas_id_t");
  if ($rv) return $rv;

  $i = null;
  $i = vas_id_alloc($c, null);

  $rv = testResource($i, "vas_id_t");
  if ($rv) return $rv;
}

function t_vas_id_get_ccache_name()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $s = vas_id_get_ccache_name($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if (strpos($s, "MEMORY:vas-ccache") === false) return 101;
}

function t_vas_id_get_keytab_name()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $s = vas_id_get_keytab_name($c, $i);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 100;  // we don't have one.
}

function t_vas_id_get_name()
{
  global $username;
  global $credflags;
  global $password;
  global $principal, $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $err = vas_id_get_name($c, $i, $p, $d);
  if ($err != vas_err()) return 101;
  if ($p != $principal) return 102;
  if ($d != "CN=$username,CN=Users,DC=dan,DC=vas") return 103;
}

function t_vas_id_get_user()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );

  $user = vas_id_get_user($c, $i);

  return testResource($user, "vas_user_t");
}

function t_vas_id_is_cred_established()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  /* NOTE: NOTE: Fails when root! */
  if (vas_err() == VAS_ERR_SUCCESS) return 100;

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
}

function t_vas_id_renew_cred()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  /* NOTE: NOTE: Fails when root! */
  if (vas_err() == VAS_ERR_SUCCESS) return 100;

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  vas_id_renew_cred( $c, $i, 0 );
  $err = vas_id_is_cred_established($c, $i);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
}

function t_vas_id_establish_cred_keytab()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  //
  // Can't really test the functionality here, so just test
  // the prototyping.  Tested in vas_auth()
  //
  $err = vas_id_establish_cred_keytab($c, $i, VAS_ID_FLAG_USE_MEMORY_CCACHE, null);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 101;

  $err = vas_id_establish_cred_keytab($c, $i, VAS_ID_FLAG_USE_MEMORY_CCACHE, "fubar");
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 101;
}

function t_vas_attrs_alloc()
{
  global $username;
  global $password;
  global $credflags;

  $c = vas_ctx_alloc();
  $a = vas_attrs_alloc($c, null);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($a, "vas_attrs_t");
  if ($rv) return $rv;

  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  $a = vas_attrs_alloc($c, $i);

  $rv = testResource($a, "vas_attrs_t");
  if ($rv) return $rv;
}

function t_vas_err_get_code()
{
  $c2 = vas_ctx_alloc();
  $c = cause_invalid_param();

  if (vas_err() != VAS_ERR_INVALID_PARAM) return 100;
  if (vas_err_get_code($c) != VAS_ERR_INVALID_PARAM) return 101;
  if (vas_err_get_code($c2) != VAS_ERR_SUCCESS) return 102;
}

function t_vas_err_get_string()
{
  $c = cause_invalid_param();

  $s1 = vas_err_get_string($c, 0);
  $s2 = vas_err_get_string($c, 1);

  // note that $s1 and $s2 seem to be the same with either with_clause
  if (stristr($s1, "VAS_ERR_INVALID_PARAM") === FALSE) return 100;
  if (stristr($s2, "VAS_ERR_INVALID_PARAM") === FALSE) return 101;
}

function t_vas_err_clear()
{
  $c = cause_invalid_param();

  if (vas_err() != VAS_ERR_INVALID_PARAM) return 100;

  vas_err_clear($c);

  if (vas_err() != VAS_ERR_SUCCESS) return 101;
}

function t_vas_err_get_info()
{
  $c = cause_invalid_param();

  $info = vas_err_get_info($c);

  $c = vas_ctx_alloc(); // to set vas_err() to success.

  return testStruct($info, array("code", "type", "cause", "message"));
}

function t_vas_err_info_get_string()
{
  $c = cause_invalid_param();

  $info = vas_err_get_info($c);

  $c2 = vas_ctx_alloc(); // to set vas_err() to success.

  $s1 = vas_err_info_get_string($c, $info, 0);

  if ( ($s1 != "VAS_ERR_INVALID_PARAM: id must not be NULL")
    && ($s1 != "VAS_ERR_INVALID_PARAM: at id.c:445 in vas_id_alloc\n   id must not be NULL" ) )
      return 101;
}

function t_vas_err_get_cause_by_type()
{
  $c = cause_invalid_param();

  $info1 = vas_err_get_cause_by_type($c, VAS_ERR_TYPE_VAS);
  $info2 = vas_err_get_cause_by_type($c, VAS_ERR_TYPE_SYS);

  $c2 = vas_ctx_alloc(); // to set vas_err() to success.

  if ($info1 != null) return 101;
  if ($info2 != null) return 102;
}

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

function t_vas_attrs_find_continue()
{
  return t_vas_attrs_find();
}

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

function t_vas_info_forest_root()
{
  vas_info_forest_root(vas_ctx_alloc(), $forest_root, $forest_root_dn);

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($forest_root != "dan.vas") return 101;
  if ($forest_root_dn != "DC=dan,DC=vas") return 102;
}

function t_vas_info_joined_domain()
{
  vas_info_joined_domain(vas_ctx_alloc(), $domain, $domain_dn);

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($domain != "dan.vas") return 101;
  if ($domain_dn != "DC=dan,DC=vas") return 102;
}

function t_vas_info_domains()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_info_domains($c, $i, $domains, $domains_dn);

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($domains[0] != "dan.vas") return 101;
  if ($domains_dn[0] != "DC=dan,DC=vas") return 102;
}

function t_vas_info_site()
{
  $site = vas_info_site(vas_ctx_alloc());

  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($site != "Default-First-Site-Name") return 101;
}

function t_vas_info_servers()
{
  $servers = vas_info_servers(vas_ctx_alloc(), null, null, VAS_SRVINFO_TYPE_ANY);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;
  if ($servers[0] != "booger.dan.vas") return 101;

  $servers = vas_info_servers(vas_ctx_alloc(), null, "*", VAS_SRVINFO_TYPE_ANY);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if ($servers[0] != "booger.dan.vas") return 201;
}

function t_vas_gss_initialize()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_gss_initialize($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
}

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

function t_vas_gss_auth()
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
  $a = vas_gss_auth($c, $cred, $gss_ctx);

  if (vas_err() != VAS_ERR_SUCCESS) return 103;
  $rv = testResource($a, "vas_auth_t");
  if ($rv) return $rv;
}

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

function t_vas_gss_spnego_accept()
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

  $auth = 0;
  $gss_ctx = GSS_C_NO_CONTEXT;
  $flags = null;
  $deleg_cred = GSS_C_NO_CREDENTIAL;

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
  $in_token = $out_token;
  $out_token = null;

  $gsserr = vas_gss_spnego_accept($c, $i,
	    $auth, $gss_ctx, $flags,
	    VAS_GSS_SPNEGO_ENCODING_BASE64, $in_token, $out_token, $deleg_cred);

  if (GSS_ERROR($gsserr))
  {
    //printf("vas_err = %s\n", vas_err_get_string($c, 1));
    return 300;
  }
}

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

function t_vas_name_to_principal()
{
  global $username;
  global $principal;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  $p = vas_name_to_principal($c, $username,
		 VAS_NAME_TYPE_UNKNOWN,
		 0);

  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($p != $principal) return 102;
}

function t_vas_user_init()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  return testResource($user, "vas_user_t");
}

function t_vas_user_is_member()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $groupBad = vas_group_init($c, $i, "Administrators", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 105;

  $err = vas_user_is_member($c, $i, $user, $group);
  if ($err != VAS_ERR_SUCCESS) return 103;

  $err = vas_user_is_member($c, $i, $user, $groupBad);
  if ($err != VAS_ERR_NOT_FOUND) return 104;
}

function t_vas_user_get_groups()
{
  global $username;
  global $credflags;
  global $password;

  $expectedGroups = array("Users", "testgroup", "Domain Users");

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $groups = vas_user_get_groups($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 103;

  foreach ($groups as $g)
  {
    $name = vas_group_get_dn($c, $i, $g);
    $pos = 0;
    foreach ($expectedGroups as $e)
    {
      if (strstr($name, $e) != false)
      {
	    array_splice($expectedGroups, $pos, 1);
	    break;
      }
      $pos++;
    }
  }
  if (count($expectedGroups) != 0) return 200;
}

function t_vas_user_get_attrs()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val1, $attrs_val2;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $attrs = vas_user_get_attrs($c, $i, $user, array("telephoneNumber", "cn"));
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $s = vas_vals_get_string($c, $attrs, $attrs_name1);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if ($s[0] != $attrs_val1) return 201;

  $s = vas_vals_get_string($c, $attrs, $attrs_name2);
  if (vas_err() != VAS_ERR_SUCCESS) return 300;
  if ($s[0] != $attrs_val2) return 301;
}

function t_vas_user_get_dn()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_dn($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != "CN=testuser,CN=Users,DC=dan,DC=vas") return 103;
}

function t_vas_user_get_domain()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_domain($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != "DAN.VAS") return 103;
}

function t_vas_user_get_sam_account_name()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_domain($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != "DAN.VAS") return 103;
}

function t_vas_user_get_sid()
{
  global $username;
  global $credflags;
  global $password;
  global $usersid;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_sid($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != $usersid) return 103;
}

function t_vas_user_get_upn()
{
  global $username;
  global $credflags;
  global $password;
  global $userupn;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_upn($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != $userupn) return 103;
}

function t_vas_user_get_pwinfo()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $p = vas_user_get_pwinfo($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if (get_class($p) != "CVAS_passwd") return 103;
  if ($p->pw_name != "testuser") return 104;
  if ($p->pw_gecos != "testuser") return 105;
  if ($p->pw_uid != 8010) return 106;
  if ($p->pw_gid != 1000) return 107;
}

function t_vas_user_get_krb5_client_name()
{
  global $username;
  global $credflags;
  global $password;
  global $principal;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_user_get_krb5_client_name($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != $principal) return 103;
}

function t_vas_user_get_account_control()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $i = vas_user_get_account_control($c, $i, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  // Flags are opaque, so just verify it's an integer.
  if (!is_long($i)) return 103;
}

function t_vas_user_check_access()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $i = vas_user_check_access($c, $user, null);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $i = vas_user_check_access($c, $user, "fubar");
  if (vas_err() != VAS_ERR_SUCCESS) return 103;

  $i = vas_user_check_access($c, $user, "-");
  if (vas_err() != VAS_ERR_SUCCESS) return 103;
}

function t_vas_user_check_conflicts()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $i = vas_user_check_conflicts($c, $user);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
}

function t_vas_group_init()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($group, "vas_group_t");
  if ($test) return $test;

  $group = vas_group_init($c, $i, "does not exist", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 103;
  if ($group != null) return 104;
}

function t_vas_group_has_member()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_group_has_member($c, $i, $group, $user);
  if ($err != vas_err()) return 100;
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $user2 = vas_user_init($c, $i, "Administrator", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_group_has_member($c, $i, $group, $user2);
  if ($err != vas_err()) return 103;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 104;
}

function t_vas_group_get_attrs()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $attrs = vas_group_get_attrs($c, $i, $group, array($attrs_name1, $attrs_name2));
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $s = vas_vals_get_string($c, $attrs, $attrs_name1);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 200;

  $s = vas_vals_get_string($c, $attrs, $attrs_name2);
  if (vas_err() != VAS_ERR_SUCCESS) return 300;
  if ($s[0] != $groupname) return 301;
}

function t_vas_group_get_dn()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_group_get_dn($c, $i, $group);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != "CN=$groupname,DC=example,DC=com") return 103;
}

function t_vas_group_get_domain()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_group_get_domain($c, $i, $group);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != "DAN.VAS") return 103;
}

function t_vas_group_get_sid()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;
  global $groupsid;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $s = vas_group_get_sid($c, $i, $group);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($s != $groupsid) return 103;
}

function t_vas_computer_init()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($computer, "vas_computer_t");
  if ($test) return $test;

  $computer = vas_computer_init($c, $i, "does not exist", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 103;
  if ($computer != null) return 104;
}

function t_vas_computer_is_member()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;
  global $dcgroup;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $group = vas_group_init($c, $i, $groupname, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_computer_is_member($c, $i, $computer, $group);
  if ($err != vas_err()) return 103;
  if (vas_err() != VAS_ERR_NOT_FOUND) return 104;

  $group = vas_group_init($c, $i, $dcgroup, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 201;

  $err = vas_computer_is_member($c, $i, $computer, $group);
  if ($err != vas_err()) return 203;
  if (vas_err() != VAS_ERR_SUCCESS) return 204;
}

function t_vas_computer_get_attrs()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $attrs = vas_computer_get_attrs($c, $i, $computer, array($attrs_name1, $attrs_name2));
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $s = vas_vals_get_string($c, $attrs, $attrs_name1);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 200;

  $s = vas_vals_get_string($c, $attrs, $attrs_name2);
  if (vas_err() != VAS_ERR_SUCCESS) return 300;
  if ($s[0] != "DC1") return 301;
}

function t_vas_computer_get_dn()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_dn($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "CN=DC1,OU=Domain Controllers,DC=example,DC=com") return 103;
}

function t_vas_computer_get_dns_hostname()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_dns_hostname($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != $computername) return 103;
}

function t_vas_computer_get_domain()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_domain($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "DAN.VAS") return 103;
}

function t_vas_computer_get_sid()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;
  global $dc1sid;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_sid($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != $dc1sid) return 103;
}

function t_vas_computer_get_spns()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_spns($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  if (!array_search("DNS/dc1.example.com", $s)) return 103;
  if (!array_search("ldap/DC1", $s)) return 104;
  if (!array_search("HOST/DC1", $s)) return 105;
}

function t_vas_computer_get_sam_account_name()
{
  global $username;
  global $credflags;
  global $password;
  global $computername;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, $computername, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_sam_account_name($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "DC1$") return 103;
}

function t_vas_computer_get_upn()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, "c1", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_upn($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "host/c1.example.com@DAN.VAS") return 103;
}

function t_vas_computer_get_krb5_client_name()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, "c1", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_krb5_client_name($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "C1$@DAN.VAS") return 103;
}

function t_vas_computer_get_host_spn()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, "c1", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_host_spn($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "host/C1$@DAN.VAS") return 103;
}

function t_vas_computer_get_account_control()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_computer_init($c, $i, "c1", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $s = vas_computer_get_account_control($c, $i, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if (!is_int($s)) return 103;
}

function t_vas_service_init()
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
  $test = testResource($service, "vas_service_t");
  if ($test) return $test;

  $service = vas_service_init($c, $i, "does not exist", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 103;
  if ($service != null) return 104;
}

function t_vas_service_get_attrs()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $service = vas_service_init($c, $i, "ldap/DC1", VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $attrs = vas_service_get_attrs($c, $i, $service, array($attrs_name1, $attrs_name2));
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $s = vas_vals_get_string($c, $attrs, $attrs_name1);
  if (vas_err() != VAS_ERR_NOT_FOUND) return 200;

  $s = vas_vals_get_string($c, $attrs, $attrs_name2);
  if (vas_err() != VAS_ERR_SUCCESS) return 300;
  if ($s[0] != "DC1") return 301;
}

function t_vas_service_get_dn()
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

  $s = vas_service_get_dn($c, $i, $service);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "CN=DC1,OU=Domain Controllers,DC=example,DC=com") return 301;
}

function t_vas_service_get_domain()
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

  $s = vas_service_get_domain($c, $i, $service);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "DAN.VAS") return 301;
}

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

function t_vas_service_get_upn()
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

  $s = vas_service_get_upn($c, $i, $service);
  /*
   * I can't seem to find any found UPN's.
   *
  var_dump($s);
  myprint(vas_err());
  if (vas_err() != VAS_ERR_SUCCESS) return 101;
  if ($s != "DC1$@DAN.VAS") return 301;
  */
  if (vas_err() != VAS_ERR_NOT_FOUND) return 400;
}

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

function t_vas_auth_with_password()
{
  global $username;
  global $credflags;
  global $password;

  /* NOTE: NOTE: MUST BE ROOT TO RUN THIS TEST!!!!! */

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_id_alloc($c, "host/");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $a = vas_auth_with_password($c, $username, "wrong password", $computer);
  if (vas_err() == VAS_ERR_SUCCESS) return 101;

  vas_id_establish_cred_keytab($c, $computer, VAS_ID_FLAG_USE_MEMORY_CCACHE, null);

  $a = vas_auth_with_password($c, $username, $password, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  return testResource($a, "vas_auth_t");
}

function t_vas_attrs_get_option()
{
  return t_vas_attrs_set_option();
}

function t_vas_attrs_set_option()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $a = vas_attrs_alloc($c, $i);

  vas_attrs_set_option($c, $a, VAS_ATTRS_OPTION_SEARCH_TIMEOUT, 10);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $value = vas_attrs_get_option($c, $a, VAS_ATTRS_OPTION_SEARCH_TIMEOUT);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  if ($value != 10) return 103;

  vas_attrs_set_option($c, $a, VAS_ATTRS_OPTION_LDAP_PAGESIZE, 8);
  if (vas_err() != VAS_ERR_SUCCESS) return 104;

  $value = vas_attrs_get_option($c, $a, VAS_ATTRS_OPTION_LDAP_PAGESIZE);
  if (vas_err() != VAS_ERR_SUCCESS) return 105;
  if ($value != 8) return 106;
  //
  // Now test the string parms.
  //
  vas_attrs_set_option($c, $a, VAS_ATTRS_B64_ENCODE_ATTRS, 8);
  if (vas_err() == VAS_ERR_SUCCESS) return 107;
  vas_attrs_set_option($c, $a, VAS_ATTRS_B64_ENCODE_ATTRS, "hi,mom");
  if (vas_err() != VAS_ERR_SUCCESS) return 108;

  $value = vas_attrs_get_option($c, $a, VAS_ATTRS_B64_ENCODE_ATTRS);
  if (vas_err() != VAS_ERR_SUCCESS) return 109;
  if ($value != "hi,mom") return 110;
  //
  // the difference between "" and null is significant.
  //
  vas_attrs_set_option($c, $a, VAS_ATTRS_B64_ENCODE_ATTRS, "");
  if (vas_err() != VAS_ERR_SUCCESS) return 120;

  $value = vas_attrs_get_option($c, $a, VAS_ATTRS_B64_ENCODE_ATTRS);
  if (vas_err() != VAS_ERR_SUCCESS) return 121;
  if (!is_null($value)) return 122;

  vas_attrs_set_option($c, $a, VAS_ATTRS_B64_ENCODE_ATTRS, null);
  if (vas_err() != VAS_ERR_SUCCESS) return 130;

  $value = vas_attrs_get_option($c, $a, VAS_ATTRS_B64_ENCODE_ATTRS);
  if (vas_err() != VAS_ERR_SUCCESS) return 131;
  if ($value != 'userCertificate,objectGUID,objectSID,userParameters,logonHours,vintela-sidBL') return 132;
}

function t_vas_vals_get_anames()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val1, $attrs_val2;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $attrs = vas_user_get_attrs($c, $i, $user, array("telephoneNumber", "cn"));
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $anames = vas_vals_get_anames($c, $attrs);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;

  if ($anames[0] != "cn") return 201;
  if ($anames[1] != "telephoneNumber") return 301;
}

function t_vas_vals_get_dn()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val1, $attrs_val2;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $attrs = vas_user_get_attrs($c, $i, $user, array("telephoneNumber", "cn"));
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $s = vas_vals_get_dn($c, $attrs);
  if (vas_err() != VAS_ERR_SUCCESS) return 200;

  if ($s != "CN=testuser,CN=Users,DC=dan,DC=vas") return 201;
}

function t_vas_vals_get_integer()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val1, $attrs_val2;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $attrs = vas_user_get_attrs($c, $i, $user, array("uidNumber"));
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $s = vas_vals_get_integer($c, $attrs, "uidNumber");
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if ($s[0] != 8010) return 201;
}

function t_vas_vals_get_binary()
{
  global $username;
  global $credflags;
  global $password;
  global $attrs_val1, $attrs_val2;
  global $attrs_name1, $attrs_name2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);

  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $user = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS) return 101;

  $attrs = vas_user_get_attrs($c, $i, $user, array("uidNumber"));
  if (vas_err() != VAS_ERR_SUCCESS) return 102;
  $test = testResource($attrs, "vas_attrs_t");
  if ($test) return $test;

  $s = vas_vals_get_binary($c, $attrs, "uidNumber");
  if (vas_err() != VAS_ERR_SUCCESS) return 200;
  if ($s[0] != 8010) return 201;
}

function t_vas_auth_check_client_membership()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  /* NOTE: NOTE: MUST BE ROOT TO RUN THIS TEST!!!!! */

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_id_alloc($c, "host/");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_id_establish_cred_keytab($c, $computer, VAS_ID_FLAG_USE_MEMORY_CCACHE, null);

  $a = vas_auth_with_password($c, $username, $password, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $err = vas_auth_check_client_membership($c, $i, $a, "no group name");
  if ($err != vas_err()) return 99;
  if (vas_err() == VAS_ERR_SUCCESS) return 103;

  $err = vas_auth_check_client_membership($c, $i, $a, $groupname);
  if ($err != vas_err()) return 99;
  if (vas_err() != VAS_ERR_SUCCESS) return 104;
}

function t_vas_auth_get_client_groups()
{
  global $username;
  global $credflags;
  global $password;
  global $groupname;

  /* NOTE: NOTE: MUST BE ROOT TO RUN THIS TEST!!!!! */

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $computer = vas_id_alloc($c, "host/");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  vas_id_establish_cred_keytab($c, $computer, VAS_ID_FLAG_USE_MEMORY_CCACHE, null);

  $a = vas_auth_with_password($c, $username, $password, $computer);
  if (vas_err() != VAS_ERR_SUCCESS) return 102;

  $g = vas_auth_get_client_groups($c, $i, $a);
  if (vas_err() != VAS_ERR_SUCCESS) return 103;

  if (!is_array($g)) return 104;
  if (count($g) < 2) return 105;

  return testResource($g[0], "vas_group_t");
}

function t_vas_krb5_get_context()
{
  $c = vas_ctx_alloc();

  $krb5 = vas_krb5_get_context($c);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($krb5, "krb5_context");
}

function t_vas_krb5_get_principal()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $krb5 = vas_krb5_get_principal($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($krb5, "krb5_principal");
}

function t_vas_krb5_get_ccache()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $krb5 = vas_krb5_get_ccache($c, $i);
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($krb5, "krb5_ccache");
}

function t_vas_ldap_init_and_bind()
{
  global $username;
  global $credflags;
  global $password;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $ldap = vas_ldap_init_and_bind($c, $i, "DC://");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  return testResource($ldap, "LDAP");
}

function checkAttribute($a)
{
  global $username;
  global $credflags;
  global $password;

  $verbose = 0;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $username);
  vas_id_establish_cred_password( $c, $i, $credflags, $password );
  if (vas_err() != VAS_ERR_SUCCESS)
  {
    if ($verbose) printf("checkAttributes: vas_id_establish_cred_password failed\n");
    return null;
  }

  $u = vas_user_init($c, $i, $username, VAS_NAME_FLAG_NO_CACHE);
  if (vas_err() != VAS_ERR_SUCCESS)
  {
    if ($verbose) printf("checkAttributes: vas_user_init failed\n");
    return null;
  }

  $attrs = vas_user_get_attrs($c, $i, $u, array($a));
  if (vas_err() != VAS_ERR_SUCCESS)
  {
    if ($verbose) printf("checkAttributes: vas_user_get_attrs failed\n");
    return null;
  }

  $s = vas_vals_get_string($c, $attrs, $a);
  if (vas_err() != VAS_ERR_SUCCESS)
  {
    if ($verbose) printf("checkAttributes: vas_vals_get_string failed\n");
    return null;
  }

  if ($verbose) echo "checkAttribute returning: ", $s[0], "\n";
  return $s[0];
}

function subTest($name)
{
  global $argv;
  system("/usr/bin/php -f " . $argv[0] . " " . $name);
  return VAS_ERR_SUCCESS;
}

function t_vas_ldap_set_attributes()
{
  global $username;
  global $adminusername;
  global $credflags;
  global $adminpassword;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $adminusername);
  vas_id_establish_cred_password( $c, $i, $credflags, $adminpassword );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $ldap = vas_ldap_init_and_bind($c, $i, "DC://");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($ldap, "LDAP");
  if ($rv) return $rv;

  $dn = "CN=$attrs_val2,CN=Users,DC=example,DC=com";
  //
  // Tests:
  // 0) Delete our attribute.
  // 1) Add an addribute.  Check that it exists.
  // 2) Delete it and check that it's gone.
  // 3) Add two attributes and verify
  // 4) Delete both and verify.
  //
  // 0
  //
  // Don't check return code, because we don't care about errors
  // if these don't exist.
  $m = new CVAS_LDAPMod(LDAP_MOD_DELETE, "title");
  $mod[] = $m;
  $m = new CVAS_LDAPMod(LDAP_MOD_DELETE, "department");
  $mod[] = $m;
  $m = new CVAS_LDAPMod(LDAP_MOD_DELETE, "company");
  $mod[] = $m;
  vas_ldap_set_attributes($c, $i, "DC://", $dn, $mod);

  $ldap = null;
  $i = null;
  $c = null;
  //
  // We need to run the rest of the tests as new processes because vas
  // caches attribute information and we're sort-of going behind its
  // back to change it.
  //
  subTest("vas_ldap_set_attributes1");
  subTest("vas_ldap_set_attributes2");
  subTest("vas_ldap_set_attributes3");
  subTest("vas_ldap_set_attributes4");
}

function t_vas_ldap_set_attributes1()
{
  global $username;
  global $adminusername;
  global $credflags;
  global $adminpassword;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $adminusername);
  vas_id_establish_cred_password( $c, $i, $credflags, $adminpassword );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $ldap = vas_ldap_init_and_bind($c, $i, "DC://");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($ldap, "LDAP");
  if ($rv) return $rv;

  $dn = "CN=$attrs_val2,CN=Users,DC=example,DC=com";
  //
  // Tests:
  // 0) Delete our attribute.
  // 1) Add an addribute.  Check that it exists.
  // 2) Delete it and check that it's gone.
  // 3) Add two attributes and verify
  // 4) Delete both and verify.
  //
  // 1
  //
  $m = new CVAS_LDAPMod(LDAP_MOD_ADD, "title");
  $m->add_value("Hi Mom");
  $mod[] = $m;
  vas_ldap_set_attributes($c, $i, "DC://", $dn, $mod);
  if (vas_err() != VAS_ERR_SUCCESS) return 201;
  if (checkAttribute("title") != "Hi Mom") return 2010;
}

function t_vas_ldap_set_attributes2()
{
  global $username;
  global $adminusername;
  global $credflags;
  global $adminpassword;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $adminusername);
  vas_id_establish_cred_password( $c, $i, $credflags, $adminpassword );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $ldap = vas_ldap_init_and_bind($c, $i, "DC://");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($ldap, "LDAP");
  if ($rv) return $rv;

  $dn = "CN=$attrs_val2,CN=Users,DC=example,DC=com";
  //
  // Tests:
  // 2) Delete it and check that it's gone.
  //
  // 2
  //
  $m = new CVAS_LDAPMod(LDAP_MOD_DELETE, "title");
  $mod[] = $m;
  vas_ldap_set_attributes($c, $i, "DC://", $dn, $mod);
  if (vas_err() != VAS_ERR_SUCCESS) return 201;
  if (checkAttribute("title") != null) return 2010;
}

function t_vas_ldap_set_attributes3()
{
  global $username;
  global $adminusername;
  global $credflags;
  global $adminpassword;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $adminusername);
  vas_id_establish_cred_password( $c, $i, $credflags, $adminpassword );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $ldap = vas_ldap_init_and_bind($c, $i, "DC://");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($ldap, "LDAP");
  if ($rv) return $rv;

  $dn = "CN=$attrs_val2,CN=Users,DC=example,DC=com";
  //
  // Tests:
  // 3) Add two attributes and verify
  //
  // 3
  //
  $m = new CVAS_LDAPMod(LDAP_MOD_ADD, "title");
  $m->add_value("Hi Mom");
  $mod[] = $m;
  $m = new CVAS_LDAPMod(LDAP_MOD_ADD, "company");
  $m->add_value("My Co");
  $mod[] = $m;
  $m = new CVAS_LDAPMod(LDAP_MOD_ADD, "department");
  $m->add_value("My Dep");
  $mod[] = $m;
  vas_ldap_set_attributes($c, $i, "DC://", $dn, $mod);
  if (vas_err() != VAS_ERR_SUCCESS) return 2030;
  if (checkAttribute("title") != "Hi Mom") return 2031;
  if (checkAttribute("company") != "My Co") return 2033;
}

function t_vas_ldap_set_attributes4()
{
  global $username;
  global $adminusername;
  global $credflags;
  global $adminpassword;
  global $attrs_val2;

  $c = vas_ctx_alloc();
  $i = vas_id_alloc($c, $adminusername);
  vas_id_establish_cred_password( $c, $i, $credflags, $adminpassword );
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $ldap = vas_ldap_init_and_bind($c, $i, "DC://");
  if (vas_err() != VAS_ERR_SUCCESS) return 100;

  $rv = testResource($ldap, "LDAP");
  if ($rv) return $rv;

  $dn = "CN=$attrs_val2,CN=Users,DC=example,DC=com";
  //
  // Tests:
  // 4) Delete both and verify.
  //
  // 4
  //
  $m = new CVAS_LDAPMod(LDAP_MOD_DELETE, "title");
  $mod[] = $m;
  $m = new CVAS_LDAPMod(LDAP_MOD_DELETE, "department");
  $mod[] = $m;
  $m = new CVAS_LDAPMod(LDAP_MOD_DELETE, "company");
  $mod[] = $m;
  vas_ldap_set_attributes($c, $i, "DC://", $dn, $mod);
  if (vas_err() != VAS_ERR_SUCCESS) return 2040;
  if (checkAttribute("title") != null) return 2041;
  if (checkAttribute("department") != null) return 2043;
}

function t_vas_prompt_for_cred_string()
{
  // Nothing.
}

/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////

function cause_invalid_param()
{
  $c = vas_ctx_alloc();

  vas_ctx_set_option($c, VAS_CTX_OPTION_DEFAULT_REALM, 0);   // Cause error.

  return $c;
}

function testResource(&$var, $type)
{
  if (vas_err() != VAS_ERR_SUCCESS)
  {
    return 5;
  }
  if (!isset($var))
  {
    return 1;
  }
  if (is_null($var))
  {
    return 2;
  }
  if (!is_resource($var))
  {
    return 3;
  }
  if (get_resource_type($var) != $type)
  {
    myprint(get_resource_type($var));
    return 4;
  }
  return 0; // PASS
}

function testStruct(&$var, $members)
{
  if (vas_err() != VAS_ERR_SUCCESS)
  {
    return 5;
  }
  if (!isset($var))
  {
    return 1;
  }
  if (is_null($var))
  {
    return 2;
  }
  if (!is_object($var))
  {
    return 3;
  }
  foreach ($members as $m)
  {
    if (!isset($var->$m))
    {
      return 4;
    }
  }
  return 0; // PASS
}

function myprint($s)
{
  print($s);

  if (isset($_SERVER["REQUEST_METHOD"]))
  {
    print("<BR>");
  }
  else
  {
    print("\n");
  }
}

function RunTests()
{
  global $t;
  global $warn;
  global $error;
  global $miss;

  foreach ($t as $test)
  {
    $test = "t_" . $test;
    if (function_exists($test))
    {
      $rv = $test();

      if ($rv > 0)
      {
	    myprint("$test: FAILURE: $rv");
	    $error++;
      }
      else
      {
	    myprint("$test: Pass");
      }
    }
    else
    {
      myprint("$test: does not exist");
      $miss++;
    }
  }
}

//
// Main Program.
//
$ran1 = 0;

if ($argc == 2)
{
  if (in_array($argv[1], $cl))
  {
    $f = "t_" . $argv[1];
    $rv = $f();
    if ($rv > 0)
    {
      myprint("$f: FAILURE: $rv");
    }
    else
    {
      myprint("$f: Pass");
    }
    $ran1 = 1;
  }
}
if ($ran1 == 0)
{
  RunTests();

  $count = count($t);
  $passes = $count - $error - $miss;

  myprint("");
  myprint("Tests: $count");
  myprint("Passes: $passes");
  myprint("Failures: $error");
  myprint("Warnings: $warn");
  myprint("Missing: $miss");
}

?>
