<?

include("test.php");

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
}

runTest("t_vas_ldap_set_attributes");

?>
