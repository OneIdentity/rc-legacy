<?

/* This test should be run in process separate to other tests,
 * because we want to avoid VAS's cache */

include("test.php");
include("checkAttribute.php");

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

runTest("t_vas_ldap_set_attributes4");

?>
