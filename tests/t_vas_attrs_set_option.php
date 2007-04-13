<?

include("test.php");

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

runTest("t_vas_attrs_set_option");

?>
