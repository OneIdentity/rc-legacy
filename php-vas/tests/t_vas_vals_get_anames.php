<?

include("test.php");

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

runTest("t_vas_vals_get_anames");

?>
