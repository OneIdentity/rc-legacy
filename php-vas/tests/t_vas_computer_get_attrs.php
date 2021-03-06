<?

include("test.php");

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

runTest("t_vas_computer_get_attrs");

?>
