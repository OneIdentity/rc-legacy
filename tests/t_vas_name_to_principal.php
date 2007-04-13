<?

include("test.php");

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

runTest("t_vas_name_to_principal");

?>
