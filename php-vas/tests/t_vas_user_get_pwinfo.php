<?

include("test.php");

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

runTest("t_vas_user_get_pwinfo");

?>
