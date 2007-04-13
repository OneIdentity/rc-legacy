<?

/* Included by t_vas_ldap_set_attributes[1234].php */

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

?>
