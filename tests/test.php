<?

//
// Our environment.
//
$username = "testuser";
$password = "testuser";
$adminusername = "Administrator";
$adminpassword = "test";
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
$principal = "testuser@rcdev.vintela.com";
$userupn = "testuser@rcdev.vintela.com";
$usersid = "S-1-5-21-2672905828-3419038426-2056116520-102273";
$groupsid = "S-1-5-21-2473201516-3199465966-3788853037-1121";
$dc1sid =  "S-1-5-21-2473201516-3199465966-3788853037-1003";
$computername = "dbone.dan.vas";

include("vas.php");

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
    print("<br />");
  }
  else
  {
    print("\n");
  }
}

function runTest($t)
{
  $rv = $t();
  if ($rv > 0)
  {
    print("      $t() -> $rv\n");
    exit(1);
  }
}

?>
