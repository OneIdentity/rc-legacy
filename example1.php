<?php

require "vas.php";
//
// This is a simple demonstration program that illustrates
// querying Active Directory for common information.
//

//
// Constants for later....
//
$username = "jdoe";
$password = "jdoepassword";
$attrs_val2 = "John fool. Doe";
$uri = "DC://";
$scope = "sub";
$search_base  = "CN=Users,DC=EXAMPLE,DC=COM";
$search_filter = "(&(ObjectClass=User)(uidNumber=*))";

$vas = new CVAS();

$vas->authenticate($username, $password);
//
// See if we authenticated correctly.
//
if ($vas->get_error_code() != VAS_ERR_SUCCESS)
{
  echo "Authentication of $username failed.\n";
}

//
// See if our user is in the "Test Users" group.
//
echo "Is $username in Test Users:\n";

$group = "CN=Test Users,DC=example,DC=com";

$x = $vas->is_user_in_group("jdoe", $group);

if ($x == VAS_ERR_SUCCESS)
{
  echo "    Yes, $username found in group\n";
}
else
{
  if ($x == VAS_ERR_NOT_FOUND)
  {
    echo "    Not Found\n";
  }
  else
  {
    echo "    ERROR\nvas_err is ", $x, " ", $vas->get_error_string(), "\n";
  }
}

//
// Get the list of groups for our user.
//
$groups = $vas->get_groups_for_user($username, 0);
if ($vas->get_error_code() == VAS_ERR_SUCCESS)
{
  echo "Groups for ", $username, " are:\n";
  foreach ($groups as $g)
  {
    echo "    ", $g, "\n";
  }
}
else
{
  printf("Failure to find attributes.  Code: %s\n", $vas->get_error_string());
}

//
// Get the list of groups for the Administrator.
//
$groups = $vas->get_groups_for_user("Administrator", 0);
if ($vas->get_error_code() == VAS_ERR_SUCCESS)
{
  echo "Groups for ", "Administrator", " are:\n";
  foreach ($groups as $g)
  {
    echo "    ", $g, "\n";
  }
}
else
{
  printf("Failure to find attributes.  Code: %s\n", $vas->get_error_string());
}

//
// Find all the the attributes for $username that match homePhone.
//
$attrs = $vas->find( $uri, $scope, $search_base, $search_filter, "homePhone" );

if ($vas->get_error_code() == VAS_ERR_SUCCESS)
{
  echo "Attributes for $username are:\n";
  foreach ($attrs as $a)
  {
    echo "    ", $a, "\n";
  }
}
else
{
  printf("Failure to find attributes.  Code: %s\n", $vas->get_error_string());
}

//
// Find all the the attributes for Test Users
//
$attrs = $vas->get_group_attributes("Test Users", array("name", "description", "mail") );

if ($vas->get_error_code() == VAS_ERR_SUCCESS)
{
  echo "Attributes for Test Users are:\n";
  foreach ($attrs as $a)
  {
    echo "    ", $a, "\n";
  }
}
else
{
  printf("Failure to find attributes.  Code: %s\n", $vas->get_error_string());
}

//
// Add and then Delete the company attribute for the test user.
//

// do an extra delete incase there is one already.
$attrs = $vas->set_attributes("DC://", "CN=$attrs_val2,$search_base",
			      new CVAS_LDAPMod(LDAP_MOD_DELETE, "company"));

$m = new CVAS_LDAPMod(LDAP_MOD_ADD, "company");
$m->add_value("this is the company name");
$attrs = $vas->set_attributes("DC://", "CN=$attrs_val2,$search_base", $m);

if ($vas->get_error_code() == VAS_ERR_SUCCESS)
{
  printf("Company attribute for %s added\n", $attrs_val2);
}
else
{
  printf("Failure to add attribute.  Code: %s\n", $vas->get_error_string());
}

$attrs = $vas->set_attributes("DC://", "CN=$attrs_val2,$search_base",
			      new CVAS_LDAPMod(LDAP_MOD_DELETE, "company"));

if ($vas->get_error_code() == VAS_ERR_SUCCESS)
{
  printf("Company attribute for %s deleted\n", $attrs_val2);
}
else
{
  printf("Failure to delete attribute.  Code: %s\n", $vas->get_error_string());
}

?>
