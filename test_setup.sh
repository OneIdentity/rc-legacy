#!/bin/sh

# Sets up users for password based tests. 

echo "Only run this if you want to tick off Seth"
echo
echo "This script re-makes users used for DB2 testing, but"
echo "db2_test needs the 'cannot change password' flags set,"
echo "and currently that can only be done from Windows, so need"
echo "at least that extra step if this is run."
echo "See: http://msdn.microsoft.com/en-us/library/aa746398(VS.85).aspx (Modifying User Cannot Change Password (LDAP Provider))"
exit 1

VAS=/opt/quest/bin/vastool
AUTH="-u administrator@build.vas -w test123"

./test_cleanup.sh

$VAS $AUTH kinit

if [ $? -ne 0 ] ; then
    echo "Unable to auth using <$AUTH>, exiting."
    exit 1
fi

$VAS $AUTH create -c "cn=users,dc=build,dc=vas" -g -i "db2_gr1:x:550001:" db2_gr1@build.vas
$VAS $AUTH create -g -c "cn=users,dc=build,dc=vas" -i "db2_gr2:x:550002:" db2_gr2@build.vas
$VAS $AUTH create -g -c "cn=users,dc=build,dc=vas" -i "db2_gr3:x:550003:" db2_gr3@build.vas
$VAS $AUTH create -c "cn=users,dc=build,dc=vas" -xp Abcd1234 -i "db2_test:x:550000:550001::/home/db2_test:/bin/sh" db2_test@build.vas
$VAS $AUTH setattrs -d "cn=db2_gr2,cn=users,dc=build,dc=vas" member "cn=db2_test,cn=users,dc=build,dc=vas"

I=550001
for username in lxx64 lxx86 lx390 sol8s hpia hppa aix53 aix5 aix51 lxppc; do
    $VAS $AUTH create -p Abcd1234 -c "cn=users,dc=build,dc=vas" -i "${username}_pwd:x:$I:550001::/home/${username}_pwd:/bin/sh" ${username}_pwd@build.vas
    ((++I))
done
