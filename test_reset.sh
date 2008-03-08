#!/bin/sh

# Sets up users for password based tests. 

VAS=/opt/quest/bin/vastool
AUTH="-u administrator@build.vas -w test123"

$VAS $AUTH kinit

if [ $? -ne 0 ] ; then
    echo "Unable to auth using <$AUTH>, exiting."
    exit 1
fi

( echo Abcd1234 ; echo Abcd1234 ) | $VAS $AUTH -s passwd db2_test &
$VAS $AUTH group db2_gr2 add db2_test 2>/dev/null &

for username in lxx64 lxx86 lx390 sol8s hpia hppa aix53 aix51 ; do
    ( echo Abcd1234 ; echo Abcd1234 ) | $VAS $AUTH -s passwd -x ${username}_pwd &
done

wait
