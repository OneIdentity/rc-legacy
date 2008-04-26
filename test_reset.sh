#!/bin/sh

# Sets up users for password based tests. 

VAS=/opt/quest/bin/vastool
AUTH="-u administrator@build.vas -w test123"

$VAS $AUTH kinit
if [ $? -ne 0 ] ; then
    echo "Unable to auth using <$AUTH>, trying with [realms] setting..."
    sudo $VAS configure extra-realm build.vas build.build.vas

    $VAS $AUTH kinit
    if [ $? -ne 0 ] ; then
        echo "Unable to auth using <$AUTH>, exiting."
        exit 1
    fi
fi

( echo Abcd1234 ; echo Abcd1234 ) | $VAS $AUTH -s passwd db2_test@build.vas &
$VAS $AUTH group db2_gr2@build.vas add db2_test@build.vas 2>/dev/null &

for username in lxx64 lxx86 lx390 sol8s hpia hppa aix53 aix51 aix5; do
    ( echo Abcd1234 ; echo Abcd1234 ) | $VAS $AUTH -s passwd -x ${username}_pwd@build.vas &
done

wait
