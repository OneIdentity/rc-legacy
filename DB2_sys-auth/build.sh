#!/bin/sh
VERSION=3.0.0.`tr -d '\012' < build-number.txt`
SERVERLIST="vassles9ppc.vintela.com vasx86.vintela.com vasx8664.vintela.com vassol8.vintela.com vashpux.vintela.com vashpuxia64.vintela.com 10.4.23.115 vasaix51.vintela.com vasaix53.vintela.com"
#SERVERLIST="vasx86.vintela.com vasx8664.vintela.com vassol8.vintela.com vashpux.vintela.com vashpuxia64.vintela.com 10.4.23.115 vasaix53.vintela.com"
#SERVERLIST="vasx86.vintela.com vasx8664.vintela.com vassol8.vintela.com vashpuxia64.vintela.com vashpux.vintela.com 10.4.23.115"
#SERVERLIST="vassles9ppc.vintela.com"
#SERVERLIST="vasx86.vintela.com vasx8664.vintela.com vasia64.vintela.com vassles8ppc.vintela.com vassles9ppc.vintela.com vass390.vintela.com vass390x.vintela.com vassol6.vintela.com vassol7.vintela.com vassol8.vintela.com vassol8x86.vintela.com vassolx8664.vintela.com vashpux.vintela.com vashpux11i.vintela.com vashpuxia64.vintela.com vasaix43.vintela.com vasaix51.vintela.com vasaix53.vintela.com vasirix.vintela.com vastru64.vintela.com"

#SERVERLIST="vasx86.vintela.com vasx8664.vintela.com vassol8.vintela.com vashpuxia64.vintela.com 10.4.23.115 vasaix51.vintela.com vasaix53.vintela.com"

server_test()
{
    ssh $1 exit 0
    if [ $? -ne 0 ] ; then
        echo "Server: <$server> failed."
        echo $server >> ./failed
    fi        
}
    
server_copy()
{
    scp DB2_sys-auth_src.$VERSION.tar.gz $1: >/dev/null
    if [ $? -ne 0 ] ; then
        echo "Server: <$server> failed on copy."
        echo $server >> ./failed
    fi        
}
    
server_clean()
{
    ssh $1 "rm -rf DB2_sys-auth/ DB2_sys-auth_src.$VERSION.tar.gz DB2_sys-auth_src.$VERSION.tar DB2_sys-auth_*.$VERSION.tar.gz"
    if [ $? -ne 0 ] ; then
        echo "Server: <$server> failed on run."
        echo $server >> ./failed
    fi        
}
    
server_build()
{
    ssh $1 "export PATH=/opt/ccache/bin:/opt/hp-gcc/bin:/opt/quest/bin:/usr/local/pa20_32/bin:/usr/local/bin:/usr/contrib/bin:/usr/local:\$PATH; rm -rf DB2_sys-auth/ ; gunzip DB2_sys-auth_src.$VERSION.tar.gz && tar xf DB2_sys-auth_src.$VERSION.tar && cd DB2_sys-auth/ && ./configure && make bin_dist && mv DB2_sys-auth_*.$VERSION.tar.gz ../"
    if [ $? -ne 0 ] ; then
        echo "Server: <$server> failed on run."
        echo $server >> ./failed
    fi        
}
    
server_build_test_clean()
{
    if [ "$1" = "10.4.23.115" ] ; then
        ssh $1 "rm -rf DB2_sys-auth/ DB2_sys-auth_src.$VERSION.tar.gz DB2_sys-auth_src.$VERSION.tar DB2_sys-auth_*.$VERSION.tar.gz sys-auth.conf"
    else
        ssh $1 "export PATH=/opt/hp-gcc/bin:/opt/quest/bin:/usr/local/pa20_32/bin:/usr/local/bin:/usr/contrib/bin:/usr/local:\$PATH; cd DB2_sys-auth/ && make check && cd ../ && rm -rf DB2_sys-auth/ DB2_sys-auth_src.$VERSION.tar.gz DB2_sys-auth_src.$VERSION.tar DB2_sys-auth_*.$VERSION.tar.gz sys-auth.conf"
    fi
    if [ $? -ne 0 ] ; then
        echo "Server: <$server> failed on run."
        echo $server >> ./failed
    fi        
}
    
server_gather()
{
    scp $1:DB2_sys-auth_*.$VERSION.tar.gz binaries/
    if [ $? -ne 0 ] ; then
        echo "Server(s): <$server> failed."
        echo $server >> ./failed
    fi        
}

check_failed ()
{
    if [ -f ./failed ] ; then
        echo "$1 call failed on:"
        cat ./failed
        rm -rf ./failed
        exit 1
    fi    
}

loop ()
{
    echo "<$1> Begin"
    rm -rf ./failed
    for server in $SERVERLIST ; do
        echo "" >> out.$server
        echo "$1" >> out.$server
        $1 $server >> out.$server 2>&1 &
    done

    wait

    check_failed $1
    echo "<$1> End"
    echo
}

rm -rf out.*

loop server_test

echo "<setup> Begin"
make distclean 2>/dev/null 1>&2

./bootstrap.sh

./configure 2>/dev/null 1>&2

make src_dist  2>/dev/null 1>&2

echo "<setup> End"
echo

loop server_clean

loop server_copy

./test_reset.sh >/dev/null

loop server_build

rm -rf binaries/

mkdir binaries

cp DB2_sys-auth_src.$VERSION.tar.gz binaries/

loop server_gather

loop server_build_test_clean

tar czf out.$VERSION.tar.gz out.*
rm -rf out.*

make distclean
cd binaries/
tar cvf DB2_sys-auth.$VERSION.tar *
cd ../
