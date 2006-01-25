#!/bin/sh

# Uncomment for debug info.
# set -x


if [ -z "$1" ] || [ -n "$3" ]
then
	echo "Usage: $0 <Instance owner, i.e. db2inst1> [LAM] "
	exit 1
fi

whoami | grep root
if [ $? -ne 0 ]
then
	echo "Must be root to run this!"
	exit 1
fi

INSTANCEHOME="`eval echo ~${1}`"
PLUGINPATH32="${INSTANCEHOME}/sqllib/security32/plugin"
PLUGINPATH64="${INSTANCEHOME}/sqllib/security64/plugin"
LIBFILE=sys-auth.so
LIBFILE32=sys-auth32.so
LIBFILE64=sys-auth64.so
AUTHFILE32=sys-auth32
AUTHFILE64=sys-auth64

if [ ! -f ${LIBFILE32} ]
then
	echo "Library ${LIBFILE32} not found!"
	exit 1
fi

if [ -f ${LIBFILE64} ]
then
    echo "64-bit library found, installing both 32 and 64 libraries/auth programs."
    TYPE=64
else 
    echo "64-bit library not found, installing only 32 library and auth program."
    TYPE=32
fi

if [ "$2" != "LAM" ] && [ -n "$2" ]
then
	echo "Second argument can only be LAM."
	exit 1
fi

if [ "$2" = "LAM" ] 
then
		AUTH32=lamAuth32
		AUTH64=lamAuth64
else
		AUTH32=pamAuth32
		AUTH64=pamAuth64
fi


if [ ! -x "${AUTH32}" ]
then
	echo "Auth program ${AUTH32} not found."
	exit 1
fi

if [ "$TYPE" = "64" ]
then
    if [ ! -x "${AUTH64}" ]
    then
    	echo "Auth program ${AUTH64} not found."
    	exit 1
    fi
fi

if [ ! -d ${PLUGINPATH32} ]
then
        echo "Directory $PLUGINPATH32 not found!"
        echo "Do you have the right name for an instance owner?"
        exit 1
fi

echo "Everything checks out, installing the 32-bit files."
echo "First the cleanup, delete the old versions if they exist."
rm -f ${PLUGINPATH32}/server/${LIBFILE}
rm -f ${PLUGINPATH32}/client/${LIBFILE}
rm -f ${PLUGINPATH32}/group/${LIBFILE}
rm -f ${PLUGINPATH32}/${AUTHFILE32}
# Clean up old files as well.
rm -f ${PLUGINPATH32}/*/${LIBFILE32}

echo "Now copy over the ${LIBFILE32} to ${PLUGINPATH32}/server&client&group/${LIBFILE}."
cp ${LIBFILE32} ${PLUGINPATH32}/server/${LIBFILE}
cp ${LIBFILE32} ${PLUGINPATH32}/client/${LIBFILE}
cp ${LIBFILE32} ${PLUGINPATH32}/group/${LIBFILE}
echo "Copy ${AUTH32} to ${PLUGINPATH32}/${AUTHFILE32}"
cp ${AUTH32} ${PLUGINPATH32}/${AUTHFILE32}
echo "And fix the ownerships/permissions. WARNING!!! ${PLUGINPATH32}/${AUTHFILE32} is setuid root becasue it has to be to do authentications. Just so you know."
chown ${1} ${PLUGINPATH32}/server/${LIBFILE} ${PLUGINPATH32}/client/${LIBFILE} ${PLUGINPATH32}/group/${LIBFILE}
chmod 0755 ${PLUGINPATH32}/server/${LIBFILE} ${PLUGINPATH32}/client/${LIBFILE} ${PLUGINPATH32}/group/${LIBFILE}
chown root ${PLUGINPATH32}/${AUTHFILE32} 
chmod 4755 ${PLUGINPATH32}/${AUTHFILE32} 

if [ "${TYPE}" = "64" ]
then
    echo "Now the 64-bit files."
    echo "First the cleanup, delete the old versions if they exist."
	rm -f ${PLUGINPATH64}/server/${LIBFILE}
	rm -f ${PLUGINPATH64}/client/${LIBFILE}
	rm -f ${PLUGINPATH64}/group/${LIBFILE}
	rm -f ${PLUGINPATH64}/${AUTHFILE64}
    # Clean up old files as well.
    rm -f ${PLUGINPATH64}/*/${LIBFILE64}
	
    echo "Now copy over the ${LIBFILE64} to ${PLUGINPATH64}/server&client&group/${LIBFILE}."
	cp ${LIBFILE64} ${PLUGINPATH64}/server/${LIBFILE}
	cp ${LIBFILE64} ${PLUGINPATH64}/client/${LIBFILE}
	cp ${LIBFILE64} ${PLUGINPATH64}/group/${LIBFILE}
    echo "Copy ${AUTH64} to ${PLUGINPATH64}/${AUTHFILE64}"
	cp ${AUTH64} ${PLUGINPATH64}/${AUTHFILE64}
    echo "And fix the ownerships/permissions. WARNING!!! ${PLUGINPATH64}/${AUTHFILE64} is setuid root becasue it has to be to do authentications. Just so you know."
	chown ${1} ${PLUGINPATH64}/server/${LIBFILE} ${PLUGINPATH64}/client/${LIBFILE} ${PLUGINPATH64}/group/${LIBFILE}
	chmod 0755 ${PLUGINPATH64}/server/${LIBFILE} ${PLUGINPATH64}/client/${LIBFILE} ${PLUGINPATH64}/group/${LIBFILE}
	chown root ${PLUGINPATH64}/${AUTHFILE64} 
	chmod 4755 ${PLUGINPATH64}/${AUTHFILE64} 
fi

echo ""
echo ""
echo ""
echo "The plug-in is now installed."
echo ""
echo ""
echo ""
echo "To make the instance use it, 3 more steps. "
echo "As the instance owner or user with admin, run the 3 following commands:"
echo ""
echo "db2 update dbm cfg using SRVCON_PW_PLUGIN sys-auth"
echo "db2 update dbm cfg using GROUP_PLUGIN sys-auth"
echo "db2 update dbm cfg using CLNT_PW_PLUGIN sys-auth"
echo ""
echo "Then restart the instance."
echo ""
echo ""
echo ""
echo "If the instance partitioned the install script will needs to be run on each machine that hosts a partition."
echo ""
echo "Any issues, please use the general mailing list general@rc.vintela.com"
echo "after signing up at http://rc.vintela.com/mailman/listinfo/general"
