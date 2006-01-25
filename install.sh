#!/bin/sh
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -n "$4" ]
then
	echo "Usage: $0 <32|64> <Instance home i.e. /home/db2inst1> [LAM] "
	exit 1
fi

whoami | grep root
if [ $? -ne 0 ]
then
	echo "Must be root to run this!"
	exit 1
fi

if [ "$1" != "32" ] && [ "$1" != "64" ]
then
        echo "First argument must be 32 or 64. Match to the output of db2level"
        exit 1
else 
	PLUGINPATH=${2}/sqllib/security${1}/plugin
	AUTHFILE=sys-auth${1}
	LIBFILE=sys-auth${1}.so
	TYPE=32
fi

if [ ! -d "$PLUGINPATH" ]
then
        echo "Directory $PLUGINPATH not found!"
        exit 1
fi

if [ ! -f "$LIBFILE" ]
then
	echo "File ${LIBFILE} not found."
	exit 1
fi

if [ "$3" != "LAM" ]
then
	echo "Third argument must be LAM or blank."
	exit 1
fi

if [ ! -d "$2" ] 
then
	echo "Directory $2 not found!"
	exit 1
fi

if [ "$3" = "LAM" ] 
then
	if [ $TYPE = "32" ]
	then
		AUTH_IN=lamAuth32
	else
		AUTH_IN=lamAuth64
	fi
else
	if [ $TYPE = "32" ]
	then
		AUTH_IN=pamAuth32
	else
		AUTH_IN=pamAuth64
	fi
fi


if [ ! -x "${AUTH_IN}" ]
then
	echo "File ${AUTH_IN} not found."
	exit 1
fi


rm -f ${PLUGINPATH}/server/${LIBFILE}
rm -f ${PLUGINPATH}/client/${LIBFILE}
rm -f ${PLUGINPATH}/group/${LIBFILE}
rm -f ${PLUGINPATH}/${AUTHFILE}

cp -p ${LIBFILE} ${PLUGINPATH}/server/.
cp -p ${LIBFILE} ${PLUGINPATH}/client/.
cp -p ${LIBFILE} ${PLUGINPATH}/group/.
cp -p ${AUTH_IN} ${PLUGINPATH}/${AUTHFILE}
chown root:staff ${PLUGINPATH}/${AUTHFILE} 
chmod 4755 ${PLUGINPATH}/${AUTHFILE} 
