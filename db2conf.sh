#!/bin/sh

# Check for usage.
if [ -z "$1" ]
then
        echo "Usage: $0 <library>"
        exit 1
fi

# Check for file.
if [ ! -f "$1" ]
then
        echo "File $1 not found."
        exit 1
fi

# Verify has right extension.
echo "$1" | grep ".so"
if [ $? -ne 0 ]
then
        echo "Please use on a '.so' file."
        exit 1
fi

# Find is 32 or 64.
echo "$1" | grep "32"
if [ $? -eq 0 ]
then
        TYPE=32
        PLUGINPATH=${HOME}/sqllib/security32/plugin
else
        TYPE=64
        PLUGINPATH=${HOME}/sqllib/security64/plugin
fi

# Cut off the .so for the configure part.
LIB_NAME=`echo "$1" | sed 's/\([^.]*\)\.so/\1/'`

# Remove old files, a straight copy might fail if the library had been previously loaded.
# Now handled in the install.sh script run by root.
#rm -f ${PLUGINPATH}/server/${1}
#rm -f ${PLUGINPATH}/client/${1}
#rm -f ${PLUGINPATH}/group/${1}

#cp -p $1 ${PLUGINPATH}/server/.
#cp -p $1 ${PLUGINPATH}/client/.
#cp -p $1 ${PLUGINPATH}/group/.

db2 update dbm cfg using SRVCON_PW_PLUGIN $LIB_NAME
db2 update dbm cfg using GROUP_PLUGIN $LIB_NAME
db2 update dbm cfg using CLNT_PW_PLUGIN $LIB_NAME

