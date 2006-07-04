#!/bin/sh

SetDebugAll ()
{

	SetDebug sys-auth.c $1
	SetDebug pamAuth.c $1
	if [ -f "lamAuth.c" ]
	then
		SetDebug lamAuth.c $1
	fi

}


SetDebug ()
{
	if [ ! -f  $1 ]  
	then
		return
	fi

	if [ "$2" != "1" ] && [ "$2" != "0" ]
	then
		return
	fi

	cp $1 ${1}.bak

	if [ "$2" = 0 ] 
	then
		sed 's/#define SHOW_ERROR.*/#define SHOW_ERROR 0/' < ${1}.bak > $1
	else 
		sed 's/#define SHOW_ERROR.*/#define SHOW_ERROR 1/' < ${1}.bak > $1
	fi

	rm ${1}.bak
}

DB2_SRC=DB2_${1}_src
DB2_BIN=DB2_${1}_bin

if [ ! -d "$DB2_SRC" ] || [ ! -d "$DB2_BIN" ]
then
	echo "Didn't find $DB2_SRC or $DB2_BIN"
	exit 1
fi

rm -f $DB2_BIN/debug/*
rm -f $DB2_BIN/*

cd $DB2_SRC
make cleanall

SetDebugAll 1
make all
cp *.so ../${DB2_BIN}/debug/.
cp [pl]amAuth[36][24] ../${DB2_BIN}/debug/.
make cleanall

SetDebugAll 0
make all
cp *.so ../${DB2_BIN}/.
cp [pl]amAuth[36][24] ../${DB2_BIN}/.
make cleanall

cp *.sh ../${DB2_BIN}/.
