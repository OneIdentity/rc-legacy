# $Id: Makefile.am,v 1.33 2005/04/29 10:59:24 lha Exp $

include $(top_srcdir)/Makefile.am.common

noinst_LTLIBRARIES = libdes.la
libdes_la_LDFLAGS = -version-info 3:1:0

build_HEADERZ = des.h md4.h md5.h sha.h rc2.h rc4.h aes.h

check_PROGRAMS = destest mdtest rctest rc2test #md5crypt_test 

TESTS = $(check_PROGRAMS)

LDADD = $(lib_LTLIBRARIES) $(LIB_roken)

libdes_la_SOURCES =	\
	aes.c		\
	aes.h		\
	des.c		\
	des.h		\
	des-tables.h	\
	hash.h		\
	md4.c		\
	md4.h		\
	md5.c		\
	md5.h		\
	rc2.c		\
	rc2.h		\
	rc4.c		\
	rc4.h		\
	rijndael-alg-fst.c \
	rijndael-alg-fst.h \
	rnd_keys.c	\
	sha.c		\
	sha.h		\
	ui.c
