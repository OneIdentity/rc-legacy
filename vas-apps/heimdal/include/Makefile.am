# $Id: Makefile.am,v 1.34 2004/08/26 11:55:21 joda Exp $

include $(top_srcdir)/Makefile.am.common

#SUBDIRS = kadm5

noinst_PROGRAMS = bits make_crypto
CHECK_LOCAL =

AM_CPPFLAGS += -DHOST=\"$(CANONICAL_HOST)\"

noinst_HEADERS = crypto-headers.h pamcheck.h krb5-types.h

krb5-types.h: bits$(EXEEXT)
	./bits$(EXEEXT) krb5-types.h

crypto-headers.h: make_crypto$(EXEEXT)
	./make_crypto$(EXEEXT) crypto-headers.h

CLEANFILES =		\
	asn1.h		\
	asn1_err.h	\
	base64.h	\
	com_err.h	\
	com_right.h	\
	crypto-headers.h\
	der.h		\
	des.h		\
	editline.h	\
	err.h		\
	getarg.h	\
	glob.h		\
	gssapi.h	\
	hdb.h		\
	hdb_asn1.h	\
	hdb_err.h	\
	heim_err.h	\
	kafs.h		\
	krb5-protos.h	\
	krb5-private.h	\
	krb5-types.h	\
	krb5.h		\
	krb5_err.h	\
	md4.h		\
	md5.h		\
	rc4.h		\
	otp.h		\
	parse_time.h	\
	parse_units.h	\
	resolve.h	\
	roken-common.h	\
	roken.h		\
	sha.h		\
	sl.h		\
	xdbm.h
