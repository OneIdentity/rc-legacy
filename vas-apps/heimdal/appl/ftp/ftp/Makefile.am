# $Id: Makefile.am,v 1.17 2004/08/26 11:55:16 joda Exp $

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I$(srcdir)/../common $(INCLUDE_readline) $(INCLUDE_krb4) $(INCLUDE_des)

bin_PROGRAMS = ftp

CHECK_LOCAL = 

if KRB4
krb4_sources = krb4.c
endif
if KRB5
krb5_sources = gssapi.c
endif

ftp_SOURCES = \
	cmds.c \
	cmdtab.c \
	extern.h \
	ftp.c \
	ftp_locl.h \
	ftp_var.h \
	main.c \
	pathnames.h \
	ruserpass.c \
	domacro.c \
	globals.c \
	security.c \
	security.h \
	kauth.c \
	$(krb4_sources) \
	$(krb5_sources)

EXTRA_ftp_SOURCES = krb4.c gssapi.c

man_MANS = ftp.1

EXTRA_DIST = $(man_MANS)

LDADD = \
	../common/libcommon.a \
	$(top_builddir)/lib/vers/libvers.la \
	$(LIB_gssapi) \
	$(LIB_krb5) \
	$(LIB_krb4) \
	$(LIB_des) \
	$(LIB_roken) \
	$(LIB_readline)
