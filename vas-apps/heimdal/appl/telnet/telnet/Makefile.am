# $Id: Makefile.am,v 1.17 2004/08/26 11:55:20 joda Exp $

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I$(srcdir)/.. $(INCLUDE_krb4) $(INCLUDE_des)

bin_PROGRAMS = telnet

CHECK_LOCAL = 

telnet_SOURCES  = authenc.c commands.c main.c network.c ring.c \
		  sys_bsd.c telnet.c terminal.c \
		  utilities.c defines.h externs.h ring.h telnet_locl.h types.h

man_MANS = telnet.1

EXTRA_DIST = $(man_MANS)

LDADD = ../libtelnet/libtelnet.a \
	$(top_builddir)/lib/vers/libvers.la \
	$(LIB_krb5) \
	$(LIB_krb4) \
	$(LIB_des) \
	$(LIB_tgetent) \
	$(LIB_kdfs) \
	$(LIB_roken)
