# $Id: Makefile.am,v 1.19 2004/08/26 11:55:21 joda Exp $

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I$(srcdir)/.. $(INCLUDE_krb4) $(INCLUDE_des)

libexec_PROGRAMS = telnetd

CHECK_LOCAL = 

telnetd_SOURCES  = telnetd.c state.c termstat.c slc.c sys_term.c \
		   utility.c global.c authenc.c defs.h ext.h telnetd.h

man_MANS = telnetd.8

EXTRA_DIST = $(man_MANS)

LDADD = \
	../libtelnet/libtelnet.a \
	$(top_builddir)/lib/vers/libvers.la \
	$(LIB_krb5) \
	$(LIB_krb4) \
	$(LIB_des) \
	$(LIB_tgetent) \
	$(LIB_logwtmp) \
	$(LIB_logout) \
	$(LIB_openpty) \
	$(LIB_kdfs) \
	$(LIB_roken)
