# $Id: Makefile.am,v 1.18.4.1 2005/12/28 18:00:05 lha Exp $

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += $(INCLUDE_krb4) -I$(srcdir)/../login

bin_PROGRAMS = rsh

man_MANS = rsh.1 rshd.8

libexec_PROGRAMS = rshd

check_PROGRAMS = test-list

TESTS = $(check_PROGRAMS)

rsh_SOURCES  = rsh.c common.c rsh_locl.h list.c list.h

rshd_SOURCES = rshd.c common.c login_access.c rsh_locl.h login_locl.h \
	       login_protos.h

rshd_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/include

test_list_SOURCES = test-list.c list.c list.h

EXTRA_DIST = $(man_MANS)

login_access.c:
	$(LN_S) $(srcdir)/../login/login_access.c .

LDADD = \
	$(top_builddir)/lib/vers/libvers.la \
	$(LIB_krb5) \
	$(LIB_krb4) \
	$(LIB_des) \
	$(LIB_roken)
