# $Id: Makefile.am,v 1.17 2005/04/24 19:16:48 lha Exp $

include $(top_srcdir)/Makefile.am.common

if do_roken_rename
ES = snprintf.c strdup.c strlcat.c
endif

AM_CPPFLAGS += $(ROKEN_RENAME)

noinst_MANS = editline.3

noinst_LTLIBRARIES = libeditline.la
if el_compat
noinst_LTLIBRARIES += libel_compat.la
endif

noinst_PROGRAMS = testit

CHECK_LOCAL =

testit_LDADD = \
	libeditline.la \
        ../vers/libvers.la \
	$(LIB_tgetent) \
	$(LIB_roken)

noinst_HEADERS = editline.h

libeditline_la_SOURCES = \
	complete.c \
	editline.c \
	sysunix.c \
	edit_locl.h \
	editline.h \
	roken_rename.h \
	unix.h \
	$(EXTRA_SOURCE)

EXTRA_SOURCE = $(ES) 

libel_compat_la_SOURCES = edit_compat.c edit_compat.h

EXTRA_DIST = $(man_MANS)

snprintf.c:
	$(LN_S) $(srcdir)/../roken/snprintf.c .
strdup.c:
	$(LN_S) $(srcdir)/../roken/strdup.c .
strlcat.c:
	$(LN_S) $(srcdir)/../roken/strlcat.c .
