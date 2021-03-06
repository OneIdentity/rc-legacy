# $Id: Makefile.am,v 1.137 2005/05/24 11:39:01 lha Exp $

include $(top_srcdir)/Makefile.am.common

ACLOCAL_AMFLAGS = -I ../../cf

CLEANFILES = roken.h make-roken.c $(XHEADERS)

noinst_LTLIBRARIES = libroken.la
libroken_la_LDFLAGS = -version-info 17:0:1
libroken_la_CPPFLAGS = -DBUILD_ROKEN_LIB

noinst_PROGRAMS = make-roken snprintf-test resolve-test

nodist_make_roken_SOURCES = make-roken.c

check_PROGRAMS = 				\
		base64-test			\
		getaddrinfo-test		\
		hex-test			\
		test-readenv			\
		parse_bytes-test		\
		parse_reply-test		\
		parse_time-test			\
		snprintf-test			\
		strpftime-test

TESTS = $(check_PROGRAMS)

LDADD = libroken.la $(LIB_crypt)
make_roken_LDADD = 

noinst_LTLIBRARIES += libtest.la
libtest_la_SOURCES = strftime.c strptime.c snprintf.c
libtest_la_CFLAGS = -DTEST_SNPRINTF

parse_reply_test_SOURCES = parse_reply-test.c resolve.c
parse_reply_test_CFLAGS  = -DTEST_RESOLVE

test_readenv_SOURCES = test-readenv.c test-mem.c

parse_time_test_SOURCES = parse_time-test.c test-mem.c test-mem.h

strpftime_test_SOURCES	= strpftime-test.c
strpftime_test_LDADD = libtest.la $(LDADD)
snprintf_test_SOURCES	= snprintf-test.c snprintf-test.h
snprintf_test_LDADD = libtest.la $(LDADD)
snprintf_test_CFLAGS	= -DTEST_SNPRINTF

resolve_test_SOURCES = resolve-test.c

libroken_la_SOURCES =		\
	base64.c		\
	bswap.c			\
	concat.c		\
	environment.c		\
	eread.c			\
	esetenv.c		\
	ewrite.c		\
	getaddrinfo_hostspec.c	\
	get_default_username.c	\
	get_window_size.c	\
	getarg.c		\
	getnameinfo_verified.c	\
	getprogname.c		\
	h_errno.c		\
	hex.c			\
	hostent_find_fqdn.c	\
	issuid.c		\
	k_getpwnam.c		\
	k_getpwuid.c		\
	mini_inetd.c		\
	net_read.c		\
	net_write.c		\
	parse_bytes.c		\
	parse_time.c		\
	parse_units.c		\
	realloc.c		\
	resolve.c		\
	roken_gethostby.c	\
	rtbl.c			\
	rtbl.h			\
	setprogname.c		\
	signal.c		\
	simple_exec.c		\
	snprintf.c		\
	socket.c		\
	strcollect.c		\
	timeval.c		\
	tm2time.c		\
	unvis.c			\
	verify.c		\
	vis.c			\
	vis.h			\
	warnerr.c		\
	write_pid.c		\
	xdbm.h

EXTRA_libroken_la_SOURCES =	\
	err.hin			\
	fnmatch.hin		\
	glob.hin		\
	ifaddrs.hin		\
	vis.hin	

EXTRA_DIST = roken.awk roken.h.in

libroken_la_LIBADD = @LTLIBOBJS@
if have_cgetent
else
libroken_la_LIBADD += $(DBLIB)
endif

$(LTLIBOBJS) $(libroken_la_OBJECTS): roken.h $(XHEADERS)

BUILT_SOURCES = make-roken.c roken.h

if have_err_h
err_h =
else
err_h = err.h
endif

if have_fnmatch_h
fnmatch_h =
else
fnmatch_h = fnmatch.h
endif

if have_glob_h
glob_h =
else
glob_h = glob.h
endif

if have_ifaddrs_h
ifaddrs_h =
else
ifaddrs_h = ifaddrs.h
endif

if have_vis_h
vis_h = 
else
vis_h = vis.h
endif

## these are controlled by configure
XHEADERS = $(err_h) $(fnmatch_h) $(glob_h) $(ifaddrs_h) $(vis_h)
CLEANFILES += err.h fnmatch.h glob.h ifaddrs.h vis.h

noinst_HEADERS = 				\
	base64.h				\
	getarg.h				\
	hex.h					\
	parse_bytes.h 				\
	parse_time.h 				\
	parse_units.h				\
	resolve.h 				\
	roken-common.h 				\
	rtbl.h 					\
	xdbm.h					\
	$(XHEADERS) 

build_HEADERZ = test-mem.h

noinst_HEADERS += roken.h

noinst_MANS = getarg.3 parse_time.3 rtbl.3

SUFFIXES += .hin
.hin.h:
	cp $< $@

roken.h: make-roken$(EXEEXT)
	@./make-roken$(EXEEXT) > tmp.h ;\
	if [ -f roken.h ] && cmp -s tmp.h roken.h ; then rm -f tmp.h ; \
	else rm -f roken.h; mv tmp.h roken.h; fi

make-roken.c: roken.h.in roken.awk
	$(AWK) -f $(srcdir)/roken.awk $(srcdir)/roken.h.in > make-roken.c
