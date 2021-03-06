# Process this file with automake to create Makefile.in.

AM_CPPFLAGS = -I$(top_srcdir)/src/PCSC -I$(top_builddir)/src/PCSC \
	$(SYMBOL_VISIBILITY)

lib_LTLIBRARIES = libpcsclite.la

if !HAVE_SCF
sbin_PROGRAMS = pcscd
endif
noinst_PROGRAMS = testpcsc

if HAVE_SCF
PCSC_CLIENT_SRC  = winscard_scf.c
else
PCSC_CLIENT_SRC  = winscard_clnt.c
endif

libpcsclite_la_SOURCES = \
	debug.c \
	debug.h \
	dyn_hpux.c \
	dyn_macosx.c \
	dyn_unix.c \
	error.c \
	$(PCSC_CLIENT_SRC) \
	strlcat.c \
	strlcpy.c \
	sys_unix.c \
	thread_unix.c \
	utils.c \
	winscard_msg.c
libpcsclite_la_LDFLAGS = -version-info 1:0:0
libpcsclite_la_CFLAGS = $(CFLAGS) $(PTHREAD_CFLAGS) -DLIBPCSCLITE
libpcsclite_la_LIBADD = $(COREFOUNDATION) $(LIBSMARTCARD) $(LIBDL) \
	$(PTHREAD_CFLAGS) $(PTHREAD_LIBS)

pcscd_SOURCES = \
	atrhandler.c \
	atrhandler.h \
	configfile.h \
	configfile.l \
	debuglog.c \
	dyn_generic.h \
	dyn_hpux.c \
	dyn_macosx.c \
	dyn_unix.c \
	eventhandler.c \
	eventhandler.h \
	hotplug_generic.c \
	hotplug.h \
	hotplug_libusb.c \
	hotplug_linux.c \
	hotplug_macosx.c \
	ifdwrapper.c \
	ifdwrapper.h \
	misc.h \
	parser.h \
	pcscdaemon.c \
	pcscd.h \
	pcscd.h.in \
	PCSC/debuglog.h \
	PCSC/ifdhandler.h \
	PCSC/pcsclite.h \
	PCSC/pcsclite.h.in \
	PCSC/winscard.h \
	PCSC/wintypes.h \
	powermgt_generic.c \
	powermgt_generic.h \
	powermgt_macosx.c \
	prothandler.c \
	prothandler.h \
	readerfactory.c \
	readerfactory.h \
	strlcat.c \
	strlcpy.c \
	strlcpycat.h \
	sys_generic.h \
	sys_unix.c \
	thread_generic.h \
	thread_unix.c \
	tokenparser.l \
	utils.c \
	utils.h \
	winscard.c \
	winscard_msg.c \
	winscard_msg.h \
	winscard_msg_srv.c \
	winscard_svc.c \
	winscard_svc.h
pcscd_CFLAGS = $(CFLAGS) $(PTHREAD_CFLAGS) $(LIBUSB_CFLAGS) -DPCSCD
pcscd_LDFLAGS = $(LDFLAGS) -export-dynamic
pcscd_LDADD = \
	$(PTHREAD_LIBS) $(COREFOUNDATION) \
	$(LIBUSB_LIBS) $(LIBDL) $(IOKIT) \
	$(PTHREAD_LIBS) $(PTHREAD_CFLAGS)

testpcsc_SOURCES = testpcsc.c
testpcsc_LDADD = libpcsclite.la

nobase_include_HEADERS = \
	PCSC/debuglog.h \
	PCSC/ifdhandler.h \
	PCSC/winscard.h \
	PCSC/wintypes.h

nodistheaderdir = $(includedir)/PCSC
nodistheader_DATA = PCSC/reader.h PCSC/pcsclite.h

pcdir= $(libdir)/pkgconfig
pc_DATA = libpcsclite.pc

# Hack to be able to use flex -P to enable linking of multiple lexer
# sources into one library, until we find a way to make automake handle
# this automagically.  This breaks if lex is not flex!!
tokenparser.c: tokenparser.l
	$(SHELL) $(YLWRAP) $< lex.tp.c $@ -- "$(LEX)" -Ptp $(AM_LFLAGS) $(LFLAGS)

EXTRA_DIST = README_INTERNALS.txt dyn_win32.c thread_win32.c winscard_scf.c

