INCLUDES = -I$(srcdir)/../minilzo

lib_LTLIBRARIES = libicecc.la

libicecc_la_SOURCES = job.cpp comm.cpp getifaddrs.cpp logging.cpp tempfile.c
libicecc_la_SOURCES += daemon.c wait4.c setenv.c getloadavg.c
EXTRA_HEADERS = daemon.h wait4.h setenv.h getloadavg.h
libicecc_la_LIBADD = ../minilzo/libminilzo.la
libicecc_la_CFLAGS = -fPIC -DPIC
libicecc_la_CXXFLAGS = -fPIC -DPIC

ice_HEADERS = job.h comm.h
icedir = $(includedir)/icecc

sbin_PROGRAMS = scheduler
scheduler_SOURCES = scheduler.cpp
scheduler_LDADD = libicecc.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = icecc.pc

