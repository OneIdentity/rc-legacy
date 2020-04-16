
AUTOMAKE_OPTIONS =	foreign subdir-objects

AM_CPPFLAGS = -I$(srcdir)/include
bin_PROGRAMS =
man_MANS =
EXTRA_DIST =

noinst_LIBRARIES =	 libauthtest.a
libauthtest_a_SOURCES =	 lib/authtest/colours.c
libauthtest_a_SOURCES += lib/authtest/privsep.c 
libauthtest_a_SOURCES += lib/authtest/strtouid.c 
libauthtest_a_SOURCES += include/authtest.h

#
# Kerberos User OK
#
bin_PROGRAMS +=		kuserok
kuserok_CFLAGS =	@KRB5_CFLAGS@
kuserok_SOURCES =       src/kuserok.c
kuserok_LDFLAGS =	@KRB5_LIBS@
kuserok_LDADD =		-L. -lauthtest
kuserok_DEPENDENCIES =	libauthtest.a
man_MANS += 		src/kuserok.1

#
# PAM test
#
if HAVE_PAM
bin_PROGRAMS +=		pamtest
pamtest_SOURCES =       src/pamtest.c
pamtest_LDADD =		-L. -lauthtest $(LIBOBJS)
pamtest_DEPENDENCIES =	libauthtest.a $(LIBOBJS)
man_MANS +=		src/pamtest.1

#
# pam_debug module
#
securitydir =		$(libdir)/security
security_LTLIBRARIES =  pam_debug.la
pam_debug_la_SOURCES =  src/pam_debug.c src/syslog.c
pam_debug_la_LDFLAGS =  -module -XCClinker -nostdlib
#pam_debug_la_LIBADD =	$(LIBOBJS)
install-pam: pam_debug.la
	sudo $(MAKE) install-securityLTLIBRARIES
endif

#
# LAM test
#
if HAVE_LAM
bin_PROGRAMS +=		lamtest
lamtest_SOURCES =       src/lamtest.c
lamtest_LDADD =		-L. -lauthtest $(LIBOBJS)
lamtest_DEPENDENCIES =	libauthtest.a $(LIBOBJS)
man_MANS +=		src/lamtest.1
endif

#
# Unix GSSAPI
#
bin_PROGRAMS +=		gss-server gss-client
man_MANS +=		gssapi/unix/gss-server.1
man_MANS +=		gssapi/unix/gss-client.1

gss_common_sources =    gssapi/unix/base64.c      gssapi/unix/base64.h
gss_common_sources +=   gssapi/unix/gss-common.c  gssapi/unix/gss-common.h

gss_server_SOURCES=	gssapi/unix/gss-server.c $(gss_common_sources)
gss_client_SOURCES=	gssapi/unix/gss-client.c $(gss_common_sources)
gss_server_CFLAGS =	@GSS_CFLAGS@
gss_server_LDFLAGS =	@GSS_LIBS@
gss_server_LDADD =	libauthtest.a
gss_client_CFLAGS =	@GSS_CFLAGS@
gss_client_LDFLAGS =	@GSS_LIBS@
gss_client_LDADD =	libauthtest.a

bin_SCRIPTS =		gss-dump
EXTRA_DIST +=		gssapi/unix/gss-dump.sh
man_MANS +=		gssapi/unix/gss-dump.1
CLEANFILES  =		gss-dump

gss-dump: $(srcdir)/gssapi/unix/gss-dump.sh
	cp $(srcdir)/gssapi/unix/gss-dump.sh $@
	chmod +x $@

#
# Java GSSAPI
#
if HAVE_JAVAC
javagss_src =		gssapi/java/src/main/java
noinst_JAVA =
noinst_JAVA +=	$(javagss_src)/Base64Decoder.java
noinst_JAVA +=	$(javagss_src)/Base64Encoder.java
noinst_JAVA +=	$(javagss_src)/Client.java
noinst_JAVA +=	$(javagss_src)/Console.java
noinst_JAVA +=	$(javagss_src)/GSSUtil.java
noinst_JAVA +=	$(javagss_src)/Server.java

javagss_jar =		gssapi/java/target/authtest-java-1.0.jar
$(javagss_jar): $(top_srcdir)/configure.ac
	$(MAKE) $(AM_MAKEFLAGS) class"noinst".stamp
	$(MKDIR_P) $(dir $@)
	$(JAR) fc $@ -C $(JAVAROOT) *.class
EXTRA_DIST +=		$(javagss_jar)

EXTRA_DIST +=	gssapi/java/README
EXTRA_DIST +=	gssapi/java/jaas-krb5.conf
EXTRA_DIST +=	gssapi/java/pom.xml
EXTRA_DIST +=	$(noinst_JAVA)
EXTRA_DIST +=	gssapi/java/src/test/java/Base64DecoderTest.java
EXTRA_DIST +=	gssapi/java/src/test/java/Base64EncoderTest.java
endif

#
# Windows GSSAPI
#
EXTRA_DIST +=	gssapi/windows/README.txt
EXTRA_DIST +=	gssapi/windows/Makefile
EXTRA_DIST +=	gssapi/windows/mkversion.vbs
EXTRA_DIST +=	gssapi/windows/client.c
EXTRA_DIST +=	gssapi/windows/server.c
EXTRA_DIST +=	gssapi/windows/wsspi.h
EXTRA_DIST +=	gssapi/windows/clipboard.c gssapi/windows/clipboard.h
EXTRA_DIST +=	gssapi/windows/common.c    gssapi/windows/common.h
EXTRA_DIST +=	gssapi/windows/deleg.c     gssapi/windows/deleg.h
EXTRA_DIST +=	gssapi/windows/errmsg.c    gssapi/windows/errmsg.h
EXTRA_DIST +=	gssapi/windows/flags.c     gssapi/windows/flags.h
EXTRA_DIST +=	gssapi/windows/getopt.c    gssapi/windows/getopt.h
EXTRA_DIST +=	gssapi/windows/userio.c    gssapi/windows/userio.h
EXTRA_DIST +=	gssapi/windows/wrap.c      gssapi/windows/wrap.h


EXTRA_DIST +=	$(man_MANS)
EXTRA_DIST +=	LICENCE pp authtest.pp
package: authtest.pp pp
	DESTDIR=`pwd -P`/destdir; rm -rf $$DESTDIR; mkdir -p $$DESTDIR && \
	$(MAKE) install DESTDIR=$$DESTDIR && \
	$(SHELL) $(srcdir)/pp --destdir=$$DESTDIR \
	    $(srcdir)/authtest.pp \
	    bindir=$(bindir) \
	    mandir=$(mandir) \
	    version=$(PACKAGE_VERSION) \
	    name=$(PACKAGE_NAME)

