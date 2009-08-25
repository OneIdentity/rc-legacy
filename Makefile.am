
AUTOMAKE_OPTIONS =	foreign

noinst_LIBRARIES =	libauthtest.a
libauthtest_a_SOURCES =	colours.c privsep.c strtouid.c authtest.h

#
# Kerberos User OK
#
bin_PROGRAMS =		kuserok
man_MANS = 		kuserok.1
kuserok_CFLAGS =	@KRB5_CFLAGS@
kuserok_LDFLAGS =	@KRB5_LIBS@
kuserok_LDADD =		-L. -lauthtest
kuserok_DEPENDENCIES =	libauthtest.a

#
# PAM test
#
if HAVE_PAM
bin_PROGRAMS +=		pamtest
pamtest_LDADD =		-L. -lauthtest $(LIBOBJS)
pamtest_DEPENDENCIES =	libauthtest.a $(LIBOBJS)
man_MANS +=		pamtest.1

securitydir =		$(libdir)/security
security_LTLIBRARIES =  pam_debug.la
pam_debug_la_SOURCES =  pam_debug.c syslog.c
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
lamtest_LDADD =		-L. -lauthtest $(LIBOBJS)
lamtest_DEPENDENCIES =	libauthtest.a $(LIBOBJS)
man_MANS +=		lamtest.1
endif

EXTRA_DIST =		LICENCE pp authtest.pp
EXTRA_DIST +=		kuserok.1 pamtest.1 lamtest.1

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

EXTRA_DIST +=		gssapi/unix/gss-client.1 
EXTRA_DIST +=		gssapi/unix/gss-server.1
EXTRA_DIST +=		gssapi/unix/gss-dump.1

bin_SCRIPTS =		gss-dump
EXTRA_DIST +=		gssapi/unix/gss-dump.sh
CLEANFILES  =		gss-dump

gss-dump: $(srcdir)/gssapi/unix/gss-dump.sh
	cp $(srcdir)/gssapi/unix/gss-dump.sh $@
	chmod +x $@

#
# Java GSSAPI
#
if HAVE_JAVAC
javagss_src =		java/src/main/java
noinst_JAVA =
noinst_JAVA +=	$(javagss_src)/Base64Decoder.java
noinst_JAVA +=	$(javagss_src)/Base64Encoder.java
noinst_JAVA +=	$(javagss_src)/Client.java
noinst_JAVA +=	$(javagss_src)/Console.java
noinst_JAVA +=	$(javagss_src)/GSSUtil.java
noinst_JAVA +=	$(javagss_src)/Server.java

javagss_jar =		java/target/authtest-java-1.0.jar
$(javagss_jar): $(top_srcdir)/configure.ac
	$(MAKE) $(AM_MAKEFLAGS) class"noinst".stamp
	$(MKDIR_P) $(dir $@)
	$(JAR) fc $@ -C $(JAVAROOT) *.class
EXTRA_DIST +=		$(javagss_jar)

EXTRA_DIST +=	java/README
EXTRA_DIST +=	java/jaas-krb5.conf
EXTRA_DIST +=	java/pom.xml
EXTRA_DIST +=	$(noinst_JAVA)
EXTRA_DIST +=	java/src/test/java/Base64DecoderTest.java
EXTRA_DIST +=	java/src/test/java/Base64EncoderTest.java
endif

package: authtest.pp pp
	DESTDIR=`pwd -P`/destdir; rm -rf $$DESTDIR; mkdir -p $$DESTDIR && \
	$(MAKE) install DESTDIR=$$DESTDIR && \
	$(SHELL) $(srcdir)/pp --destdir=$$DESTDIR \
	    $(srcdir)/authtest.pp \
	    bindir=$(bindir) \
	    mandir=$(mandir) \
	    version=$(PACKAGE_VERSION) \
	    name=$(PACKAGE_NAME)

