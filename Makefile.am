
AUTOMAKE_OPTIONS =	foreign

noinst_LIBRARIES =	libauthtest.a
libauthtest_a_SOURCES =	colours.c privsep.c strtouid.c authtest.h

bin_PROGRAMS =		kuserok gss-server gss-client
man_MANS = 		kuserok.1 gss-server.1 gss-client.1

kuserok_CFLAGS =	@KRB5_CFLAGS@
kuserok_LDFLAGS =	@KRB5_LIBS@
kuserok_LDADD =		libauthtest.a

if HAVE_PAM
bin_PROGRAMS +=		pamtest
pamtest_LDADD =		libauthtest.a
man_MANS +=		pamtest.1
endif

if HAVE_LAM
bin_PROGRAMS +=		lamtest
lamtest_LDADD =		libauthtest.a
man_MANS +=		lamtest.1
endif

gss_server_SOURCES=	gss-server.c base64.c gss-common.c base64.h gss-common.h
gss_client_SOURCES=	gss-client.c base64.c gss-common.c base64.h gss-common.h
gss_server_CFLAGS =	@GSS_CFLAGS@
gss_server_LDFLAGS =	@GSS_LIBS@
gss_server_LDADD =	libauthtest.a
gss_client_CFLAGS =	@GSS_CFLAGS@
gss_client_LDFLAGS =	@GSS_LIBS@
gss_client_LDADD =	libauthtest.a

EXTRA_DIST =		LICENCE pp authtest.pp
EXTRA_DIST +=		kuserok.1 gss-server.1 gss-client.1 pamtest.1 lamtest.1

package: authtest.pp pp
	DESTDIR=`pwd -P`/destdir; rm -rf $$DESTDIR; mkdir -p $$DESTDIR && \
	$(MAKE) install DESTDIR=$$DESTDIR && \
	$(SHELL) $(srcdir)/pp --destdir=$$DESTDIR \
	    $(srcdir)/authtest.pp \
	    bindir=$(bindir) \
	    mandir=$(mandir) \
	    version=$(PACKAGE_VERSION) \
	    name=$(PACKAGE_NAME)

