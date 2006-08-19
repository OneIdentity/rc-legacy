
AUTOMAKE_OPTIONS =	foreign

noinst_LIBRARIES =	libauthtest.a
libauthtest_a_SOURCES =	colours.c

bin_PROGRAMS =		pamtest kuserok gss-server gss-client

kuserok_CFLAGS =	@KRB5_CFLAGS@
kuserok_LDFLAGS =	@KRB5_LIBS@
kuserok_LDADD =		libauthtest.a

pamtest_LDADD =		libauthtest.a

if HAVE_LAM
bin_PROGRAMS +=		lamtest
lamtest_LDADD =		libauthtest.a
endif

gss_server_SOURCES=	gss-server.c base64.c gss-common.c
gss_client_SOURCES=	gss-client.c base64.c gss-common.c
gss_server_CFLAGS =	@GSS_CFLAGS@
gss_server_LDFLAGS =	@GSS_LIBS@
gss_client_CFLAGS =	@GSS_CFLAGS@
gss_client_LDFLAGS =	@GSS_LIBS@
