# $Id: Makefile.am,v 1.17 2005/02/03 08:18:22 lukeh Exp $

include $(top_srcdir)/Makefile.am.common

#SUBDIRS	= include lib kuser kdc admin kadmin kpasswd $(kcm_dir) appl doc tools
SUBDIRS	= include lib appl

if KCM
kcm_dir = kcm
endif

## ACLOCAL = @ACLOCAL@ -I cf
ACLOCAL_AMFLAGS = -I cf

EXTRA_DIST = Makefile.am.common #krb5.conf
