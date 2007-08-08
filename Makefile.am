# $Vintela: Makefile.am,v 1.7 2005/05/19 11:00:11 davidl Exp $
bin_PROGRAMS=	ktedit
ktedit_SOURCES= compat.c cmd.c error.c keytab.c ktedit.h main.c splitline.c

man_MANS= 	ktedit.1

EXTRA_DIST=	ktedit.sgml ktedit.1 ktedit.spec ktedit.spec.in \
		LICENCE ChangeLog

ktedit.1: ktedit.sgml
	docbook2man -V pkgstring="$(PACKAGE_STRING)" $(srcdir)/ktedit.sgml

ktedit.spec: ktedit.spec.in
	sed -e 's,!PACKAGE_VERSION!,$(PACKAGE_VERSION),g' \
		< $(srcdir)/ktedit.spec.in >$@
