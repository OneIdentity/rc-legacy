# (c) 2007 Quest Software, Inc. All rights reserved.
bin_PROGRAMS=	ktedit
ktedit_SOURCES= compat.c cmd.c error.c keytab.c ktedit.h main.c splitline.c

man_MANS= 	ktedit.1

EXTRA_DIST=	ktedit.sgml ktedit.1 ktedit.spec ktedit.spec.in \
		LICENCE ChangeLog NEWS

ktedit.1: ktedit.sgml Makefile
	docbook2man -V pkgstring="$(PACKAGE_STRING)" $(srcdir)/ktedit.sgml

ktedit.spec: ktedit.spec.in Makefile
	sed -e 's,!PACKAGE_VERSION!,$(PACKAGE_VERSION),g' \
		< $(srcdir)/ktedit.spec.in >$@

CLEANFILES=	ktedit.1 ktedit.spec manpage.links manpage.refs
