# (c) 2007 Quest Software, Inc. All rights reserved.
bin_PROGRAMS=	ktedit
ktedit_SOURCES= compat.c cmd.c error.c keytab.c ktedit.h main.c splitline.c

man_MANS= 	ktedit.1

EXTRA_DIST=	ktedit.1 ktedit.pp pp \
		LICENCE ChangeLog NEWS

package:	pp ktedit.pp
	DESTDIR=`pwd`/destdir; \
	rm -rf "$$DESTDIR"; mkdir -p "$$DESTDIR"; \
	$(MAKE) install DESTDIR=$$DESTDIR; \
	$(srcdir)/pp \
	    --destdir="$$DESTDIR" \
	    --install-script=inst.sh \
	    $(srcdir)/ktedit.pp \
	    bindir="$(bindir)" \
	    man1dir="$(man1dir)" \
	    version="$(PACKAGE_VERSION)" \
	    name="$(PACKAGE_NAME)" 
