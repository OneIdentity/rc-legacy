prefix=	/opt/quest
tmpdir=	/var/tmp
wrkdir= $(tmpdir)/labtopia.icecream
builddir= $(wrkdir)/build
destdir= $(wrkdir)/root
srcdir=	$(shell pwd)/icecream
version = 0.7.14

package: $(destdir)$(prefix)/bin/icecc icecream.pp pp
	./pp --destdir=$(destdir) icecream.pp \
	    prefix=$(prefix) \
	    version=$(version)
fake-install: $(destdir)$(prefix)/bin/icecc
$(destdir)$(prefix)/bin/icecc: $(builddir)/client/icecc
	rm -rf $(destdir)
	cd $(builddir) && $(MAKE) DESTDIR=$(destdir) install
fake-install-doc: $(builddir)/doc/icecc.1
	cd $(builddir)/doc && for i in $(srcdir)/doc/man-*.docbook; do \
		f=`echo $$i|sed -e 's,^.*/man-,,;s,.docbook$$,,'`;\
		sect=`echo $$f|sed -e 's,.*\.,,'`; \
		mkdir -p $(destdir)$(prefix)/man/man$$sect; \
		cp $$f $(destdir)$(prefix)/man/man$$sect/; \
		chmod 644 $(destdir)$(prefix)/man/man$$sect/$$f; \
	done
build: $(builddir)/client/icecc
$(builddir)/client/icecc: $(builddir)/Makefile
	cd $(builddir) && $(MAKE)
build-doc: $(builddir)/doc/icecc.1
$(builddir)/doc/icecc.1: $(builddir)/Makefile
	mkdir -p $(builddir)/doc
	cd $(builddir)/doc && for i in $(srcdir)/doc/man-*.docbook; do \
	    docbook-to-man $$i \
		> `echo $$i|sed -e 's,^.*/man-,,;s,.docbook$$,,'`;\
	    done
configure: $(builddir)/Makefile
$(builddir)/Makefile: $(srcdir)/configure
	rm -rf $(builddir)
	mkdir -p $(builddir)
	cd $(builddir) && $(srcdir)/configure --prefix=$(prefix)
	test -r $@ && touch $@

#-- this nonsense is needed because icecream is mispackaged
prep: $(OURSRC)
	cd $(srcdir) && $(MAKE) -f Makefile.cvs
	test -r $(srcdir)/configure 
	touch $(srcdir)/configure

clean:
	rm -rf $(wrkdir) 
