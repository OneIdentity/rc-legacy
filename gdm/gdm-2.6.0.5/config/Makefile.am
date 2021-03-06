pixmapdir = $(datadir)/pixmaps
confdir = $(sysconfdir)/gdm
crossconfdir = $(sysconfdir)/dm
localedir = $(sysconfdir)/gdm
bisessdir = $(datadir)/gdm/BuiltInSessions
instsessdir = $(datadir)/xsessions
initdir = $(sysconfdir)/gdm/Init
authdir = $(localstatedir)/gdm
logdir = $(localstatedir)/log/gdm
gnomercdir = $(sysconfdir)/gdm
postdir = $(sysconfdir)/gdm/PostSession
predir = $(sysconfdir)/gdm/PreSession
postlogindir = $(sysconfdir)/gdm/PostLogin


noinst_DATA = gdm.conf

EXTRA_DIST = \
	gdm.conf.in \
	gnome.desktop.in \
	default.desktop.in \
	CDE.desktop.in \
	Xsession.in \
	gdm \
	gdm-autologin \
	locale.alias \
	Default.in \
	PostSession.in \
	PreSession.in \
	PostLogin \
	XKeepsCrashing \
	gettextfoo.h \
	extract-shell.sh

gettextfoo.h: XKeepsCrashing Xsession.in
	cat $^ | $(srcdir)/extract-shell.sh > gettextfoo.h

@INTLTOOL_DESKTOP_RULE@

install-data-hook: gdm.conf Xsession gnome.desktop default.desktop CDE.desktop Default PostSession PreSession
	if test '!' -d $(DESTDIR)$(confdir); then \
		$(mkinstalldirs) $(DESTDIR)$(confdir); \
		chmod 755 $(DESTDIR)$(confdir); \
	fi
	if test '!' -d $(DESTDIR)$(crossconfdir); then \
		$(mkinstalldirs) $(DESTDIR)$(crossconfdir); \
		chmod 755 $(DESTDIR)$(crossconfdir); \
	fi
	-if cmp -s $(DESTDIR)$(confdir)/gdm.conf $(DESTDIR)$(confdir)/factory-gdm.conf > /dev/null 2>&1 ; then \
		cp -f $(DESTDIR)$(confdir)/gdm.conf $(DESTDIR)$(confdir)/gdm.conf.orig; \
		$(INSTALL_DATA) gdm.conf $(DESTDIR)$(confdir)/gdm.conf; \
	fi
	if test '!' -f $(DESTDIR)$(confdir)/gdm.conf; then \
		$(INSTALL_DATA) gdm.conf $(DESTDIR)$(confdir)/gdm.conf; \
	fi
	$(INSTALL_DATA) gdm.conf $(DESTDIR)$(confdir)/factory-gdm.conf

	$(INSTALL_SCRIPT) $(srcdir)/XKeepsCrashing $(DESTDIR)$(confdir)/XKeepsCrashing
	$(INSTALL_SCRIPT) Xsession $(DESTDIR)$(confdir)/Xsession

	-if test -f $(DESTDIR)$(localedir)/locale.alias; then \
		cp -f $(DESTDIR)$(localedir)/locale.alias $(DESTDIR)$(localedir)/locale.alias.orig; \
	fi
	$(INSTALL_DATA) $(srcdir)/locale.alias $(DESTDIR)$(localedir)/locale.alias

	if test '!' -d $(DESTDIR)$(bisessdir); then \
		$(mkinstalldirs) $(DESTDIR)$(bisessdir); \
		chmod 755 $(DESTDIR)$(bisessdir); \
	fi

	if test '!' -d $(DESTDIR)$(instsessdir); then \
		$(mkinstalldirs) $(DESTDIR)$(instsessdir); \
		chmod 755 $(DESTDIR)$(instsessdir); \
	fi

	-if test -f $(DESTDIR)$(bisessdir)/Default.desktop; then \
		mv -f $(DESTDIR)$(bisessdir)/Default.desktop $(DESTDIR)$(bisessdir)/Default.desktop.orig; \
	fi
	-if test -f $(DESTDIR)$(bisessdir)/default.desktop; then \
		cp -f $(DESTDIR)$(bisessdir)/default.desktop $(DESTDIR)$(bisessdir)/default.desktop.orig; \
	fi
	$(INSTALL_SCRIPT) default.desktop $(DESTDIR)$(bisessdir)/default.desktop

	-if test -f $(DESTDIR)$(bisessdir)/gnome.desktop; then \
		mv -f $(DESTDIR)$(bisessdir)/gnome.desktop $(DESTDIR)$(bisessdir)/gnome.desktop.orig; \
	fi
	-if test -f $(DESTDIR)$(instsessdir)/gnome.desktop; then \
		cp -f $(DESTDIR)$(instsessdir)/gnome.desktop $(DESTDIR)$(instsessdir)/gnome.desktop.orig; \
	fi
	$(INSTALL_SCRIPT) gnome.desktop $(DESTDIR)$(instsessdir)/gnome.desktop

	-if test -f /usr/dt/bin/Xsession; then \
	   if test -f $(DESTDIR)$(bisessdir)/CDE.desktop; then \
		mv -f $(DESTDIR)$(bisessdir)/CDE.desktop $(DESTDIR)$(bisessdir)/CDE.desktop.orig; \
	   fi; \
	   if test -f $(DESTDIR)$(instsessdir)/CDE.desktop; then \
		cp -f $(DESTDIR)$(instsessdir)/CDE.desktop $(DESTDIR)$(instsessdir)/CDE.desktop.orig; \
	   fi; \
	   $(INSTALL_SCRIPT) CDE.desktop $(DESTDIR)$(instsessdir)/CDE.desktop; \
	fi

	if test '!' -d $(DESTDIR)$(initdir); then \
		$(mkinstalldirs) $(DESTDIR)$(initdir); \
		chmod 755 $(DESTDIR)$(initdir); \
	fi
	-if test -f $(DESTDIR)$(initdir)/Default; then \
		cp -f $(DESTDIR)$(initdir)/Default $(DESTDIR)$(initdir)/Default.orig; \
	fi
	$(INSTALL_SCRIPT) Default $(DESTDIR)$(initdir)/Default

	if test '!' -d $(DESTDIR)$(postlogindir); then \
		$(mkinstalldirs) $(DESTDIR)$(postlogindir); \
		chmod 755 $(DESTDIR)$(postlogindir); \
	fi
	$(INSTALL_SCRIPT) $(srcdir)/PostLogin $(DESTDIR)$(postlogindir)/Default.sample

	if test '!' -d $(DESTDIR)$(predir); then \
		$(mkinstalldirs) $(DESTDIR)$(predir); \
		chmod 755 $(DESTDIR)$(predir); \
	fi
	-if test -f $(DESTDIR)$(predir)/Default; then \
		cp -f $(DESTDIR)$(predir)/Default $(DESTDIR)$(predir)/Default.orig; \
	fi
	$(INSTALL_SCRIPT) PreSession $(DESTDIR)$(predir)/Default

	if test '!' -d $(DESTDIR)$(postdir); then \
		$(mkinstalldirs) $(DESTDIR)$(postdir); \
		chmod 755 $(DESTDIR)$(postdir); \
	fi
	-if test -f $(DESTDIR)$(postdir)/Default; then \
		cp -f $(DESTDIR)$(postdir)/Default $(DESTDIR)$(postdir)/Default.orig; \
	fi
	$(INSTALL_SCRIPT) PostSession $(DESTDIR)$(postdir)/Default

	if test '!' -d $(DESTDIR)$(gnomercdir); then \
		$(mkinstalldirs) $(DESTDIR)$(gnomercdir); \
		chmod 755 $(DESTDIR)$(gnomercdir); \
	fi

	if test '!' -d $(DESTDIR)$(logdir); then \
		$(mkinstalldirs) $(DESTDIR)$(logdir); \
		chown root:root $(DESTDIR)$(logdir); \
		chmod 755 $(DESTDIR)$(logdir); \
	fi

	if test '!' -d $(DESTDIR)$(authdir); then \
		$(mkinstalldirs) $(DESTDIR)$(authdir); \
		chown root:gdm $(DESTDIR)$(authdir); \
		chmod 1770 $(DESTDIR)$(authdir); \
	fi

	system=`uname`; \
	if test -f /usr/include/security/pam_appl.h; then \
	  if test '!' -d $(DESTDIR)$(PAM_PREFIX)/pam.d; then \
		$(mkinstalldirs) $(DESTDIR)$(PAM_PREFIX)/pam.d; \
		chmod 755 $(DESTDIR)$(PAM_PREFIX)/pam.d; \
	   fi; \
	   if test $$system = Linux && test '!' -f $(DESTDIR)$(PAM_PREFIX)/pam.d/gdm; then \
		$(INSTALL_DATA) gdm $(DESTDIR)$(PAM_PREFIX)/pam.d/gdm; \
	   fi; \
	   if test $$system = Linux && test '!' -f $(DESTDIR)$(PAM_PREFIX)/pam.d/gdm-autologin; then \
		$(INSTALL_DATA) gdm-autologin $(DESTDIR)$(PAM_PREFIX)/pam.d/gdm-autologin; \
	   fi; \
	   if test $$system = SunOS; then \
		echo "Please add PAM authentication for gdm and gdm-autologin in $(PAM_PREFIX)/pam.conf!"; \
	   fi; \
	fi
