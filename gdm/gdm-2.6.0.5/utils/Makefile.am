## Process this file with automake to produce makefile.in
DEFS = @DEFS@ -DGDM_CONFIG_FILE=\"@sysconfdir@/gdm/gdm.conf\" \
	-DGDM_FACTORY_CONFIG_FILE=\"@sysconfdir@/gdm/factory-gdm.conf\" \
	-DGDM_GLADE_DIR=\"@datadir@/gdm\"

INCLUDES = \
	-I.						\
	-I..						\
	-I$(top_srcdir)/daemon				\
	-I$(top_srcdir)/vicious-extensions		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" 	\
	$(UTILS_CFLAGS)

libexec_PROGRAMS = \
	@GDMASKPASS@	\
	@GDMOPEN@	\
	gdmtranslate

# This is not useful anymore
# bin_PROGRAMS = \
#	gdmmktemp

EXTRA_PROGRAMS = gdmaskpass gdmopen

gdmaskpass_SOURCES = \
	gdmaskpass.c

gdmtranslate_SOURCES = \
	gdmtranslate.c

gdmopen_SOURCES = \
	gdmopen.c

#gdmmktemp_SOURCES = \
#	gdmmktemp.c

gdmaskpass_LDADD = \
	$(INTLLIBS)		\
	-lpam			\
	$(EXTRA_GDMASKPASS_LIBS)

gdmopen_LDADD = \
	$(INTLLIBS)

gdmtranslate_LDADD = \
	$(INTLLIBS)

#gdmmktemp_LDADD = \
#	$(INTLLIBS)
