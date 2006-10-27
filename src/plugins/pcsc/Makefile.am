DEFS = @DEFS@ \
        -DPREFIX=\"@prefix@\" \
        -DSYSCONFDIR=\"@sysconfdir@\" \
        -DDATADIR=\"@datadir@\" \
        -DLIBDIR=\"@libdir@\" \
        -DPKCS11_PLUGIN_CONFIG_FILE=\"@sysconfdir@/pcsc.conf\" 

# Copied from generated Makefile for GDM. Need to get this configured
GUI_CFLAGS = -DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -DORBIT2=1 -pthread -I/usr/include/gtk-2.0 -I/usr/lib/gtk-2.0/include -I/usr/X11R6/include -I/usr/include/atk-1.0 -I/usr/include/pango-1.0 -I/usr/include/freetype2 -I/usr/include/freetype2/config -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/libgnomeui-2.0 -I/usr/include/libgnome-2.0 -I/usr/include/libgnomecanvas-2.0 -I/usr/include/libart-2.0 -I/usr/include/gconf/2 -I/usr/include/libbonoboui-2.0 -I/usr/include/orbit-2.0 -I/usr/include/libbonobo-2.0 -I/usr/include/gnome-vfs-2.0 -I/usr/lib/gnome-vfs-2.0/include -I/usr/include/bonobo-activation-2.0 -I/usr/include/libxml2 -I/usr/include/libglade-2.0

INCLUDES = \
	-I$(srcdir)/.					\
	-I$(srcdir)/include				\
	-I$(srcdir)/include/PCSC			\
	-I$(top_srcdir)/src/include			\
	-I$(top_srcdir)/src/libs/vicious-extensions 	\
	$(GUI_CFLAGS)

libpromptpcsc_la_SOURCES = \
	gdm_prompt_pcsc.c

libpromptpcsc_la_LDFLAGS =        			\
	-module -avoid-version 				\
	-ldl -lpthread					\
	-L$(top_builddir)/src/libs/vicious-extensions    \
	-lvicious

pluginsdir=$(libdir)/gdm/plugins

plugins_LTLIBRARIES =            \
	libpromptpcsc.la 


