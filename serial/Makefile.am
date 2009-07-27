
if SERIALPLUGIN
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES = serial.la

serial_la_SOURCES = main.c \
			manager.h manager.c port.h port.c \
			proxy.h proxy.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

AM_LDFLAGS = -module -avoid-version -no-undefined

AM_CFLAGS = -fvisibility=hidden \
		@BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

EXTRA_DIST = serial.conf

MAINTAINERCLEANFILES = Makefile.in
