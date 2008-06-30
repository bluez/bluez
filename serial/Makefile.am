
if SERIALPLUGIN
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES = serial.la

serial_la_SOURCES = main.c \
		manager.h manager.c port.h port.c \
		storage.h storage.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

AM_LDFLAGS = -module -avoid-version -no-undefined \
			-export-symbols-regex bluetooth_plugin_desc

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid -I$(top_srcdir)/sdpd

EXTRA_DIST = serial-api.txt test-serial

MAINTAINERCLEANFILES = Makefile.in
