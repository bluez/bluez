
if INPUTPLUGIN
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES = input.la

input_la_SOURCES = main.c manager.h manager.c \
		server.h server.c device.h device.c \
		storage.h storage.c fakehid.c fakehid.h

LDADD = $(top_builddir)/common/libhelper.a \
		@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

AM_LDFLAGS = -module -avoid-version -no-undefined \
			-export-symbols-regex bluetooth_plugin_desc

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid

EXTRA_DIST = input.conf input-api.txt test-input

MAINTAINERCLEANFILES = Makefile.in
