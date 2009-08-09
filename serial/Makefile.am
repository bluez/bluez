
if SERIALPLUGIN
noinst_LTLIBRARIES = serial.la

serial_la_SOURCES = main.c manager.h manager.c \
			port.h port.c proxy.h proxy.c

endif

AM_LDFLAGS = -module -avoid-version -no-undefined

AM_CFLAGS = -fvisibility=hidden -DBLUETOOTH_PLUGIN_BUILTIN \
		@BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

EXTRA_DIST = serial.conf

MAINTAINERCLEANFILES = Makefile.in
