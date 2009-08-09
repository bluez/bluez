
if NETWORKPLUGIN
noinst_LTLIBRARIES = network.la

network_la_SOURCES = main.c manager.h manager.c \
				server.h server.c bridge.h bridge.c \
				connection.h connection.c common.h common.c
endif

AM_LDFLAGS = -module -avoid-version -no-undefined

AM_CFLAGS = -fvisibility=hidden -DBLUETOOTH_PLUGIN_BUILTIN \
		@BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

EXTRA_DIST = network.conf

MAINTAINERCLEANFILES = Makefile.in
