
if NETWORKPLUGIN
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES = network.la

network_la_SOURCES = main.c manager.h manager.c \
				server.h server.c bridge.h bridge.c \
				connection.h connection.c common.h common.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

AM_LDFLAGS = -module -avoid-version -no-undefined

AM_CFLAGS = -fvisibility=hidden \
		@BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

EXTRA_DIST = network.conf

MAINTAINERCLEANFILES = Makefile.in
