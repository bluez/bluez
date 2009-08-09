
if INPUTPLUGIN
noinst_LTLIBRARIES = input.la

input_la_SOURCES = main.c manager.h manager.c \
			server.h server.c device.h device.c \
						fakehid.c fakehid.h
endif

AM_LDFLAGS = -module -avoid-version -no-undefined

AM_CFLAGS = -fvisibility=hidden -DBLUETOOTH_PLUGIN_BUILTIN \
		@BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

EXTRA_DIST = input.conf sixpair.c

MAINTAINERCLEANFILES = Makefile.in
