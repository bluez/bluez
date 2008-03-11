
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES = libecho.la

libecho_la_SOURCES = echo.c

AM_LDFLAGS = -module -avoid-version -export-symbols-regex bluetooth_plugin_desc

AM_CFLAGS = @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

INCLUDES = -I$(top_builddir)/common -I$(top_builddir)/hcid

MAINTAINERCLEANFILES = Makefile.in
