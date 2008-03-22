
plugindir = $(libdir)/bluetooth/plugins

noinst_LTLIBRARIES = libecho.la

libecho_la_SOURCES = echo.c

AM_LDFLAGS = -module -avoid-version -export-symbols-regex bluetooth_plugin_desc

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid

MAINTAINERCLEANFILES = Makefile.in

all-local:
	@$(LN_S) -f $(top_srcdir)/input/.libs/libinput.so
	@$(LN_S) -f $(top_srcdir)/network/.libs/libnetwork.so

clean-local:
	@rm -f libnetwork.so
	@rm -f libinput.so
