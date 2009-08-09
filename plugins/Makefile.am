
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES =

if NETLINK
plugin_LTLIBRARIES += netlink.la
netlink_la_LIBADD = @NETLINK_LIBS@
endif

noinst_LTLIBRARIES = echo.la

AM_LDFLAGS = -module -avoid-version -no-undefined

AM_CFLAGS = -fvisibility=hidden @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ \
			@GLIB_CFLAGS@ @GDBUS_CFLAGS@ @NETLINK_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

MAINTAINERCLEANFILES = Makefile.in
