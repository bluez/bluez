
plugindir = $(libdir)/bluetooth/plugins

if NETLINK
netlink_plugins = netlink.la
else
netlink_plugins =
endif

plugin_LTLIBRARIES = $(netlink_plugins)

noinst_LTLIBRARIES = echo.la storage.la

echo_la_SOURCES = echo.c

storage_la_SOURCES = storage.c

if NETLINK
netlink_la_SOURCES = netlink.c

netlink_la_LIBADD = @NETLINK_LIBS@
endif

AM_LDFLAGS = -module -avoid-version -no-undefined \
			-export-symbols-regex bluetooth_plugin_desc

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@ @NETLINK_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid

MAINTAINERCLEANFILES = Makefile.in

all-local:
	@$(LN_S) -f $(top_srcdir)/input/.libs/input.so
	@$(LN_S) -f $(top_srcdir)/audio/.libs/audio.so
	@$(LN_S) -f $(top_srcdir)/serial/.libs/serial.so
	@$(LN_S) -f $(top_srcdir)/network/.libs/network.so

clean-local:
	@rm -f network.so
	@rm -f serial.so
	@rm -f audio.so
	@rm -f input.so
