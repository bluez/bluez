
plugindir = $(libdir)/bluetooth/plugins

if NETLINK
netlink_plugins = libnetlink.la
else
netlink_plugins =
endif

plugin_LTLIBRARIES = $(netlink_plugins)

noinst_LTLIBRARIES = libecho.la libstorage.la

libecho_la_SOURCES = echo.c

libstorage_la_SOURCES = storage.c

if NETLINK
libnetlink_la_SOURCES = netlink.c

libnetlink_la_LIBADD = @NETLINK_LIBS@
endif

AM_LDFLAGS = -module -avoid-version -no-undefined \
			-export-symbols-regex bluetooth_plugin_desc

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@ @NETLINK_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid

MAINTAINERCLEANFILES = Makefile.in

all-local:
	@$(LN_S) -f $(top_srcdir)/plugins/.libs/libstorage.so
	@$(LN_S) -f $(top_srcdir)/plugins/.libs/libnetlink.so
	@$(LN_S) -f $(top_srcdir)/input/.libs/libinput.so
	@$(LN_S) -f $(top_srcdir)/audio/.libs/libaudio.so
	@$(LN_S) -f $(top_srcdir)/serial/.libs/libserial.so
	@$(LN_S) -f $(top_srcdir)/network/.libs/libnetwork.so

clean-local:
	@rm -f libnetwork.so
	@rm -f libserial.so
	@rm -f libaudio.so
	@rm -f libinput.so
	@rm -f libnetlink.so
	@rm -f libstorage.so
