
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth.conf

confdir = $(sysconfdir)/bluetooth

conf_DATA = main.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =
endif

sbin_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c security.c hcid.h sdpd.h \
	sdpd-server.c sdpd-request.c sdpd-service.c sdpd-database.c \
	plugin.h plugin.c storage.h storage.c agent.h agent.c rfkill.c \
	error.h error.c manager.h manager.c adapter.h adapter.c \
	device.h device.c dbus-common.c dbus-common.h dbus-hci.h dbus-hci.c

bluetoothd_LDADD = $(top_builddir)/common/libhelper.a \
			$(top_builddir)/plugins/libbuiltin.la \
			@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@ -ldl

bluetoothd_LDFLAGS = -Wl,--export-dynamic

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins
else
plugindir = $(libdir)/bluetooth/plugins
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@ \
						-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_srcdir)/common -I$(top_builddir)/plugins

if MANPAGES
man_MANS = bluetoothd.8
endif

EXTRA_DIST = bluetooth.conf bluetoothd.8 main.conf

MAINTAINERCLEANFILES = Makefile.in
