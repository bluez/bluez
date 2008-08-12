
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth.conf

confdir = $(sysconfdir)/bluetooth

conf_DATA = main.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =
endif

sbin_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c hcid.h sdpd.h \
	sdpd-server.c sdpd-request.c sdpd-service.c \
	sdpd-database.c security.c storage.c \
	manager.h manager.c error.h error.c \
	adapter.h adapter.c device.h device.c plugin.h plugin.c \
	dbus-common.c dbus-common.h dbus-hci.h dbus-hci.c \
	dbus-database.c dbus-database.h dbus-service.c dbus-service.h \
	telephony.h telephony.c agent.h agent.c driver.h driver.c

bluetoothd_LDADD = $(top_builddir)/common/libhelper.a \
	@GDBUS_LIBS@ @GMODULE_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins
else
plugindir = $(libdir)/bluetooth/plugins
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ \
		@GLIB_CFLAGS@ @GMODULE_CFLAGS@ @GDBUS_CFLAGS@ \
					-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_srcdir)/common

if MANPAGES
man_MANS = bluetoothd.8
endif

EXTRA_DIST = bluetooth.conf bluetoothd.8 main.conf \
	list-devices test-discovery test-manager test-adapter test-device \
	simple-service simple-agent service-record.dtd \
	service-did.xml service-spp.xml service-opp.xml service-ftp.xml

MAINTAINERCLEANFILES = Makefile.in
