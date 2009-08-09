
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth.conf

confdir = $(sysconfdir)/bluetooth

conf_DATA = main.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =
endif

builtin_modules =
builtin_sources =
builtin_cflags =
builtin_libadd =

if SERVICEPLUGIN
builtin_modules += service
builtin_sources += $(top_srcdir)/plugins/service.c
endif

builtin_modules += hciops
builtin_sources += $(top_srcdir)/plugins/hciops.c

builtin_modules += hal
builtin_sources += $(top_srcdir)/plugins/hal.c

builtin_modules += storage
builtin_sources += $(top_srcdir)/plugins/storage.c

if NETWORKPLUGIN
builtin_modules += network
builtin_libadd += $(top_builddir)/network/network.la
endif

if SERIALPLUGIN
builtin_modules += serial
builtin_libadd += $(top_builddir)/serial/serial.la
endif

if INPUTPLUGIN
builtin_modules += input
builtin_libadd += $(top_builddir)/input/input.la
endif

if AUDIOPLUGIN
builtin_modules += audio
builtin_libadd += $(top_builddir)/audio/audio.la
endif

noinst_LTLIBRARIES = libbuiltin.la

libbuiltin_la_SOURCES = $(builtin_sources)
libbuiltin_la_LDFLAGS =
libbuiltin_la_CFLAGS = $(AM_CFLAGS) \
			$(builtin_cflags) -DBLUETOOTH_PLUGIN_BUILTIN

BUILT_SOURCES = builtin.h

nodist_libbuiltin_la_SOURCES = $(BUILT_SOURCES)

CLEANFILES = $(BUILT_SOURCES)

sbin_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c security.c hcid.h sdpd.h \
	sdpd-server.c sdpd-request.c sdpd-service.c sdpd-database.c \
	plugin.h plugin.c storage.h storage.c agent.h agent.c rfkill.c \
	error.h error.c manager.h manager.c adapter.h adapter.c \
	device.h device.c dbus-common.c dbus-common.h dbus-hci.h dbus-hci.c

bluetoothd_LDADD = $(top_builddir)/common/libhelper.a \
			libbuiltin.la $(builtin_libadd) \
			@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@ -ldl

bluetoothd_LDFLAGS = -Wl,--export-dynamic

bluetoothd_DEPENDENCIES = libbuiltin.la

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins/.libs
else
plugindir = $(libdir)/bluetooth/plugins
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@ \
						-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_srcdir)/common

if MANPAGES
man_MANS = bluetoothd.8
endif

EXTRA_DIST = bluetooth.conf bluetoothd.8 main.conf

MAINTAINERCLEANFILES = Makefile.in

builtin.h:
	echo "" > $@
	list='$(builtin_modules)'; for i in $$list; \
	  do echo "extern struct bluetooth_plugin_desc __bluetooth_builtin_$$i;" >> $@; done
	echo "" >> $@
	echo "static struct bluetooth_plugin_desc *__bluetooth_builtin[] = {" >> $@
	list='$(builtin_modules)'; for i in $$list; \
	  do echo "&__bluetooth_builtin_$$i," >> $@; done
	echo "NULL };" >> $@
