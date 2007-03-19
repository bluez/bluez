
if NETWORKSERVICE
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = network.service
endif

servicedir = $(libdir)/bluetooth

noinst_PROGRAMS = bluetoothd-service-network

bluetoothd_service_network_SOURCES = main.c \
	manager.h manager.c error.h error.c \
	server.h server.c bridge.h bridge.c \
	hal.h hal.c connection.h connection.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GLIB_LIBS@ @HAL_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @HAL_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = network.service network-api.txt

MAINTAINERCLEANFILES = Makefile.in
