
if NETWORKSERVICE
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = network.service
endif

servicedir = $(libdir)/bluetooth

service_PROGRAMS = bluetoothd-service-network

bluetoothd_service_network_SOURCES = main.c \
	manager.h manager.c error.h error.c \
	server.h server.c bridge.h bridge.c \
	connection.h connection.c common.h common.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GLIB_LIBS@ @HAL_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @HAL_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = network.service network.conf network-api.txt test-network

MAINTAINERCLEANFILES = Makefile.in
