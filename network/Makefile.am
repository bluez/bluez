
servicedir = $(libdir)/bluetooth

service_PROGRAMS = bluetoothd-service-network

bluetoothd_service_network_SOURCES = main.c

LDADD = $(top_builddir)/common/libhelper.a \
	@DBUS_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

MAINTAINERCLEANFILES = Makefile.in
