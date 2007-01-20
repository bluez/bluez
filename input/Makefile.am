
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth-input.conf
endif

servicedir = $(libdir)/bluetooth

noinst_PROGRAMS = bluetoothd-service-input

bluetoothd_service_input_SOURCES = \
		main.c input-service.h input-service.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = bluetooth-input.conf

MAINTAINERCLEANFILES = Makefile.in
