
noinst_PROGRAMS = bluetoothd-service-serial

bluetoothd_service_serial_SOURCES = main.c manager.h manager.c

LDADD = $(top_builddir)/common/libhelper.a \
                @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = serial-api.txt

MAINTAINERCLEANFILES = Makefile.in
