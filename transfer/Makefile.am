
if OBEX
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth-transfer.conf
endif

servicedir = $(libdir)/bluetooth

noinst_PROGRAMS = bluetoothd-service-transfer

bluetoothd_service_transfer_SOURCES = \
		main.c session.h session.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GLIB_LIBS@ @DBUS_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @OPENOBEX_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = bluetooth-transfer.conf transfer-api.txt

MAINTAINERCLEANFILES = Makefile.in
