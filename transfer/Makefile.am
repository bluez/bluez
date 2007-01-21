
if OBEX
servicedir = $(libdir)/bluetooth

noinst_PROGRAMS = bluetoothd-service-transfer

bluetoothd_service_transfer_SOURCES = main.c \
		server.h server.c session.h session.c \
		process.h process.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GLIB_LIBS@ @DBUS_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @OPENOBEX_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = transfer.service transfer-api.txt

MAINTAINERCLEANFILES = Makefile.in
