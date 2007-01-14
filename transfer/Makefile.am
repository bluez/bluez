
if OBEX
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth-transfer.conf
endif

noinst_PROGRAMS = transferd

transferd_SOURCES = main.c

LDADD = $(top_builddir)/common/libhelper.a \
	@DBUS_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @OPENOBEX_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = bluetooth-transfer.conf transfer-api.txt

MAINTAINERCLEANFILES = Makefile.in
