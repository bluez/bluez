
if OBEX
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth-transfer.conf
endif

if GLIB
glib_cflags = @GLIB_CFLAGS@
glib_ldadd  = @GLIB_LIBS@
else
glib_cflags =
glib_ldadd  =
endif

noinst_PROGRAMS = transferd

transferd_SOURCES = main.c

LDADD = $(top_builddir)/common/libhelper.a $(glib_ldadd) \
	@DBUS_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @OPENOBEX_CFLAGS@ @DBUS_CFLAGS@ $(glib_cflags)

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = bluetooth-transfer.conf transfer-api.txt

MAINTAINERCLEANFILES = Makefile.in
