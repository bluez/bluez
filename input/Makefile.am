
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth-input.conf
endif

servicedir = $(libdir)/bluetooth

if GLIB
glib_cflags = @GLIB_CFLAGS@
glib_ldadd  = @GLIB_LIBS@
else
glib_cflags =
glib_ldadd  =
endif

service_PROGRAMS = bluetoothd-service-input

bluetoothd_service_input_SOURCES = \
		main.c input-service.h input-service.c

LDADD = $(top_builddir)/common/libhelper.a $(glib_ldadd) \
	@DBUS_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(glib_cflags)

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = bluetooth-input.conf

MAINTAINERCLEANFILES = Makefile.in
