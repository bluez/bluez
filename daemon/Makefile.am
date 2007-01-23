
if ECHOSERVICE
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = echo.service
endif

servicedir = $(libdir)/bluetooth

service_PROGRAMS = bluetoothd-service-echo

bluetoothd_service_echo_SOURCES = echo.c

bluetoothd_service_echo_LDADD = \
	$(top_builddir)/common/libhelper.a \
	@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

noinst_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c system.h \
	manager.h manager.c database.h database.c \
	adapter.h adapter.c service.h service.c

bluetoothd_LDADD = \
	$(top_builddir)/common/libhelper.a \
	$(top_builddir)/sdpd/libsdpserver.a \
	@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

if EXPAT
bluetoothd_LDADD += -lexpat
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/sdpd

EXTRA_DIST = echo.service

MAINTAINERCLEANFILES = Makefile.in
