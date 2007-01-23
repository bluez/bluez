
if INPUTSERVICE
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = input.service
endif

servicedir = $(libdir)/bluetooth

service_PROGRAMS = bluetoothd-service-input

bluetoothd_service_input_SOURCES = \
		main.c server.h server.c \
		input-service.h input-service.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = input.service input-api.txt

MAINTAINERCLEANFILES = Makefile.in
