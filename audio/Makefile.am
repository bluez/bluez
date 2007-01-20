
servicedir = $(libdir)/bluetooth

noinst_PROGRAMS = bluetoothd-service-audio \
			bluetoothd-service-headset

bluetoothd_service_audio_SOURCES = main.c

bluetoothd_service_headset_SOURCES = headset.c

LDADD = $(top_builddir)/common/libhelper.a \
		@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = headset.service audio-api.txt

MAINTAINERCLEANFILES = Makefile.in
