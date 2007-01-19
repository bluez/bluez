
servicedir = $(libdir)/bluetooth

if GLIB
glib_cflags = @GLIB_CFLAGS@
glib_ldadd  = @GLIB_LIBS@
else
glib_cflags =
glib_ldadd  =
endif

service_PROGRAMS = bluetoothd-service-audio

noinst_PROGRAMS = bluetoothd-service-headset

bluetoothd_service_audio_SOURCES = main.c

bluetoothd_service_headset_SOURCES = headset.c

LDADD = $(top_builddir)/common/libhelper.a $(glib_ldadd) \
	@DBUS_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(glib_cflags)

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = headset.service audio-api.txt

MAINTAINERCLEANFILES = Makefile.in
