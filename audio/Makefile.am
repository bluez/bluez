
if HEADSETSERVICE
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = headset.service
endif

servicedir = $(libdir)/bluetooth

service_PROGRAMS = bluetoothd-service-headset

bluetoothd_service_headset_SOURCES = headset.c

bluetoothd_service_headset_LDADD = $(top_builddir)/common/libhelper.a \
				@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

noinst_PROGRAMS = bluetoothd-service-audio

bluetoothd_service_audio_SOURCES = main.c manager.h manager.c

bluetoothd_service_audio_LDADD = $(top_builddir)/common/libhelper.a \
			@SBC_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @SBC_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = headset.service audio-api.txt

MAINTAINERCLEANFILES = Makefile.in
