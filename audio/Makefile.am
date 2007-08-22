
if AUDIOSERVICE
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = audio.service
endif

servicedir = $(libdir)/bluetooth

service_PROGRAMS = bluetoothd-service-audio

bluetoothd_service_audio_SOURCES = main.c \
	manager.h manager.c headset.h headset.c ipc.h unix.h unix.c \
	error.h error.c device.h device.c gateway.h gateway.c \
	sink.c sink.h avdtp.c avdtp.h a2dp.c a2dp.h

bluetoothd_service_audio_LDADD = $(top_builddir)/common/libhelper.a \
				@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

if ALSA
alsadir = $(libdir)/alsa-lib

alsa_LTLIBRARIES = libasound_module_pcm_bluetooth.la libasound_module_ctl_bluetooth.la

libasound_module_pcm_bluetooth_la_SOURCES = pcm_bluetooth.c ipc.h
libasound_module_pcm_bluetooth_la_LDFLAGS = -module -avoid-version -export-dynamic
libasound_module_pcm_bluetooth_la_LIBADD = @SBC_LIBS@ @ALSA_LIBS@
libasound_module_pcm_bluetooth_la_CFLAGS = @ALSA_CFLAGS@ @SBC_CFLAGS@

libasound_module_ctl_bluetooth_la_SOURCES = ctl_bluetooth.c ipc.h
libasound_module_ctl_bluetooth_la_LDFLAGS = -module -avoid-version -export-dynamic
libasound_module_ctl_bluetooth_la_LIBADD = @ALSA_LIBS@ 
libasound_module_ctl_bluetooth_la_CFLAGS = @ALSA_CFLAGS@
endif

if GSTREAMER
gstreamerdir = $(libdir)/gstreamer-0.10

gstreamer_LTLIBRARIES = libgstbluetooth.la

libgstbluetooth_la_SOURCES = gstbluetooth.c ipc.h
libgstbluetooth_la_LDFLAGS = -module -avoid-version -export-dynamic -no-undefined
libgstbluetooth_la_LIBADD = @SBC_LIBS@ @GSTREAMER_LIBS@
libgstbluetooth_la_CFLAGS = @GSTREAMER_CFLAGS@ @SBC_CFLAGS@
endif

endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = audio.service audio.conf audio-api.txt test-audio asound.conf

MAINTAINERCLEANFILES = Makefile.in
