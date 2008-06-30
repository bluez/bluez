
if AUDIOPLUGIN
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES = audio.la

audio_la_SOURCES = main.c \
	manager.h manager.c headset.h headset.c \
	ipc.h ipc.c unix.h unix.c \
	device.h device.c gateway.h gateway.c \
	sink.c sink.h avdtp.c avdtp.h \
	a2dp.c a2dp.h control.c control.h

audio_la_LDFLAGS = -module -avoid-version -no-undefined \
			-export-symbols-regex bluetooth_plugin_desc

LDADD = $(top_builddir)/common/libhelper.a \
		@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

if ALSA
alsadir = $(libdir)/alsa-lib

alsa_LTLIBRARIES = libasound_module_pcm_bluetooth.la libasound_module_ctl_bluetooth.la

libasound_module_pcm_bluetooth_la_SOURCES = pcm_bluetooth.c rtp.h ipc.h ipc.c
libasound_module_pcm_bluetooth_la_LDFLAGS = -module -avoid-version -export-symbols-regex [_]*snd_pcm_.*
libasound_module_pcm_bluetooth_la_LIBADD = @SBC_LIBS@ @ALSA_LIBS@
libasound_module_pcm_bluetooth_la_CFLAGS = @ALSA_CFLAGS@ @SBC_CFLAGS@

libasound_module_ctl_bluetooth_la_SOURCES = ctl_bluetooth.c rtp.h ipc.h ipc.c
libasound_module_ctl_bluetooth_la_LDFLAGS = -module -avoid-version -export-symbols-regex [_]*snd_ctl_.*
libasound_module_ctl_bluetooth_la_LIBADD = @ALSA_LIBS@
libasound_module_ctl_bluetooth_la_CFLAGS = @ALSA_CFLAGS@
endif

if GSTREAMER
gstreamerdir = $(libdir)/gstreamer-0.10

gstreamer_LTLIBRARIES = libgstbluetooth.la

libgstbluetooth_la_SOURCES = gstbluetooth.c \
				gstsbcenc.h gstsbcenc.c \
				gstsbcdec.h gstsbcdec.c \
				gstsbcparse.h gstsbcparse.c \
				gstavdtpsink.h gstavdtpsink.c \
				gsta2dpsink.h gsta2dpsink.c \
				gstsbcutil.h gstsbcutil.c \
				gstrtpsbcpay.h gstrtpsbcpay.c \
				rtp.h ipc.h ipc.c
libgstbluetooth_la_LDFLAGS = -module -avoid-version -export-symbols-regex gst_plugin_desc
libgstbluetooth_la_LIBADD = @SBC_LIBS@ @GSTREAMER_LIBS@ -lgstaudio-0.10 -lgstrtp-0.10
libgstbluetooth_la_CFLAGS = @GSTREAMER_CFLAGS@ @SBC_CFLAGS@
endif
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid -I$(top_srcdir)/sdpd

EXTRA_DIST = audio.conf audio-api.txt test-audio asound.conf

MAINTAINERCLEANFILES = Makefile.in
