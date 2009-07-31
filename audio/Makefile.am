
BUILT_SOURCES = telephony.c

if AUDIOPLUGIN
plugindir = $(libdir)/bluetooth/plugins

plugin_LTLIBRARIES = audio.la

audio_la_SOURCES = main.c \
	ipc.h ipc.c unix.h unix.c manager.h manager.c telephony.h \
	device.h device.c headset.h headset.c gateway.h gateway.c \
	avdtp.h avdtp.c a2dp.h a2dp.c sink.h sink.c source.h source.c \
	control.h control.c

nodist_audio_la_SOURCES = $(BUILT_SOURCES)

audio_la_LDFLAGS = -module -avoid-version -no-undefined

LDADD = $(top_builddir)/common/libhelper.a \
		@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

if ALSA
alsadir = $(libdir)/alsa-lib

alsa_LTLIBRARIES = libasound_module_pcm_bluetooth.la libasound_module_ctl_bluetooth.la

libasound_module_pcm_bluetooth_la_SOURCES = pcm_bluetooth.c rtp.h ipc.h ipc.c
libasound_module_pcm_bluetooth_la_LDFLAGS = -module -avoid-version #-export-symbols-regex [_]*snd_pcm_.*
libasound_module_pcm_bluetooth_la_LIBADD = @SBC_LIBS@ @BLUEZ_LIBS@ @ALSA_LIBS@
libasound_module_pcm_bluetooth_la_CFLAGS = @ALSA_CFLAGS@ @BLUEZ_CFLAGS@ @SBC_CFLAGS@

libasound_module_ctl_bluetooth_la_SOURCES = ctl_bluetooth.c rtp.h ipc.h ipc.c
libasound_module_ctl_bluetooth_la_LDFLAGS = -module -avoid-version #-export-symbols-regex [_]*snd_ctl_.*
libasound_module_ctl_bluetooth_la_LIBADD = @BLUEZ_LIBS@ @ALSA_LIBS@
libasound_module_ctl_bluetooth_la_CFLAGS = @ALSA_CFLAGS@ @BLUEZ_CFLAGS@

if CONFIGFILES
alsaconfdir = $(sysconfdir)/alsa

alsaconf_DATA = bluetooth.conf
endif
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
libgstbluetooth_la_LDFLAGS = -module -avoid-version
libgstbluetooth_la_LIBADD = @SBC_LIBS@ @BLUEZ_LIBS@ @GSTREAMER_LIBS@ \
						-lgstaudio-0.10 -lgstrtp-0.10
libgstbluetooth_la_CFLAGS = -fvisibility=hidden -fno-strict-aliasing \
			 @GSTREAMER_CFLAGS@ @BLUEZ_CFLAGS@ @SBC_CFLAGS@
endif
endif

noinst_LTLIBRARIES = libipc.la

libipc_la_SOURCES = ipc.h ipc.c

noinst_PROGRAMS = ipctest

ipctest_LDADD= libipc.la @SBC_LIBS@ @GLIB_LIBS@

AM_CFLAGS = -fvisibility=hidden @SBC_CFLAGS@ \
		@BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

CLEANFILES = $(BUILT_SOURCES)

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/src

EXTRA_DIST = audio.conf telephony-dummy.c telephony-maemo.c telephony-ofono.c \
		bluetooth.conf

MAINTAINERCLEANFILES = Makefile.in

telephony.c: @TELEPHONY_DRIVER@
	@if [ ! -e $@ ] ; then $(LN_S) $< $@ ; fi
