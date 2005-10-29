
if ALSA
alsadir = $(libdir)/alsa-lib

alsa_LTLIBRARIES = libasound_module_pcm_a2dp.la libasound_module_pcm_headset.la

libasound_module_pcm_a2dp_la_SOURCES = pcm_a2dp.c sbc.h sbc.c
libasound_module_pcm_a2dp_la_LDFLAGS = -module -avoid-version -export-dynamic
libasound_module_pcm_a2dp_la_LIBADD = @ALSA_LIBS@ @BLUEZ_LIBS@

libasound_module_pcm_headset_la_SOURCES = pcm_headset.c
libasound_module_pcm_headset_la_LDFLAGS = -module -avoid-version -export-dynamic
libasound_module_pcm_headset_la_LIBADD = @ALSA_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @ALSA_CFLAGS@ @BLUEZ_CFLAGS@
endif

MAINTAINERCLEANFILES = Makefile.in
