
if GLIB
glib_cflags = @GLIB_CFLAGS@
glib_ldadd  = @GLIB_LIBS@
else
glib_cflags =
glib_ldadd  =
endif

noinst_PROGRAMS = bt.audiod bt.headsetd

bt_audiod_SOURCES = main.c

bt_audiod_LDADD = $(glib_ldadd) @DBUS_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

bt_headsetd_SOURCES = headset.c

bt_headsetd_LDADD = $(glib_ldadd) @DBUS_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(glib_cflags)

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = audio-api.txt

MAINTAINERCLEANFILES = Makefile.in
