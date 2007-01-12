
if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth-input.conf
endif

if GLIB
glib_cflags = @GLIB_CFLAGS@
glib_ldadd  = @GLIB_LIBS@
else
glib_cflags =
glib_ldadd  =
endif

noinst_PROGRAMS = bt.inputd

bt_inputd_SOURCES = main.c input-service.h input-service.c

bt_inputd_LDADD = $(glib_ldadd) @DBUS_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(glib_cflags)

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = bluetooth-input.conf

MAINTAINERCLEANFILES = Makefile.in
