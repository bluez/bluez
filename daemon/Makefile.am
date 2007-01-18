
if GLIB
glib_cflags = @GLIB_CFLAGS@
glib_ldadd  = @GLIB_LIBS@
else
glib_cflags =
glib_ldadd  =
endif

noinst_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c manager.h manager.c

bluetoothd_LDADD = $(glib_ldadd) @DBUS_LIBS@ @BLUEZ_LIBS@ \
			$(top_builddir)/sdpd/libsdpserver.a \
			$(top_builddir)/common/libhelper.a

if EXPAT
bluetoothd_LDADD += -lexpat
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(glib_cflags)

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid -I$(top_srcdir)/sdpd

MAINTAINERCLEANFILES = Makefile.in
