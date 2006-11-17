
noinst_PROGRAMS = bluetoothd

bluetoothd_SOURCES = main.c

bluetoothd_LDADD = @DBUS_LIBS@ @BLUEZ_LIBS@ \
			$(top_builddir)/hcid/libhciserver.a \
			$(top_builddir)/sdpd/libsdpserver.a \
			$(top_builddir)/common/libhelper.a

if EXPAT
bluetoothd_LDADD += -lexpat
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/hcid -I$(top_srcdir)/sdpd

MAINTAINERCLEANFILES = Makefile.in
