
noinst_PROGRAMS = bluetoothd passkey-agent auth-agent

if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth.conf
endif

bluetoothd_SOURCES = main.c system.h \
	manager.h manager.c database.h database.c \
	adapter.h adapter.c service.h service.c

bluetoothd_LDADD = \
	$(top_builddir)/common/libhelper.a \
	$(top_builddir)/sdpd/libsdpserver.a \
	@GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

passkey_agent_SOURCES = passkey-agent.c

passkey_agent_LDADD = @DBUS_LIBS@

auth_agent_SOURCES = auth-agent.c

auth_agent_LDADD = @DBUS_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/sdpd

EXTRA_DIST = bluetooth.conf test-manager test-database

MAINTAINERCLEANFILES = Makefile.in
