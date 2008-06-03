
noinst_PROGRAMS = passkey-agent auth-agent

if CONFIGFILES
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth.conf
endif

passkey_agent_SOURCES = passkey-agent.c

passkey_agent_LDADD = @DBUS_LIBS@

auth_agent_SOURCES = auth-agent.c

auth_agent_LDADD = @DBUS_LIBS@

AM_CFLAGS = @DBUS_CFLAGS@

EXTRA_DIST = bluetooth.conf test-manager test-database

MAINTAINERCLEANFILES = Makefile.in
