
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = hcid.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =

dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluez-hcid.conf
endif

sbin_PROGRAMS = hcid

noinst_PROGRAMS = passkey-agent service-agent auth-agent

hcid_SOURCES = main.c security.c device.c storage.c \
		sdp.c sdp.h hcid.h parser.h parser.y \
		lexer.l kword.c kword.h \
		dbus.h dbus.c dbus-common.c dbus-common.h \
		dbus-error.c dbus-error.h dbus-manager.c dbus-manager.h \
		dbus-adapter.c dbus-adapter.h \
		dbus-device.c dbus-device.h dbus-service.c dbus-service.h \
		dbus-security.c dbus-security.h dbus-test.c dbus-test.h \
		dbus-sdp.c dbus-sdp.h dbus-rfcomm.c dbus-rfcomm.h

hcid_LDADD = @DBUS_LIBS@ @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

passkey_agent_SOURCES = passkey-agent.c

passkey_agent_LDADD = @DBUS_LIBS@

service_agent_SOURCES = service-agent.c

service_agent_LDADD = @DBUS_LIBS@

auth_agent_SOURCES = auth-agent.c

auth_agent_LDADD = @DBUS_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

man_MANS = hcid.8 hcid.conf.5

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(man_MANS) hcid.conf bluez-hcid.conf \
	service-record.dtd service-opp.xml dbus-api.txt

MAINTAINERCLEANFILES = Makefile.in
