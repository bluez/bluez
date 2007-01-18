
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = hcid.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =

dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = bluetooth.conf
endif

if GLIB
glib_cflags = @GLIB_CFLAGS@
glib_ldadd  = @GLIB_LIBS@
else
glib_cflags =
glib_ldadd  =
endif

noinst_LIBRARIES = libhciserver.a

libhciserver_a_SOURCES = hcid.h security.c device.c \
	storage.c parser.h parser.y lexer.l kword.c kword.h \
	dbus-hci.h dbus-hci.c dbus-common.c dbus-common.h \
	dbus-error.c dbus-error.h dbus-manager.c dbus-manager.h \
	dbus-database.c dbus-database.h dbus-security.c dbus-security.h \
	dbus-adapter.c dbus-adapter.h dbus-device.c dbus-device.h \
	dbus-service.c dbus-service.h dbus-sdp.c dbus-sdp.h \
	dbus-rfcomm.c dbus-rfcomm.h dbus-test.c dbus-test.h

if HCID
sbin_PROGRAMS = hcid

hcid_SOURCES = main.c

hcid_LDADD = $(glib_ldadd) @DBUS_LIBS@ @BLUEZ_LIBS@ \
		libhciserver.a \
		$(top_builddir)/sdpd/libsdpserver.a \
		$(top_builddir)/common/libhelper.a

if EXPAT
hcid_LDADD += -lexpat
endif
endif

noinst_PROGRAMS = passkey-agent service-agent auth-agent

passkey_agent_SOURCES = passkey-agent.c

passkey_agent_LDADD = @DBUS_LIBS@

service_agent_SOURCES = service-agent.c

service_agent_LDADD = @DBUS_LIBS@

auth_agent_SOURCES = auth-agent.c

auth_agent_LDADD = @DBUS_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ $(glib_cflags)

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/sdpd

BUILT_SOURCES = parser.h

man_MANS = hcid.8 hcid.conf.5

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(man_MANS) hcid.conf bluetooth.conf dbus-api.txt \
	service-record.dtd service-did.xml service-spp.xml \
	service-opp.xml service-ftp.xml

MAINTAINERCLEANFILES = Makefile.in
