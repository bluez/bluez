
if HCID
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = hcid.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =
endif
endif

noinst_LIBRARIES = libhciserver.a

libhciserver_a_SOURCES = hcid.h security.c storage.c \
	parser.h parser.y lexer.l kword.c kword.h \
	server.h server.c manager.h manager.c \
	adapter.h adapter.c device.h device.c plugin.h plugin.c \
	dbus-common.c dbus-common.h dbus-error.c dbus-error.h \
	dbus-database.c dbus-database.h dbus-security.c dbus-security.h \
	dbus-service.c dbus-service.h dbus-test.c dbus-test.h \
	dbus-hci.h dbus-hci.c dbus-sdp.c dbus-sdp.h \
	telephony.h telephony.c agent.h agent.c

if HCID
sbin_PROGRAMS = hcid

hcid_SOURCES = main.c

hcid_LDADD = libhciserver.a \
	$(top_builddir)/sdpd/libsdpserver.a \
	$(top_builddir)/common/libhelper.a \
	@GMODULE_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@
endif

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins
else
plugindir = $(libdir)/bluetooth/plugins
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@ @GMODULE_CFLAGS@ \
					-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/sdpd

BUILT_SOURCES = parser.h

if HCID
if MANPAGES
man_MANS = hcid.8 hcid.conf.5
endif
endif

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = hcid.8 hcid.conf.5 hcid.conf dbus-api.txt \
	list-devices test-discovery test-adapter test-device simple-agent \
	service-record.dtd \
	service-did.xml service-spp.xml service-opp.xml service-ftp.xml

MAINTAINERCLEANFILES = Makefile.in
