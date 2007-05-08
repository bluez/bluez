
if CONFIGFILES
confdir = $(sysconfdir)/bluetooth

conf_DATA = hcid.conf

statedir = $(localstatedir)/lib/bluetooth

state_DATA =
endif

noinst_LIBRARIES = libhciserver.a

libhciserver_a_SOURCES = hcid.h security.c device.c \
	storage.c parser.h parser.y lexer.l kword.c kword.h \
	dbus-hci.h dbus-hci.c dbus-common.c dbus-common.h \
	dbus-error.c dbus-error.h dbus-manager.c dbus-manager.h \
	dbus-database.c dbus-database.h dbus-security.c dbus-security.h \
	dbus-adapter.c dbus-adapter.h dbus-device.c dbus-device.h \
	dbus-service.c dbus-service.h dbus-sdp.c dbus-sdp.h \
	dbus-test.c dbus-test.h

if HCID
sbin_PROGRAMS = hcid

hcid_SOURCES = main.c

hcid_LDADD = libhciserver.a \
	$(top_builddir)/sdpd/libsdpserver.a \
	$(top_builddir)/common/libhelper.a \
	@GLIB_LIBS@ @DBUS_LIBS@ @BLUEZ_LIBS@

if EXPAT
hcid_LDADD += -lexpat
endif
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common -I$(top_srcdir)/sdpd

BUILT_SOURCES = parser.h

if HCID
man_MANS = hcid.8 hcid.conf.5
endif

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = hcid.8 hcid.conf.5 hcid.conf dbus-api.txt \
	service-record.dtd service-did.xml service-spp.xml \
	service-opp.xml service-ftp.xml

MAINTAINERCLEANFILES = Makefile.in
