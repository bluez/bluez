
if TEST
sbin_PROGRAMS = hciemu

bin_PROGRAMS = l2test rctest

noinst_PROGRAMS = sdptest scotest attest hstest avtest lmptest \
						bdaddr agent btiotest

hciemu_LDADD = $(top_builddir)/common/libhelper.a \
			@GLIB_LIBS@ @BLUEZ_LIBS@

l2test_LDADD = @BLUEZ_LIBS@

rctest_LDADD = @BLUEZ_LIBS@

sdptest_LDADD = @BLUEZ_LIBS@

scotest_LDADD = @BLUEZ_LIBS@

attest_LDADD = @BLUEZ_LIBS@

hstest_LDADD = @BLUEZ_LIBS@

avtest_LDADD = @BLUEZ_LIBS@

bdaddr_SOURCES = bdaddr.c

bdaddr_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

lmptest_LDADD = @BLUEZ_LIBS@

agent_LDADD = @DBUS_LIBS@

btiotest_LDADD = $(top_builddir)/common/libhelper.a @GLIB_LIBS@ @BLUEZ_LIBS@

noinst_MANS = bdaddr.8

if MANPAGES
man_MANS = rctest.1 hciemu.1
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@
endif

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = apitest hsplay hsmicro bdaddr.8 rctest.1 hciemu.1 dbusdef.py \
		monitor-bluetooth list-devices test-discovery test-manager \
		test-adapter test-device test-service test-serial \
		test-telephony test-network simple-agent simple-service \
		service-record.dtd service-did.xml service-spp.xml \
		service-opp.xml service-ftp.xml

MAINTAINERCLEANFILES = Makefile.in
