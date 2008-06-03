
if TEST
sbin_PROGRAMS = hciemu

bin_PROGRAMS = l2test rctest

noinst_PROGRAMS = sdptest scotest attest hstest bdaddr lmptest \
					passkey-agent auth-agent

hciemu_LDADD = $(top_builddir)/common/libhelper.a \
			@GLIB_LIBS@ @BLUEZ_LIBS@

l2test_LDADD = @BLUEZ_LIBS@

rctest_LDADD = @BLUEZ_LIBS@

sdptest_LDADD = @BLUEZ_LIBS@

scotest_LDADD = @BLUEZ_LIBS@

attest_LDADD = @BLUEZ_LIBS@

hstest_LDADD = @BLUEZ_LIBS@

bdaddr_SOURCES = bdaddr.c

bdaddr_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

lmptest_LDADD = @BLUEZ_LIBS@

passkey_agent_LDADD = @DBUS_LIBS@

auth_agent_LDADD = @DBUS_LIBS@

noinst_MANS = bdaddr.8

AM_CFLAGS = @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GLIB_CFLAGS@
endif

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = apitest hsplay hsmicro bdaddr.8 dbusdef.py

MAINTAINERCLEANFILES = Makefile.in
