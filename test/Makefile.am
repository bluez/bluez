
if TEST
sbin_PROGRAMS = hciemu

bin_PROGRAMS = l2test rctest

noinst_PROGRAMS = scotest attest hstest bdaddr

hciemu_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

l2test_LDADD = @BLUEZ_LIBS@

rctest_LDADD = @BLUEZ_LIBS@

scotest_LDADD = @BLUEZ_LIBS@

attest_LDADD = @BLUEZ_LIBS@

hstest_LDADD = @BLUEZ_LIBS@

bdaddr_SOURCES = bdaddr.c

bdaddr_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

noinst_MANS = bdaddr.8

AM_CFLAGS = @BLUEZ_CFLAGS@
endif

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST = hsplay hsmicro bdaddr.8

MAINTAINERCLEANFILES = Makefile.in
