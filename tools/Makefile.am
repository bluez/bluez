#
#  $Id$
#

manfiles = hid2hci.8

if HID2HCI
xbindir = $(sbindir)
xmandir = $(mandir)

xbin_PROGRAMS = hid2hci

hid2hci_LDADD = @USB_LIBS@

xman_MANS = $(manfiles)
endif

sbin_PROGRAMS = hciattach hciconfig

bin_PROGRAMS = hcitool l2ping sdptool ciptool

noinst_PROGRAMS = ppporc hcisecfilter

hciconfig_SOURCES = hciconfig.c csr.h csr.c

hciconfig_LDADD = @BLUEZ_LIBS@

hcitool_LDADD = @BLUEZ_LIBS@

l2ping_LDADD = @BLUEZ_LIBS@

sdptool_LDADD = @BLUEZ_LIBS@

ciptool_LDADD = @BLUEZ_LIBS@

ppporc_LDADD = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @USB_CFLAGS@

man_MANS = hciattach.8 hciconfig.8 hcitool.1 l2ping.1 sdptool.1 ciptool.1

EXTRA_DIST = $(man_MANS) $(manfiles)

MAINTAINERCLEANFILES = Makefile.in
