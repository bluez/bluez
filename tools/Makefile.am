#
#  $Id$
#

sbin_PROGRAMS = hciattach hciconfig hid2hci

bin_PROGRAMS = hcitool l2ping sdptool ciptool

noinst_PROGRAMS = ppporc

hciconfig_SOURCES = hciconfig.c csr.h csr.c

hciconfig_LDFLAGS = @BLUEZ_LIBS@

hcitool_LDFLAGS = @BLUEZ_LIBS@

l2ping_LDFLAGS = @BLUEZ_LIBS@

sdptool_LDFLAGS = @BLUEZ_LIBS@

ciptool_LDFLAGS = @BLUEZ_LIBS@

ppporc_LDFLAGS = @BLUEZ_LIBS@

INCLUDES = @BLUEZ_INCLUDES@

man_MANS = hciattach.8 hciconfig.8 hid2hci.8 hcitool.1 l2ping.1 sdptool.1 ciptool.1

EXTRA_DIST = $(man_MANS)
