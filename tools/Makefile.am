#
#  $Id$
#

sbin_PROGRAMS = hciattach hciconfig

bin_PROGRAMS = hcitool l2ping sdptool ciptool

hciconfig_SOURCES = hciconfig.c csr.h csr.c

LDFLAGS = @BLUEZ_LIBS@

INCLUDES = @BLUEZ_INCLUDES@

man_MANS = hciattach.8 hciconfig.8 hcitool.1 l2ping.1 sdptool.1 ciptool.1

noinst_PROGRAMS	= ppporc

EXTRA_DIST = $(man_MANS)
