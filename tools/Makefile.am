#
#  $Id$
#

if HID2HCI
hid2hci_programs = hid2hci
hid2hci_manfiles = hid2hci.8
else
hid2hci_programs =
hid2hci_manfiles =
endif

if DFUTOOL
dfutool_programs = dfutool
dfutool_manfiles = dfutool.1
else
dfutool_programs =
dfutool_manfiles =
endif

sbin_PROGRAMS = hciattach hciconfig $(hid2hci_programs)

bin_PROGRAMS = hcitool l2ping sdptool ciptool $(dfutool_programs)

noinst_PROGRAMS = hcisecfilter ppporc pskey bccmd

hciconfig_SOURCES = hciconfig.c csr.h csr.c
hciconfig_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libtextfile.a

hcitool_SOURCES = hcitool.c oui.h oui.c
hcitool_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libtextfile.a

l2ping_LDADD = @BLUEZ_LIBS@

sdptool_LDADD = @BLUEZ_LIBS@

ciptool_LDADD = @BLUEZ_LIBS@

ppporc_LDADD = @BLUEZ_LIBS@

pskey_SOURCES = pskey.c csr.h csr.c
pskey_LDADD = @BLUEZ_LIBS@

bccmd_SOURCES = bccmd.c csr.h csr.c
bccmd_LDADD = @BLUEZ_LIBS@

if HID2HCI
hid2hci_LDADD = @USB_LIBS@
endif

if DFUTOOL
dfutool_SOURCES = dfutool.c dfu.h dfu.c
dfutool_LDADD = @USB_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @USB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

man_MANS = hciattach.8 hciconfig.8 hcitool.1 l2ping.1 sdptool.1 ciptool.1 \
		$(hid2hci_manfiles) $(dfutool_manfiles)

EXTRA_DIST = $(man_MANS) hid2hci.8 dfutool.1

MAINTAINERCLEANFILES = Makefile.in
