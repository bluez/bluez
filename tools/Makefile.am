
if BCCMD
bccmd_programs = bccmd
bccmd_manfiles = bccmd.8
else
bccmd_programs =
bccmd_manfiles =
endif

if AVCTRL
avctrl_programs = avctrl
avctrl_manfiles = avctrl.8
else
avctrl_programs =
avctrl_manfiles =
endif

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

sbin_PROGRAMS = hciattach hciconfig $(bccmd_programs) $(avctrl_programs) $(hid2hci_programs)

bin_PROGRAMS = hcitool l2ping sdptool ciptool $(dfutool_programs)

noinst_PROGRAMS = hcisecfilter ppporc

hciconfig_SOURCES = hciconfig.c csr.h csr.c
hciconfig_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libtextfile.a

hcitool_SOURCES = hcitool.c oui.h oui.c
hcitool_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libtextfile.a

l2ping_LDADD = @BLUEZ_LIBS@

sdptool_LDADD = @BLUEZ_LIBS@

ciptool_LDADD = @BLUEZ_LIBS@

ppporc_LDADD = @BLUEZ_LIBS@

if BCCMD
bccmd_SOURCES = bccmd.c csr.h csr.c csr_hci.c csr_usb.c csr_bcsp.c csr_h4.c csr_3wire.c ubcsp.h ubcsp.c
bccmd_LDADD = @USB_LIBS@ @BLUEZ_LIBS@
endif

if AVCTRL
avctrl_LDADD = @USB_LIBS@
endif

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
		$(bccmd_manfiles) $(avctrl_manfiles) $(hid2hci_manfiles) $(dfutool_manfiles)

EXTRA_DIST = $(man_MANS) bccmd.8 avctrl.8 hid2hci.8 dfutool.1 example.psr

MAINTAINERCLEANFILES = Makefile.in
