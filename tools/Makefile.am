
if TOOLS
tools_programs = l2ping hcitool sdptool ciptool
tools_manfiles = l2ping.8 hcitool.1 sdptool.1 ciptool.1
else
tools_programs =
tools_manfiles =
endif

if BCCMD
bccmd_programs = bccmd
bccmd_manfiles = bccmd.8
else
bccmd_programs =
bccmd_manfiles =
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

if USB
usb_programs = dfubabel avctrl
else
usb_programs =
endif

sbin_PROGRAMS = hciattach hciconfig $(bccmd_programs) $(avctrl_programs) $(hid2hci_programs)

bin_PROGRAMS = $(tools_programs) $(dfutool_programs) $(dfubabel_programs)

noinst_PROGRAMS = hcieventmask hcisecfilter ppporc avinfo $(usb_programs)

hcieventmask_LDADD = @BLUEZ_LIBS@

hciattach_SOURCES = hciattach.c hciattach.h \
			hciattach_st.c hciattach_ti.c hciattach_tialt.c
hciattach_LDADD = @BLUEZ_LIBS@

hciconfig_SOURCES = hciconfig.c csr.h csr.c
hciconfig_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

if TOOLS
hcitool_SOURCES = hcitool.c
hcitool_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

l2ping_LDADD = @BLUEZ_LIBS@

sdptool_LDADD = @BLUEZ_LIBS@ $(top_builddir)/common/libhelper.a

ciptool_LDADD = @BLUEZ_LIBS@

avinfo_LDADD = @BLUEZ_LIBS@
endif

ppporc_LDADD = @BLUEZ_LIBS@

if BCCMD
bccmd_SOURCES = bccmd.c csr.h csr.c csr_hci.c \
			csr_bcsp.c csr_h4.c csr_3wire.c ubcsp.h ubcsp.c
bccmd_LDADD = @BLUEZ_LIBS@
if USB
bccmd_SOURCES += csr_usb.c
bccmd_LDADD += @USB_LIBS@
endif
endif

if HID2HCI
hid2hci_LDADD = @USB_LIBS@
endif

if DFUTOOL
dfutool_SOURCES = dfutool.c dfu.h dfu.c
dfutool_LDADD = @USB_LIBS@
endif

if USB
dfubabel_LDADD = @USB_LIBS@
avctrl_LDADD = @USB_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@ @USB_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

if MANPAGES
man_MANS = hciattach.8 hciconfig.8 $(tools_manfiles) \
		$(bccmd_manfiles) $(hid2hci_manfiles) $(dfutool_manfiles)
endif

EXTRA_DIST = hciattach.8 hciconfig.8 l2ping.8 hcitool.1 sdptool.1 ciptool.1 \
		 bccmd.8 avctrl.8 hid2hci.8 dfutool.1 dfubabel.1 example.psr

MAINTAINERCLEANFILES = Makefile.in
