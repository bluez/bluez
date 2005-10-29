
datafiles = bcm203x.usermap

if BCM203X
usbdir = $(sysconfdir)/hotplug/usb

usb_DATA = $(datafiles)

usb_PROGRAMS = bcm203x

bcm203x_LDADD = @USB_LIBS@

AM_CFLAGS = @USB_CFLAGS@
endif

EXTRA_DIST = $(datafiles)

MAINTAINERCLEANFILES = Makefile.in
