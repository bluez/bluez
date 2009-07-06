
SUBDIRS = include lib sbc gdbus common plugins src client\
			network serial input audio tools \
			rfcomm compat cups test scripts doc

EXTRA_DIST = bluez.m4

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = bluez.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc \
				--disable-udevrules

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs ylwrap

