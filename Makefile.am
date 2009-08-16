
SUBDIRS = include lib sbc gdbus common \
		plugins network serial input audio src \
		client tools rfcomm compat cups test scripts doc

AM_MAKEFLAGS = --no-print-directory

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = bluez.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc --disable-udevrules

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs ylwrap
