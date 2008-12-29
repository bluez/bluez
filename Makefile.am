
SUBDIRS = include lib sbc gdbus common src client\
	plugins network serial input audio \
	tools rfcomm compat cups test scripts doc

EXTRA_DIST = bluez.m4

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = bluez.pc

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp missing install-sh mkinstalldirs compile ylwrap

