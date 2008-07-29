
SUBDIRS = include lib doc \
		sbc gdbus common src plugins \
		network serial input audio \
		tools rfcomm dund pand hidd \
		cups test scripts

aclocaldir = $(datadir)/aclocal

aclocal_DATA = bluez.m4

EXTRA_DIST = $(aclocal_DATA)

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = bluez.pc

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp missing install-sh mkinstalldirs compile ylwrap

