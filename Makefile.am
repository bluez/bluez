#
#  $Id$
#

SUBDIRS = include src

EXTRA_DIST = libs.spec

DISTCLEANFILES = bluez.pc

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh missing install-sh mkinstalldirs

install-data-local: bluez.pc
	$(INSTALL) -D -m 644 $(top_builddir)/$< $(DESTDIR)$(libdir)/pkgconfig/$<

uninstall-local: bluez.pc
	@rm -f $(DESTDIR)$(libdir)/pkgconfig/$<
