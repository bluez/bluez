#
#  $Id$
#

SUBDIRS := include src

DISTCLEANFILES = conftest.c conftest bluez.pc

EXTRA_DIST = ChangeLog libs.spec

install-data-local: bluez.pc
	$(INSTALL) -D -m 644 $(top_builddir)/bluez.pc $(DESTDIR)$(libdir)/pkgconfig/bluez.pc
