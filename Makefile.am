#
#  $Id$
#

SUBDIRS := include src

DISTCLEANFILES = conftest.c conftest bluez.pc

EXTRA_DIST = ChangeLog libs.spec

install-data-local:
	$(INSTALL) -D -m 755 $(top_builddir)/bluez.pc $(DESTDIR)$(libdir)/pkgconfig/bluez.pc
