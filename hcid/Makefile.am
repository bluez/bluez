#
#  $Id$
#

sbin_PROGRAMS = hcid

hcid_SOURCES = main.c security.c hcid.h lib.c lib.h parser.h parser.y lexer.l kword.h kword.c
hcid_LDADD   = @GLIB_LDFLAGS@

INCLUDES = @GLIB_CFLAGS@
YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

confdir   = $(prefix)/etc/bluetooth
conf_FILE = $(confdir)/hcid.conf
pin_FILE  = $(confdir)/pin

#
# Install configuration files
# 
install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(confdir)
	[ -f $(DESTDIR)$(conf_FILE) ] || \
		$(INSTALL_DATA) $(srcdir)/hcid.conf $(DESTDIR)$(conf_FILE)
	[ -f $(DESTDIR)$(pin_FILE) ]  || \
		echo "BlueZ" > $(DESTDIR)$(pin_FILE); \
		chmod 600 $(DESTDIR)$(pin_FILE)
