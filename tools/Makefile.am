#
#  $Id$
#

mandir = $(prefix)/usr/share/man

sbin_PROGRAMS = hciattach hciconfig
bin_PROGRAMS  = hcitool l2ping

man_MANS      = hciattach.8 l2ping.8

CLEANFILES    = l2test.o l2test


all-local: l2test

l2test: l2test.o
	$(LINK) l2test.o $(LDFLAGS) $(LIBS)
