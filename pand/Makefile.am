
if PAND
bin_PROGRAMS = pand

pand_SOURCES = main.c pand.h bnep.c sdp.c

pand_LDADD = @BLUEZ_LIBS@
endif

AM_CFLAGS = @BLUEZ_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

if PAND
if MANPAGES
man_MANS = pand.1
endif
endif

EXTRA_DIST = pand.1

MAINTAINERCLEANFILES = Makefile.in
