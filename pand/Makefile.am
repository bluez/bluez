
bin_PROGRAMS = pand

pand_SOURCES = main.c pand.h bnep.c sdp.c
pand_LDADD = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@

man_MANS = pand.1

EXTRA_DIST = $(man_MANS)

MAINTAINERCLEANFILES = Makefile.in
