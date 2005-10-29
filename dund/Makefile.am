
bin_PROGRAMS = dund

dund_SOURCES = main.c dun.c dund.h sdp.c lib.h msdun.c
dund_LDADD = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@

man_MANS = dund.1

EXTRA_DIST = $(man_MANS)

MAINTAINERCLEANFILES = Makefile.in
