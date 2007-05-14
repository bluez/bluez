
bin_PROGRAMS = dund

dund_SOURCES = main.c dun.c dund.h sdp.c lib.h msdun.c
dund_LDADD = @BLUEZ_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@

if MANPAGES
man_MANS = dund.1
endif

EXTRA_DIST = dund.1

MAINTAINERCLEANFILES = Makefile.in
