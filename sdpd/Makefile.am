#
#  $Id$
#

sbin_PROGRAMS = sdpd

sdpd_SOURCES = main.c request.c service.c cstate.c servicedb.c sdpd.h

LDFLAGS = @BLUEZ_LIBS@

INCLUDES = @BLUEZ_INCLUDES@

man_MANS = sdpd.8

EXTRA_DIST = $(man_MANS)
