
if SNDFILE
sndfile_programs = sbctester
else
sndfile_programs =
endif

if SBC
noinst_LTLIBRARIES = libsbc.la

libsbc_la_SOURCES = sbc.h sbc.c sbc_math.h sbc_tables.h

libsbc_la_CFLAGS = -finline-functions -funswitch-loops -fgcse-after-reload

noinst_PROGRAMS = sbcinfo sbcdec sbcenc $(sndfile_programs)

sbcdec_LDADD = libsbc.la

sbcenc_LDADD = libsbc.la

if SNDFILE
sbctester_LDADD = @SNDFILE_LIBS@
endif
endif

AM_CFLAGS = @SNDFILE_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
