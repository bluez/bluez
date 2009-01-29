
if SNDFILE
sndfile_programs = sbctester
else
sndfile_programs =
endif

if SBC
noinst_LTLIBRARIES = libsbc.la

libsbc_la_SOURCES = sbc.h sbc.c sbc_math.h sbc_tables.h \
	sbc_primitives.h sbc_primitives_mmx.h sbc_primitives_neon.h \
	sbc_primitives.c sbc_primitives_mmx.c sbc_primitives_neon.c

libsbc_la_CFLAGS = -finline-functions -fgcse-after-reload \
				-funswitch-loops -funroll-loops

noinst_PROGRAMS = sbcinfo sbcdec sbcenc $(sndfile_programs)

sbcdec_SOURCES = sbcdec.c formats.h
sbcdec_LDADD = libsbc.la

sbcenc_SOURCES = sbcenc.c formats.h
sbcenc_LDADD = libsbc.la

if SNDFILE
sbctester_LDADD = @SNDFILE_LIBS@
endif
endif

AM_CFLAGS = @SNDFILE_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
