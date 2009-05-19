AC_PREREQ(2.60)
AC_INIT()

AM_INIT_AUTOMAKE(bluez, 4.40)
AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AC_INIT_BLUEZ

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL
AC_PROG_YACC
AM_PROG_LEX

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

GTK_DOC_CHECK

AC_FUNC_PPOLL

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

AC_PATH_DBUS
AC_PATH_GLIB
AC_PATH_ALSA
AC_PATH_GSTREAMER
AC_PATH_USB
AC_PATH_NETLINK
AC_PATH_SNDFILE

AC_ARG_BLUEZ

AC_OUTPUT([
	Makefile
	include/Makefile
	lib/Makefile
	gdbus/Makefile
	common/Makefile
	sbc/Makefile
	src/Makefile
	client/Makefile
	plugins/Makefile
	network/Makefile
	serial/Makefile
	input/Makefile
	audio/Makefile
	tools/Makefile
	rfcomm/Makefile
	compat/Makefile
	scripts/Makefile
	cups/Makefile
	test/Makefile
	doc/Makefile
	doc/version.xml
	bluez.pc
])
