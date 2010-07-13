AC_PREREQ(2.60)
AC_INIT(bluez, 4.69)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_CONFIG_HEADER(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

PKG_PROG_PKG_CONFIG

AC_INIT_BLUEZ

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_PIE
AC_PROG_INSTALL
AC_PROG_YACC
AM_PROG_LEX
AM_PROG_MKDIR_P

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_FUNC_PPOLL

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

AC_PATH_DBUS
AC_PATH_GLIB
AC_PATH_ALSA
AC_PATH_GSTREAMER
AC_PATH_USB
AC_PATH_SNDFILE

AC_ARG_BLUEZ

AC_ARG_ENABLE(capng, AC_HELP_STRING([--enable-capng],
		[enable capabilities support]), [enable_capng=${enableval}])
if (test "${enable_capng}" = "yes"); then
	PKG_CHECK_MODULES(CAPNG, libcap-ng, dummy=yes,
				AC_MSG_ERROR(Capabilities library is required))
	AC_SUBST(CAPNG_CFLAGS)
	AC_SUBST(CAPNG_LIBS)
	AC_DEFINE(HAVE_CAPNG, 1, [Define to 1 if you have capabilities library.])
fi

AC_ARG_ENABLE(netlink, AC_HELP_STRING([--enable-netlink],
		[enable netlink support]), [enable_netlink=${enableval}])
if (test "${enable_netlink}" = "yes"); then
	PKG_CHECK_MODULES(NETLINK, libnl-1, dummy=yes,
				AC_MSG_ERROR(Netlink library is required))
	AC_SUBST(NETLINK_CFLAGS)
	AC_SUBST(NETLINK_LIBS)
fi
AM_CONDITIONAL(NETLINK, test "${enable_netlink}" = "yes")

AC_OUTPUT(Makefile scripts/bluetooth.rules doc/version.xml
					src/bluetoothd.8 bluez.pc)
