AC_PREREQ(2.60)
AC_INIT(bluez, 4.99)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests])
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

AC_CHECK_HEADER([sys/inotify.h],
		[AC_DEFINE([HAVE_SYS_INOTIFY_H], 1,
			[Define to 1 if you have <sys/inotify.h>.])],
			[AC_MSG_ERROR(inotify headers are required and missing)])
AC_PATH_DBUS
AC_PATH_GLIB
AC_PATH_ALSA
AC_PATH_GSTREAMER
AC_PATH_USB
AC_PATH_UDEV
AC_PATH_SNDFILE
AC_PATH_OUI
AC_PATH_READLINE
AC_PATH_CHECK

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

AC_ARG_WITH([systemdunitdir], AC_HELP_STRING([--with-systemdunitdir=DIR],
	[path to systemd system service directory]), [path_systemdunit=${withval}],
		[path_systemdunit="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"])
if (test -n "${path_systemdunit}"); then
	SYSTEMD_UNITDIR="${path_systemdunit}"
	AC_SUBST(SYSTEMD_UNITDIR)
fi
AM_CONDITIONAL(SYSTEMD, test -n "${path_systemdunit}")

AC_OUTPUT(Makefile scripts/bluetooth.rules doc/version.xml
			src/bluetoothd.8 src/bluetooth.service bluez.pc)
