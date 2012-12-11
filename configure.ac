AC_PREREQ(2.60)
AC_INIT(bluez, 5.x)

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests])
AM_CONFIG_HEADER(config.h)
AC_USE_SYSTEM_EXTENSIONS

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG_C

AC_C_RESTRICT

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_PIE
AC_PROG_INSTALL
AM_PROG_MKDIR_P

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

MISC_FLAGS

AC_ARG_ENABLE(threads, AC_HELP_STRING([--enable-threads],
		[enable threading support]), [enable_threads=${enableval}])

AC_CHECK_FUNC(signalfd, dummy=yes,
			AC_MSG_ERROR(signalfd support is required))

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.28, dummy=yes,
				AC_MSG_ERROR(GLib >= 2.28 is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

if (test "${enable_threads}" = "yes"); then
	AC_DEFINE(NEED_THREADS, 1, [Define if threading support is required])
	PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= 2.16, dummy=yes,
				AC_MSG_ERROR(GThread >= 2.16 is required))
	GLIB_CFLAGS="$GLIB_CFLAGS $GTHREAD_CFLAGS"
	GLIB_LIBS="$GLIB_LIBS $GTHREAD_LIBS"
fi

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.4, dummy=yes,
				AC_MSG_ERROR(D-Bus >= 1.4 is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_ARG_WITH(dbusconfdir, AC_HELP_STRING([--with-dbusconfdir=PATH],
	[path to D-Bus config directory]), [path_dbusconf=${withval}],
		[path_dbusconf="`$PKG_CONFIG --variable=sysconfdir dbus-1`"])
if (test -z "${path_dbusconf}"); then
	DBUS_CONFDIR="${sysconfdir}/dbus-1/system.d"
else
	DBUS_CONFDIR="${path_dbusconf}/dbus-1/system.d"
fi
AC_SUBST(DBUS_CONFDIR)

AC_ARG_WITH(dbusdatadir, AC_HELP_STRING([--with-dbusdatadir=PATH],
	[path to D-Bus data directory]), [path_dbusdata=${withval}],
		[path_dbusdata="`$PKG_CONFIG --variable=datadir dbus-1`"])
if (test -z "${path_dbusdata}"); then
	DBUS_DATADIR="${datadir}/dbus-1/system-services"
else
	DBUS_DATADIR="${path_dbusdata}/dbus-1/system-services"
fi
AC_SUBST(DBUS_DATADIR)

AC_ARG_WITH([systemdunitdir], AC_HELP_STRING([--with-systemdunitdir=DIR],
	[path to systemd service directory]), [path_systemdunit=${withval}],
		[path_systemdunit="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"])
if (test -n "${path_systemdunit}"); then
	SYSTEMD_UNITDIR="${path_systemdunit}"
	AC_SUBST(SYSTEMD_UNITDIR)
fi
AM_CONDITIONAL(SYSTEMD, test -n "${path_systemdunit}")

AC_ARG_ENABLE(library, AC_HELP_STRING([--enable-library],
		[install Bluetooth library]), [enable_library=${enableval}])
AM_CONDITIONAL(LIBRARY, test "${enable_library}" = "yes")

AC_ARG_ENABLE(test, AC_HELP_STRING([--enable-test],
		[enable test/example scripts]), [enable_test=${enableval}])
AM_CONDITIONAL(TEST, test "${enable_test}" = "yes")

AC_ARG_ENABLE(tools, AC_HELP_STRING([--disable-tools],
		[disable Bluetooth tools]), [enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" != "no")

AC_ARG_ENABLE(readline, AC_HELP_STRING([--disable-readline],
		[disable readline support]), [enable_readline=${enableval}])
if (test "${enable_tools}" != "no" && test "${enable_readline}" != "no"  ); then
	AC_CHECK_HEADERS(readline/readline.h, dummy=yes,
		AC_MSG_ERROR(readline header files are required))
fi
AM_CONDITIONAL(READLINE, test "${enable_readline}" != "no")

AC_ARG_ENABLE(usb, AC_HELP_STRING([--disable-usb],
			[disable USB support]), [enable_usb=${enableval}])
if (test "${enable_tools}" != "no" && test "${enable_usb}" != "no"  ); then
	PKG_CHECK_MODULES(USB, libusb, dummy=yes,
			AC_MSG_ERROR(USB library support is required))
	AC_SUBST(USB_CFLAGS)
	AC_SUBST(USB_LIBS)
	AC_CHECK_LIB(usb, usb_get_busses, dummy=yes,
		AC_DEFINE(NEED_USB_GET_BUSSES, 1,
			[Define to 1 if you need the usb_get_busses() function.]
))
	AC_CHECK_LIB(usb, usb_interrupt_read, dummy=yes,
		AC_DEFINE(NEED_USB_INTERRUPT_READ, 1,
			[Define to 1 if you need the usb_interrupt_read() functi
on.]))
	AC_DEFINE(HAVE_LIBUSB, 1, [Define to 1 if you have USB library.])
fi
AM_CONDITIONAL(USB, test "${enable_usb}" != "no")

AC_ARG_ENABLE(udev, AC_HELP_STRING([--disable-udev],
		[disable udev device support]), [enable_udev=${enableval}])
if (test "${enable_tools}" != "no" && test "${enable_udev}" != "no"); then
	PKG_CHECK_MODULES(UDEV, libudev >= 143, dummy=yes,
				AC_MSG_ERROR(libudev >= 143 is required))
	AC_CHECK_LIB(udev, udev_hwdb_new,
		AC_DEFINE(HAVE_UDEV_HWDB_NEW, 1,
			[Define to 1 if you have the udev_hwdb_new() function.]))
	UDEV_DATADIR="`$PKG_CONFIG --variable=udevdir udev`"
	if (test -z "${UDEV_DATADIR}"); then
		UDEV_DATADIR="${sysconfdir}/udev/rules.d"
	else
		UDEV_DATADIR="${UDEV_DATADIR}/rules.d"
	fi
	AC_SUBST(UDEV_DATADIR)
	UDEV_DIR="`$PKG_CONFIG --variable=udevdir udev`"
	if (test -z "${UDEV_DIR}"); then
		UDEV_DIR="${libdir}/udev"
	fi
	AC_SUBST(UDEV_DIR)
fi
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)
AM_CONDITIONAL(UDEV, test "${enable_udev}" != "no")

AM_CONDITIONAL(HID2HCI, test "${enable_tools}" != "no" &&
		test "${enable_udev}" != "no" && test "${enable_usb}" != "no")
AM_CONDITIONAL(CUPS, test "${enable_tools}" != "no")

AC_ARG_ENABLE(obex, AC_HELP_STRING([--disable-obex],
		[disable OBEX profile support]), [enable_obex=${enableval}])
if (test "${enable_obex}" != "no"); then
	PKG_CHECK_MODULES(ICAL, libical, dummy=yes,
					AC_MSG_ERROR(libical is required))
fi
AC_SUBST(ICAL_CFLAGS)
AC_SUBST(ICAL_LIBS)
AM_CONDITIONAL(OBEX, test "${enable_obex}" != "no")

AC_ARG_ENABLE(client, AC_HELP_STRING([--disable-client],
		[disable command line client]), [enable_client=${enableval}])
AM_CONDITIONAL(CLIENT, test "${enable_client}" != "no" &&
					test "${enable_readline}" != "no")

AC_ARG_ENABLE(datafiles, AC_HELP_STRING([--disable-datafiles],
			[do not install configuration and data files]),
					[enable_datafiles=${enableval}])
AM_CONDITIONAL(DATAFILES, test "${enable_datafiles}" != "no")

AC_ARG_ENABLE(experimental, AC_HELP_STRING([--enable-experimental],
			[enable experimental plugins (SAP, NFC, ...)]),
					[enable_experimental=${enableval}])
AM_CONDITIONAL(EXPERIMENTAL, test "${enable_experimental}" = "yes")

if (test "${prefix}" = "NONE"); then
	dnl no prefix and no localstatedir, so default to /var
	if (test "$localstatedir" = '${prefix}/var'); then
		AC_SUBST([localstatedir], ['/var'])
	fi

	prefix="${ac_default_prefix}"
fi

if (test "$localstatedir" = '${prefix}/var'); then
	storagedir="${prefix}/var/lib/bluetooth"
else
	storagedir="${localstatedir}/lib/bluetooth"
fi
AC_DEFINE_UNQUOTED(STORAGEDIR, "${storagedir}",
			[Directory for the storage files])

if (test "$sysconfdir" = '${prefix}/etc'); then
	configdir="${prefix}/etc/bluetooth"
else
	configdir="${sysconfdir}/bluetooth"
fi
AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}",
			[Directory for the configuration files])

AC_OUTPUT(Makefile doc/version.xml src/bluetoothd.8 bluez.pc)
