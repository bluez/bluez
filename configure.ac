# SPDX-License-Identifier: GPL-2.0
AC_PREREQ(2.69)
AC_INIT(bluez, 5.79)
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects color-tests silent-rules
					tar-pax no-dist-gzip dist-xz])
AC_CONFIG_HEADERS(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_LANG([C])

AC_C_RESTRICT

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_PIE
AC_PROG_CC_ASAN
AC_PROG_CC_LSAN
AC_PROG_CC_UBSAN
AC_PROG_INSTALL
AC_PROG_MKDIR_P

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

LT_PREREQ(2.2)
LT_INIT([disable-static])

AS_IF(
	[test "$USE_MAINTAINER_MODE" = "yes"],
	[
		AC_CHECK_PROG(enable_coverage, [lcov], [yes], [no])
		AC_CHECK_PROG(enable_dbus_run_session, [dbus-run-session], [yes])
		AC_CHECK_PROG(enable_valgrind, [valgrind], [yes])
		AC_CHECK_HEADERS(valgrind/memcheck.h)
	],
	[]
)
AM_CONDITIONAL(COVERAGE, test "${enable_coverage}" = "yes")
AM_CONDITIONAL(DBUS_RUN_SESSION, test "${enable_dbus_run_session}" = "yes")

MISC_FLAGS

AM_CONDITIONAL(VALGRIND, test "${enable_valgrind}" = "yes" &&
		test "$ASAN_LIB" != "yes" && test "LSAN_LIB" != "yes")

AC_ARG_ENABLE(threads, AS_HELP_STRING([--enable-threads],
		[enable threading support]), [enable_threads=${enableval}])

AC_CHECK_FUNCS(explicit_bzero)

AC_CHECK_FUNCS(getrandom)

AC_CHECK_FUNCS(rawmemchr)

AC_CHECK_FUNC(signalfd, dummy=yes,
			AC_MSG_ERROR(signalfd support is required))

AC_CHECK_LIB(rt, clock_gettime, dummy=yes,
			AC_MSG_ERROR(realtime clock support is required))

AC_CHECK_LIB(pthread, pthread_create, dummy=yes,
			AC_MSG_ERROR(posix thread support is required))

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

AC_CHECK_HEADERS([string.h linux/types.h linux/if_alg.h linux/uinput.h linux/uhid.h sys/random.h])

# basename may be only available in libgen.h with the POSIX behavior,
# not desired here
AC_CHECK_DECLS([basename], [],
				AC_MSG_WARN([GNU basename extension not found]),
				[#define _GNU_SOURCE 1
				 #include <string.h>
				 ])


PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.28)

AS_IF(
	[(test "${enable_threads}" = "yes")],
	[
		AC_DEFINE(NEED_THREADS, 1, [Define if threading support is required])
		PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= 2.16)
		GLIB_CFLAGS="$GLIB_CFLAGS $GTHREAD_CFLAGS"
		GLIB_LIBS="$GLIB_LIBS $GTHREAD_LIBS"
	]
)

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.10)

# D-Bus Confdir
PKG_CHECK_VAR([DBUS_CONFDIR], [dbus-1], [datadir])
AC_MSG_CHECKING([D-Bus configuration directory])
AS_IF(
	[test "x$DBUS_CONFDIR" = "x"],
	[AC_MSG_FAILURE([D-Bus configuration directory is required.])],
	[AC_MSG_RESULT([$DBUS_CONFDIR])]
)

# D-Bus System Bus Dir
PKG_CHECK_VAR([DBUS_SYSTEMBUSDIR], [dbus-1], [system_bus_services_dir])
AC_MSG_CHECKING([D-Bus system bus services dir])
AS_IF(
	[test "x$DBUS_SYSTEMBUSDIR" = "x"],
	[AC_MSG_FAILURE([D-Bus system bus services directory is required.])],
	[AC_MSG_RESULT([$DBUS_SYSTEMBUSDIR])]
)

# D-Bus Session Bus Dir
PKG_CHECK_VAR([DBUS_SESSIONBUSDIR], [dbus-1], [session_bus_services_dir])
AC_MSG_CHECKING([D-Bus session bus services dir])
AS_IF(
	[test "x$DBUS_SESSIONBUSDIR" = "x"],
	[AC_MSG_FAILURE([D-Bus session bus services directory is required.])],
	[AC_MSG_RESULT([$DBUS_SESSIONBUSDIR])]
)

AC_ARG_WITH([zsh-completion-dir], AS_HELP_STRING([--with-zsh-completion-dir=DIR],
				[path to install zsh completions]),
					[path_zshcompletiondir=${withval}],
						[path_zshcompletiondir="yes"])

AC_MSG_CHECKING([zsh site function path])
AS_IF(
	[test "${path_zshcompletiondir}" = "yes"],
	[
		path_zshcompletiondir="$datarootdir/zsh/site-functions"
		AC_MSG_RESULT([${path_zshcompletiondir}])
	])
AC_SUBST(ZSH_COMPLETIONDIR, [${path_zshcompletiondir}])
AM_CONDITIONAL(ZSH_COMPLETIONS, test "${path_zshcompletiondir}" != "no")

AC_ARG_ENABLE(backtrace, AS_HELP_STRING([--enable-backtrace],
		[compile backtrace support]), [enable_backtrace=${enableval}])

AS_IF(
	[test "${enable_backtrace}" = "yes"],
	[
		PKG_CHECK_MODULES(
			[BACKTRACE],
			[libdw],
			[AC_DEFINE([HAVE_BACKTRACE_SUPPORT], [1], [Define to 1 if you have the backtrace support.])],
		)
	],
	[]
)

AC_ARG_ENABLE(library, AS_HELP_STRING([--enable-library],
		[compile and install Bluetooth library]), [enable_library=${enableval}])
AM_CONDITIONAL(LIBRARY, test "${enable_library}" = "yes")

AC_ARG_ENABLE(bluetoothd, AS_HELP_STRING([--enable-bluetoothd],
		[compile and install bluetoothd daemon]), [enable_bluetoothd=${enableval}])
AM_CONDITIONAL(BLUETOOTHD, test "${enable_bluetoothd}" = "yes")

AC_ARG_ENABLE(test, AS_HELP_STRING([--enable-test],
		[enable test/example scripts]), [enable_test=${enableval}])
AM_CONDITIONAL(TEST, test "${enable_test}" = "yes")

AC_ARG_ENABLE(nfc, AS_HELP_STRING([--enable-nfc],
		[enable NFC paring]), [enable_nfc=${enableval}])
AM_CONDITIONAL(NFC, test "${enable_nfc}" = "yes")

AC_ARG_ENABLE(sap, AS_HELP_STRING([--enable-sap],
		[enable SAP profile]), [enable_sap=${enableval}])
AM_CONDITIONAL(SAP, test "${enable_sap}" = "yes")

AC_ARG_ENABLE(a2dp, AS_HELP_STRING([--disable-a2dp],
		[disable A2DP profile]), [enable_a2dp=${enableval}])
AM_CONDITIONAL(A2DP, test "${enable_a2dp}" != "no")
AS_IF(
	[test "${enable_a2dp}" != "no"],
	[
		AC_DEFINE(
			[HAVE_A2DP],
			[1],[Define to 1 if you have A2DP support.])
	]
)

AC_ARG_ENABLE(avrcp, AS_HELP_STRING([--disable-avrcp],
		[disable AVRCP profile]), [enable_avrcp=${enableval}])
AM_CONDITIONAL(AVRCP, test "${enable_avrcp}" != "no")
AS_IF(
	[test "${enable_avrcp}" != "no"],
	[
		AC_DEFINE(
			[HAVE_AVRCP],
			[1], [Define to 1 if you have AVRCP support.])
	]
)

AC_ARG_ENABLE(network, AS_HELP_STRING([--disable-network],
		[disable network profiles]), [enable_network=${enableval}])
AM_CONDITIONAL(NETWORK, test "${enable_network}" != "no")

AC_ARG_ENABLE(hid, AS_HELP_STRING([--disable-hid],
		[disable HID profile]), [enable_hid=${enableval}])
AM_CONDITIONAL(HID, test "${enable_hid}" != "no")

AC_ARG_ENABLE(hog, AS_HELP_STRING([--disable-hog],
		[disable HoG profile]), [enable_hog=${enableval}])
AM_CONDITIONAL(HOG, test "${enable_hog}" != "no")

AC_ARG_ENABLE(health, AS_HELP_STRING([--enable-health],
		[enable health profiles]), [enable_health=${enableval}])
AM_CONDITIONAL(HEALTH, test "${enable_health}" = "yes")

AC_ARG_ENABLE(bap, AS_HELP_STRING([--disable-bap],
		[disable BAP profile]), [enable_bap=${enableval}])
AM_CONDITIONAL(BAP, test "${enable_bap}" != "no")

AC_ARG_ENABLE(bass, AS_HELP_STRING([--disable-bass],
		[disable BASS service]), [enable_bass=${enableval}])
AM_CONDITIONAL(BASS, test "${enable_bass}" != "no")

AC_ARG_ENABLE(mcp, AS_HELP_STRING([--disable-mcp],
        [disable MCP profile]), [enable_mcp=${enableval}])
AM_CONDITIONAL(MCP, test "${enable_mcp}" != "no")

AC_ARG_ENABLE(ccp, AS_HELP_STRING([--disable-ccp],
        [disable CCP profile]), [enable_ccp=${enableval}])
AM_CONDITIONAL(CCP, test "${enable_ccp}" != "no")

AC_ARG_ENABLE(vcp, AS_HELP_STRING([--disable-vcp],
		[disable VCP profile]), [enable_vcp=${enableval}])
AM_CONDITIONAL(VCP, test "${enable_vcp}" != "no")

AC_ARG_ENABLE(micp, AS_HELP_STRING([--disable-micp],
		[disable MICP profile]), [enable_micp=${enableval}])
AM_CONDITIONAL(MICP, test "${enable_micp}" != "no")

AC_ARG_ENABLE(csip, AS_HELP_STRING([--disable-csip],
		[disable CSIP profile]), [enable_csip=${enableval}])
AM_CONDITIONAL(CSIP, test "${enable_csip}" != "no")

AC_ARG_ENABLE(asha, AS_HELP_STRING([--disable-asha],
		[disable ASHA support]), [enable_asha=${enableval}])
AM_CONDITIONAL(ASHA, test "${enable_asha}" != "no")
AS_IF(
	[test "${enable_asha}" != "no"],
	[
		AC_DEFINE(
			[HAVE_ASHA],
			[1], [Define to 1 if you have ASHA support.])
	]
)

AC_ARG_ENABLE(tools, AS_HELP_STRING([--disable-tools],
		[disable Bluetooth tools]), [enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" != "no")

AC_ARG_ENABLE(monitor, AS_HELP_STRING([--disable-monitor],
		[disable Bluetooth monitor]), [enable_monitor=${enableval}])
AM_CONDITIONAL(MONITOR, test "${enable_monitor}" != "no")

AC_ARG_ENABLE(udev, AS_HELP_STRING([--disable-udev],
		[disable udev device support]), [enable_udev=${enableval}])
AS_IF(
	[test "${enable_udev}" != "no"],
	[
		PKG_CHECK_MODULES(
			[UDEV],
			[libudev >= 196],
			[AC_DEFINE([HAVE_UDEV], [1], [Define to 1 if udev is required])],
		)
	]
)

# udev Dir
PKG_CHECK_VAR([UDEV_DIR], [udev], [udevdir])
AC_MSG_CHECKING([udev directory])
AS_IF(
	[test "x$UDEV_DIR" = "x"],
	[AC_MSG_FAILURE([udev directory is required.])],
	[AC_MSG_RESULT([$UDEV_DIR])]
)

AC_ARG_ENABLE(cups, AS_HELP_STRING([--disable-cups],
                [disable CUPS printer support]), [enable_cups=${enableval}])
AM_CONDITIONAL(CUPS, test "${enable_cups}" != "no")

AS_IF(
	[test "${enable_cups}" != "no"],
	[
		# CUPS Server Bin
		PKG_CHECK_VAR([CUPS_SERVERBIN], [cups], [cups_serverbin])
		AC_MSG_CHECKING([cups server binary])
		AS_IF(
			[test "x$CUPS_SERVERBIN" = "x"],
			[AC_SUBST(
				[CUPS_SERVERBIN],
				[${libdir}/cups]
			)],
			[AC_MSG_RESULT([$CUPS_SERVERBIN])]
		)
	]
)

AC_ARG_ENABLE(mesh, AS_HELP_STRING([--enable-mesh],
		[enable Mesh profile support]), [enable_mesh=${enableval}])
AM_CONDITIONAL(MESH, test "${enable_mesh}" = "yes")

AS_IF(
	[test "${enable_mesh}" = "yes"],
	[PKG_CHECK_MODULES([JSONC], [json-c >= 0.13])]
)

AC_ARG_ENABLE(midi, AS_HELP_STRING([--enable-midi],
                [enable MIDI support]), [enable_midi=${enableval}])
AM_CONDITIONAL(MIDI, test "${enable_midi}" = "yes")

AS_IF(
	[test "${enable_midi}" = "yes"],
	[PKG_CHECK_MODULES([ALSA], [alsa])]
)

AC_ARG_ENABLE(obex, AS_HELP_STRING([--disable-obex],
		[disable OBEX profile support]), [enable_obex=${enableval}])
AS_IF(
	[test "${enable_obex}" != "no"],
	[PKG_CHECK_MODULES([ICAL], [libical])]
)

AM_CONDITIONAL(OBEX, test "${enable_obex}" != "no")

AC_ARG_ENABLE(btpclient, AS_HELP_STRING([--enable-btpclient],
		[enable BTP client]), [enable_btpclient=${enableval}])
AM_CONDITIONAL(BTPCLIENT, test "${enable_btpclient}" = "yes")

AC_ARG_ENABLE([external_ell], AS_HELP_STRING([--enable-external-ell],
				[enable external Embedded Linux library]),
					[enable_external_ell=${enableval}])
AS_IF(
	[test "${enable_external_ell}" = "yes"],
	[PKG_CHECK_MODULES([ELL], [ell >= 0.39])]
)

AS_IF(
	[test "${enable_external_ell}" != "yes" &&
	(test "${enable_btpclient}" = "yes" || test "${enable_mesh}" = "yes")],
	[
	AS_IF(
		[test ! -f "${srcdir}/ell/ell.h" && (test ! -f "${srcdir}/../ell/ell/ell.h")],
		[AC_MSG_ERROR([ELL source is required or use --enable-external-ell])]
	)
	]
)

AM_CONDITIONAL(
	[EXTERNAL_ELL],
	[test "${enable_external_ell}" = "yes" ||
				(test "${enable_btpclient}" != "yes" &&
						test "${enable_mesh}" != "yes")])

AM_CONDITIONAL([LIBSHARED_ELL], [test "${enable_btpclient}" = "yes" ||
						test "${enable_mesh}" = "yes"])

AC_ARG_ENABLE(client, AS_HELP_STRING([--disable-client],
		[disable command line client]), [enable_client=${enableval}])
AM_CONDITIONAL([CLIENT], [test "${enable_client}" != "no"])

AS_IF(
	[test "${enable_client}" != "no" || test "${enable_mesh}" = "yes"],
	[PKG_CHECK_MODULES([READLINE], [readline])]
)

AC_ARG_ENABLE(systemd, AS_HELP_STRING([--disable-systemd],
		[disable systemd integration]), [enable_systemd=${enableval}])
AM_CONDITIONAL(SYSTEMD, test "${enable_systemd}" != "no")

# systemd System Unit Dir
AS_IF(
	[test "${enable_systemd}" != "no"],
	[
		PKG_CHECK_VAR([SYSTEMD_SYSTEMUNITDIR], [systemd], [systemdsystemunitdir])
		AC_MSG_CHECKING([systemd system unit dir])
		AS_IF(
			[test "x$SYSTEMD_SYSTEMUNITDIR" = "x"],
			[AC_MSG_FAILURE([systemd system unit directory is required.])],
			[AC_MSG_RESULT([$SYSTEMD_SYSTEMUNITDIR])]
		)
	]
)

# systemd User Unit Dir
AS_IF(
	[test "${enable_systemd}" != "no"],
	[
		PKG_CHECK_VAR([SYSTEMD_USERUNITDIR], [systemd], [systemduserunitdir])
		AC_MSG_CHECKING([systemd user unit dir])
		AS_IF(
			[test "x$SYSTEMD_USERUNITDIR" = "x"],
			[AC_MSG_FAILURE([systemd unit unit directory is required.])],
			[AC_MSG_RESULT([$SYSTEMD_USERUNITDIR])]
		)
	]
)

AC_ARG_ENABLE(datafiles, AS_HELP_STRING([--disable-datafiles],
			[do not install configuration and data files]),
					[enable_datafiles=${enableval}])
AM_CONDITIONAL([DATAFILES], [test "${enable_datafiles}" != "no"])

AC_ARG_ENABLE([manpages], AS_HELP_STRING([--disable-manpages],
			[disable building of manual pages]),
					[enable_manpages=${enableval}])
AS_IF(
	[test "${enable_manpages}" != "no"]
	[
		AC_CHECK_PROGS([RST2MAN], [rst2man rst2man.py], ["no"])
		AS_IF(
			[test "${RST2MAN}" = "no"],
			[AC_MSG_ERROR([rst2man is required])]
		)
	]
)

AM_CONDITIONAL(MANPAGES, test "${enable_manpages}" != "no")
AM_CONDITIONAL(RUN_RST2MAN, test "${enable_manpages}" != "no" &&
				test "${RST2MAN}" != "no")

AC_ARG_ENABLE(testing, AS_HELP_STRING([--enable-testing],
			[enable testing tools]),
					[enable_testing=${enableval}])
AM_CONDITIONAL(TESTING, test "${enable_testing}" = "yes")

AC_ARG_ENABLE(experimental, AS_HELP_STRING([--enable-experimental],
			[enable experimental tools]),
					[enable_experimental=${enableval}])
AM_CONDITIONAL(EXPERIMENTAL, test "${enable_experimental}" = "yes")

AC_ARG_ENABLE(deprecated, AS_HELP_STRING([--enable-deprecated],
			[enable deprecated tools]),
					[enable_deprecated=${enableval}])
AM_CONDITIONAL(DEPRECATED, test "${enable_deprecated}" = "yes")

AC_ARG_ENABLE(external-plugins, AS_HELP_STRING([--enable-external-plugins],
			[enable support for external plugins]),
					[enable_external_plugins=${enableval}])
AM_CONDITIONAL(EXTERNAL_PLUGINS, test "${enable_external_plugins}" = "yes")
AS_IF(
	[test "${enable_external_plugins}" = "yes"],
	[
		AC_DEFINE(
			[EXTERNAL_PLUGINS],
			[1],[Define if external plugin support is required]
		)
	]
)

AC_ARG_ENABLE(sixaxis, AS_HELP_STRING([--enable-sixaxis],
		[enable sixaxis plugin]), [enable_sixaxis=${enableval}])
AM_CONDITIONAL(SIXAXIS, test "${enable_sixaxis}" = "yes" &&
					 test "${enable_udev}" != "no")

AC_ARG_ENABLE(hid2hci, AS_HELP_STRING([--enable-hid2hci],
		[enable hid2hci tool]), [enable_hid2hci=${enableval}])
AM_CONDITIONAL(HID2HCI, test "${enable_hid2hci}" = "yes" &&
					test "${enable_udev}" != "no")

AC_ARG_ENABLE(logger, AS_HELP_STRING([--enable-logger],
		[enable HCI logger service]), [enable_logger=${enableval}])
AM_CONDITIONAL(LOGGER, test "${enable_logger}" = "yes")

AC_ARG_ENABLE(admin, AS_HELP_STRING([--enable-admin],
		[enable admin policy plugin]), [enable_admin=${enableval}])
AM_CONDITIONAL(ADMIN, test "${enable_admin}" = "yes")

AS_IF(
	[test "${prefix}" = "NONE"],
	[
		dnl no prefix and no localstatedir, so default to /var
		AS_IF(
			[test "$localstatedir" = '${prefix}/var'],
			[AC_SUBST([localstatedir], ['/var'])]
		)
		prefix="${ac_default_prefix}"
	]
)

AS_IF(
	[test "${exec_prefix}" = "NONE"],
	[
		# exec_prefix defaults to prefix, although our manual handling of the
		# latter (above) confuses autoconf. Manually set the exec_prefix.
		exec_prefix="${prefix}"
	]
)

# Expand any variables containing relative references like ${prefix} and co.
#
# Otherwise we'll end up with literal references in the final binaries or
# manuals, which is not something we really want.
#
pkgbindir="${bindir}"
AS_IF(
	[test "$bindir" = '${exec_prefix}/bin'],
	[pkgbindir="${exec_prefix}/bin"]
	[pkgbindir="${bindir}"]
)
AC_SUBST(PKGBINDIR, "${pkgbindir}")

AS_IF(
    [test "$libexecdir" = '${exec_prefix}/libexec'],
    [pkglibexecdir="${exec_prefix}/libexec/bluetooth"]
    [pkglibexecdir="${libexecdir}/bluetooth"]
)
AC_SUBST(PKGLIBEXECDIR, "${pkglibexecdir}")

AS_IF(
    [test "$localstatedir" = '${prefix}/var'],
    [storagedir="${prefix}/var/lib/bluetooth"],
    [storagedir="${localstatedir}/lib/bluetooth"]
)

AC_DEFINE_UNQUOTED(STORAGEDIR, "${storagedir}",
			[Directory for the storage files])

AS_IF(
	[test "$sysconfdir" = '${prefix}/etc'],
	[configdir="${prefix}/etc/bluetooth"]
	[configdir="${sysconfdir}/bluetooth"]
)
AC_DEFINE_UNQUOTED([CONFIGDIR], ["${configdir}"],
			[Directory for the configuration files])
AC_SUBST([CONFIGDIR], ["${configdir}"])

AC_DEFINE_UNQUOTED([MESH_STORAGEDIR], ["${storagedir}/mesh"],
			[Directory for the mesh daemon storage files])
AC_SUBST([MESH_STORAGEDIR], ["${storagedir}/mesh"])

AC_ARG_ENABLE(android, AS_HELP_STRING([--enable-android],
			[enable BlueZ for Android]),
					[enable_android=${enableval}])
AM_CONDITIONAL([ANDROID], [test "${enable_android}" = "yes"])

AS_IF(
    [test "${enable_android}" = "yes"],
    [
        PKG_CHECK_MODULES([SBC], [sbc >= 1.2])
        PKG_CHECK_MODULES([SPEEXDSP], [speexdsp >= 1.2])
    ]
)

AC_DEFINE_UNQUOTED(ANDROID_STORAGEDIR, "${storagedir}/android",
			[Directory for the Android daemon storage files])

AC_ARG_WITH([phonebook], AS_HELP_STRING([--with-phonebook=PLUGIN],
			[obexd phonebook plugin (default=dummy)]),
			[plugin_phonebook=${withval}])
AS_IF(
	[test -z "${plugin_phonebook}"],
	[plugin_phonebook=dummy]
)

AS_IF(
	[test "${plugin_phonebook}" = "ebook"],
	[
		PKG_CHECK_MODULES([LIBEBOOK], [libebook-1.2 >= 3.3])
		PKG_CHECK_MODULES([LIBEDATESERVER], [libedataserver-1.2 >= 3.3])
	]
)

AC_SUBST([PLUGIN_PHONEBOOK], [${plugin_phonebook}])

AC_CONFIG_FILES([
	lib/bluez.pc
	Makefile
	mesh/bluetooth-meshd.rst
	mesh/bluetooth-mesh.service
	obexd/src/obex.service
	obexd/src/org.bluez.obex.service
	src/bluetoothd.rst
	src/bluetooth.service
	tools/bluetooth-logger.service
	tools/mpris-proxy.service
])
AC_OUTPUT()
