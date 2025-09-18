# SPDX-License-Identifier: GPL-2.0
AC_PREREQ(2.60)
AC_INIT(bluez, 5.84)

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

if (test "$USE_MAINTAINER_MODE" = "yes"); then
	AC_CHECK_PROG(enable_coverage, [lcov], [yes], [no])
	AC_CHECK_PROG(enable_dbus_run_session, [dbus-run-session], [yes])
	AC_CHECK_PROG(enable_valgrind, [valgrind], [yes])
	AC_CHECK_HEADERS(valgrind/memcheck.h)
fi
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

AC_CHECK_HEADERS(stdarg.h stdio.h string.h linux/types.h linux/if_alg.h \
			linux/uinput.h linux/uhid.h sys/random.h)

# basename may be only available in libgen.h with the POSIX behavior,
# not desired here
AC_CHECK_DECLS([basename], [],
				AC_MSG_WARN([GNU basename extension not found]),
				[#define _GNU_SOURCE 1
				 #include <string.h>
				 ])


PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.36)
PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.10)

AC_ARG_WITH([dbusconfdir], AS_HELP_STRING([--with-dbusconfdir=DIR],
				[path to D-Bus configuration directory]),
					[path_dbusconfdir=${withval}])
if (test -z "${path_dbusconfdir}"); then
	AC_MSG_CHECKING([D-Bus configuration directory])
	path_dbusconfdir="`$PKG_CONFIG --variable=datadir dbus-1`"
	if (test -z "${path_dbusconfdir}"); then
		AC_MSG_ERROR([D-Bus configuration directory is required])
	fi
	AC_MSG_RESULT([${path_dbusconfdir}])
fi
AC_SUBST(DBUS_CONFDIR, [${path_dbusconfdir}])

AC_ARG_WITH([dbussystembusdir], AS_HELP_STRING([--with-dbussystembusdir=DIR],
				[path to D-Bus system bus services directory]),
					[path_dbussystembusdir=${withval}])
if (test -z "${path_dbussystembusdir}"); then
	AC_MSG_CHECKING([D-Bus system bus services dir])
	path_dbussystembusdir="`$PKG_CONFIG --variable=system_bus_services_dir dbus-1`"
	if (test -z "${path_dbussystembusdir}"); then
		AC_MSG_ERROR([D-Bus system bus services directory is required])
	fi
	AC_MSG_RESULT([${path_dbussystembusdir}])
fi
AC_SUBST(DBUS_SYSTEMBUSDIR, [${path_dbussystembusdir}])

AC_ARG_WITH([dbussessionbusdir], AS_HELP_STRING([--with-dbussessionbusdir=DIR],
				[path to D-Bus session bus services directory]),
					[path_dbussessionbusdir=${withval}])
if (test -z "${path_dbussessionbusdir}"); then
	AC_MSG_CHECKING([D-Bus session bus services dir])
	path_dbussessionbusdir="`$PKG_CONFIG --variable=session_bus_services_dir dbus-1`"
	if (test -z "${path_dbussessionbusdir}"); then
		AC_MSG_ERROR([D-Bus session bus services directory is required])
	fi
	AC_MSG_RESULT([${path_dbussessionbusdir}])
fi
AC_SUBST(DBUS_SESSIONBUSDIR, [${path_dbussessionbusdir}])

AC_ARG_WITH([zsh-completion-dir], AS_HELP_STRING([--with-zsh-completion-dir=DIR],
				[path to install zsh completions]),
					[path_zshcompletiondir=${withval}],
						[path_zshcompletiondir="yes"])

if (test "${path_zshcompletiondir}" = "yes"); then
	path_zshcompletiondir="$datarootdir/zsh/site-functions"
	AC_MSG_RESULT([${path_zshcompletiondir}])
fi
AC_SUBST(ZSH_COMPLETIONDIR, [${path_zshcompletiondir}])
AM_CONDITIONAL(ZSH_COMPLETIONS, test "${path_zshcompletiondir}" != "no")

AC_ARG_ENABLE(backtrace, AS_HELP_STRING([--enable-backtrace],
		[compile backtrace support]), [enable_backtrace=${enableval}])

if (test "${enable_backtrace}" = "yes"); then
	AC_CHECK_HEADER(elfutils/libdwfl.h, dummy=yes,
			AC_MSG_ERROR(elfutils support is required))
	AC_DEFINE(HAVE_BACKTRACE_SUPPORT, 1,
			[Define to 1 if you have the backtrace support.])
	BACKTRACE_CFLAGS=""
	BACKTRACE_LIBS="-ldw"
	AC_SUBST(BACKTRACE_CFLAGS)
	AC_SUBST(BACKTRACE_LIBS)
fi

AC_ARG_ENABLE(library, AS_HELP_STRING([--enable-library],
		[install Bluetooth library]), [enable_library=${enableval}])
AM_CONDITIONAL(LIBRARY, test "${enable_library}" = "yes")

AC_ARG_ENABLE(test, AS_HELP_STRING([--enable-test],
		[enable test/example scripts]), [enable_test=${enableval}])
AM_CONDITIONAL(TEST, test "${enable_test}" = "yes")

AC_ARG_ENABLE(nfc, AS_HELP_STRING([--enable-nfc],
		[enable NFC pairing]), [enable_nfc=${enableval}])
AM_CONDITIONAL(NFC, test "${enable_nfc}" = "yes")

AC_ARG_ENABLE(sap, AS_HELP_STRING([--enable-sap],
		[enable SAP profile]), [enable_sap=${enableval}])
AM_CONDITIONAL(SAP, test "${enable_sap}" = "yes")

AC_ARG_ENABLE(a2dp, AS_HELP_STRING([--disable-a2dp],
		[disable A2DP profile]), [enable_a2dp=${enableval}])
AM_CONDITIONAL(A2DP, test "${enable_a2dp}" != "no")
if test "${enable_a2dp}" != "no"; then
	AC_DEFINE(HAVE_A2DP, 1, [Define to 1 if you have A2DP support.])
fi

AC_ARG_ENABLE(avrcp, AS_HELP_STRING([--disable-avrcp],
		[disable AVRCP profile]), [enable_avrcp=${enableval}])
AM_CONDITIONAL(AVRCP, test "${enable_avrcp}" != "no")
if test "${enable_avrcp}" != "no"; then
	AC_DEFINE(HAVE_AVRCP, 1, [Define to 1 if you have AVRCP support.])
fi

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
if test "${enable_vcp}" != "no"; then
	AC_DEFINE(HAVE_VCP, 1, [Define to 1 if you have VCP support.])
fi

AC_ARG_ENABLE(micp, AS_HELP_STRING([--disable-micp],
		[disable MICP profile]), [enable_micp=${enableval}])
AM_CONDITIONAL(MICP, test "${enable_micp}" != "no")

AC_ARG_ENABLE(csip, AS_HELP_STRING([--disable-csip],
		[disable CSIP profile]), [enable_csip=${enableval}])
AM_CONDITIONAL(CSIP, test "${enable_csip}" != "no")

AC_ARG_ENABLE(asha, AS_HELP_STRING([--disable-asha],
		[disable ASHA support]), [enable_asha=${enableval}])
AM_CONDITIONAL(ASHA, test "${enable_asha}" != "no")
if test "${enable_asha}" != "no"; then
	AC_DEFINE(HAVE_ASHA, 1, [Define to 1 if you have ASHA support.])
fi

AC_ARG_ENABLE(tools, AS_HELP_STRING([--disable-tools],
		[disable Bluetooth tools]), [enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" != "no")

AC_ARG_ENABLE(monitor, AS_HELP_STRING([--disable-monitor],
		[disable Bluetooth monitor]), [enable_monitor=${enableval}])
AM_CONDITIONAL(MONITOR, test "${enable_monitor}" != "no")

AC_ARG_ENABLE(udev, AS_HELP_STRING([--disable-udev],
		[disable udev device support]), [enable_udev=${enableval}])
if (test "${enable_udev}" != "no"); then
	PKG_CHECK_MODULES(UDEV, libudev >= 196)
	AC_DEFINE(HAVE_UDEV, 1, [Define to 1 if udev is required])
fi

AC_ARG_WITH([udevdir], AS_HELP_STRING([--with-udevdir=DIR],
			[path to udev directory]), [path_udevdir=${withval}])
if (test "${enable_udev}" != "no" && test -z "${path_udevdir}"); then
	AC_MSG_CHECKING([udev directory])
	path_udevdir="`$PKG_CONFIG --variable=udevdir udev`"
	if (test -z "${path_udevdir}"); then
		AC_MSG_ERROR([udev directory is required])
	fi
	AC_MSG_RESULT([${path_udevdir}])
fi
AC_SUBST(UDEV_DIR, [${path_udevdir}])

AC_ARG_ENABLE(cups, AS_HELP_STRING([--disable-cups],
                [disable CUPS printer support]), [enable_cups=${enableval}])
AM_CONDITIONAL(CUPS, test "${enable_cups}" != "no")
if (test "${enable_cups}" != "no"); then
	AC_MSG_CHECKING([cups directory])
	cups_serverbin=`$PKG_CONFIG cups --variable=cups_serverbin`
	AC_MSG_RESULT([${cups_serverbin}])
fi
AM_CONDITIONAL(CUPS_SERVERBIN, test "${cups_serverbin}" != "")
AS_IF([test "${cups_serverbin}" != ""],[
	AC_SUBST(CUPS_SERVERBIN, ${cups_serverbin})
])

AC_ARG_ENABLE(mesh, AS_HELP_STRING([--enable-mesh],
		[enable Mesh profile support]), [enable_mesh=${enableval}])
AM_CONDITIONAL(MESH, test "${enable_mesh}" = "yes")

if (test "${enable_mesh}" = "yes"); then
	PKG_CHECK_MODULES(JSONC, json-c >= 0.13)
fi

AC_ARG_ENABLE(midi, AS_HELP_STRING([--enable-midi],
                [enable MIDI support]), [enable_midi=${enableval}])
AM_CONDITIONAL(MIDI, test "${enable_midi}" = "yes")

if (test "${enable_midi}" = "yes"); then
	PKG_CHECK_MODULES(ALSA, alsa)
fi

AC_ARG_ENABLE(obex, AS_HELP_STRING([--disable-obex],
		[disable OBEX profile support]), [enable_obex=${enableval}])
if (test "${enable_obex}" != "no"); then
	PKG_CHECK_MODULES(ICAL, libical)
fi
AM_CONDITIONAL(OBEX, test "${enable_obex}" != "no")

AC_ARG_ENABLE(btpclient, AS_HELP_STRING([--enable-btpclient],
		[enable BTP client]), [enable_btpclient=${enableval}])
AM_CONDITIONAL(BTPCLIENT, test "${enable_btpclient}" = "yes")

AC_ARG_ENABLE([external_ell], AS_HELP_STRING([--enable-external-ell],
				[enable external Embedded Linux library]),
					[enable_external_ell=${enableval}])
if (test "${enable_external_ell}" = "yes"); then
	PKG_CHECK_MODULES(ELL, ell >= 0.39)
fi
if (test "${enable_external_ell}" != "yes" &&
		(test "${enable_btpclient}" = "yes" || test "${enable_mesh}" = "yes")); then
	if (test ! -f ${srcdir}/ell/ell.h) &&
			(test ! -f ${srcdir}/../ell/ell/ell.h); then
				AC_MSG_ERROR(ELL source is required or use --enable-external-ell)
	fi
fi
AM_CONDITIONAL(EXTERNAL_ELL, test "${enable_external_ell}" = "yes" ||
				(test "${enable_btpclient}" != "yes" &&
						test "${enable_mesh}" != "yes"))
AM_CONDITIONAL(LIBSHARED_ELL, test "${enable_btpclient}" = "yes" ||
						test "${enable_mesh}" = "yes")

AC_ARG_ENABLE(client, AS_HELP_STRING([--disable-client],
		[disable command line client]), [enable_client=${enableval}])
AM_CONDITIONAL(CLIENT, test "${enable_client}" != "no")

if (test "${enable_client}" != "no" || test "${enable_mesh}" = "yes"); then
        AC_CHECK_HEADERS(readline/readline.h, enable_readline=yes,
                AC_MSG_ERROR(readline header files are required))
fi
AM_CONDITIONAL(READLINE, test "${enable_readline}" = "yes")

AC_ARG_ENABLE(systemd, AS_HELP_STRING([--disable-systemd],
		[disable systemd integration]), [enable_systemd=${enableval}])
AM_CONDITIONAL(SYSTEMD, test "${enable_systemd}" != "no")

AC_ARG_WITH([systemdsystemunitdir],
			AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
			[path to systemd system unit directory]),
					[path_systemunitdir=${withval}])
if (test "${enable_systemd}" != "no" && test -z "${path_systemunitdir}"); then
	AC_MSG_CHECKING([systemd system unit dir])
	path_systemunitdir="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"
	if (test -z "${path_systemunitdir}"); then
		AC_MSG_ERROR([systemd system unit directory is required])
	fi
	AC_MSG_RESULT([${path_systemunitdir}])
fi
AC_SUBST(SYSTEMD_SYSTEMUNITDIR, [${path_systemunitdir}])

AC_ARG_WITH([systemduserunitdir],
			AS_HELP_STRING([--with-systemduserunitdir=DIR],
			[path to systemd user unit directory]),
					[path_userunitdir=${withval}])
if (test "${enable_systemd}" != "no" && test -z "${path_userunitdir}"); then
	AC_MSG_CHECKING([systemd user unit dir])
	path_userunitdir="`$PKG_CONFIG --variable=systemduserunitdir systemd`"
	if (test -z "${path_userunitdir}"); then
		AC_MSG_ERROR([systemd user unit directory is required])
	fi
	AC_MSG_RESULT([${path_userunitdir}])
fi
AC_SUBST(SYSTEMD_USERUNITDIR, [${path_userunitdir}])

AC_ARG_ENABLE(datafiles, AS_HELP_STRING([--disable-datafiles],
			[do not install configuration and data files]),
					[enable_datafiles=${enableval}])
AM_CONDITIONAL(DATAFILES, test "${enable_datafiles}" != "no")

AC_ARG_ENABLE(manpages, AS_HELP_STRING([--disable-manpages],
			[disable building of manual pages]),
					[enable_manpages=${enableval}])
if (test "${enable_manpages}" != "no"); then
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], "no")
	if (test "${RST2MAN}" = "no" ); then
		AC_MSG_ERROR([rst2man is required])
	fi
fi
AM_CONDITIONAL(MANPAGES, test "${enable_manpages}" != "no")
AM_CONDITIONAL(RUN_RST2MAN, test "${enable_manpages}" != "no" &&
				test "${RST2MAN}" != "no")

AC_ARG_ENABLE(testing, AS_HELP_STRING([--enable-testing],
			[enable testing tools]),
					[enable_testing=${enableval}])
AM_CONDITIONAL(TESTING, test "${enable_testing}" = "yes")

if (test "${enable_testing}" = "yes"); then
   AC_CHECK_DECLS([SOF_TIMESTAMPING_TX_COMPLETION, SCM_TSTAMP_COMPLETION],
	[], [], [[#include <time.h>
		#include <linux/errqueue.h>
		#include <linux/net_tstamp.h>]])
fi

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
if (test "${enable_external_plugins}" = "yes"); then
	AC_DEFINE(EXTERNAL_PLUGINS, 1, [Define if external plugin support is required])
else
	AC_DEFINE(EXTERNAL_PLUGINS, 0, [Define if external plugin support is required])
fi

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

if (test "${prefix}" = "NONE"); then
	dnl no prefix and no localstatedir, so default to /var
	if (test "$localstatedir" = '${prefix}/var'); then
		AC_SUBST([localstatedir], ['/var'])
	fi

	prefix="${ac_default_prefix}"
fi

if (test "${exec_prefix}" = "NONE"); then
	# exec_prefix defaults to prefix, although our manual handling of the
	# latter (above) confuses autoconf. Manually set the exec_prefix.
	exec_prefix="${prefix}"
fi

# Expand any variables containing relative references like ${prefix} and co.
#
# Otherwise we'll end up with literal references in the final binaries or
# manuals, which is not something we really want.
#
pkgbindir="${bindir}"
if (test "$bindir" = '${exec_prefix}/bin'); then
	pkgbindir="${exec_prefix}/bin"
else
	pkgbindir="${bindir}"
fi
AC_SUBST(PKGBINDIR, "${pkgbindir}")

if (test "$libexecdir" = '${exec_prefix}/libexec'); then
	pkglibexecdir="${exec_prefix}/libexec/bluetooth"
else
	pkglibexecdir="${libexecdir}/bluetooth"
fi
AC_SUBST(PKGLIBEXECDIR, "${pkglibexecdir}")

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
AC_SUBST(CONFIGDIR, "${configdir}")

AC_DEFINE_UNQUOTED(MESH_STORAGEDIR, "${storagedir}/mesh",
			[Directory for the mesh daemon storage files])
AC_SUBST(MESH_STORAGEDIR, "${storagedir}/mesh")

AC_ARG_WITH([phonebook], AS_HELP_STRING([--with-phonebook=PLUGIN],
			[obexd phonebook plugin (default=dummy)]),
			[plugin_phonebook=${withval}])
if (test -z "${plugin_phonebook}"); then
	plugin_phonebook=dummy
fi

if (test "${plugin_phonebook}" = "ebook"); then
	PKG_CHECK_MODULES(LIBEBOOK, libebook-1.2 >= 3.3)
	PKG_CHECK_MODULES(LIBEDATESERVER, libedataserver-1.2 >= 3.3)
fi
AC_SUBST(PLUGIN_PHONEBOOK, [${plugin_phonebook}])

AC_CONFIG_FILES(
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
)
AC_OUTPUT
