AC_DEFUN([AC_PROG_CC_PIE], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fPIE], ac_cv_prog_cc_pie, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fPIE -pie -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_pie=yes
		else
			ac_cv_prog_cc_pie=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([AC_FUNC_PPOLL], [
	AC_CHECK_FUNC(ppoll, dummy=yes, AC_DEFINE(NEED_PPOLL, 1,
			[Define to 1 if you need the ppoll() function.]))
])

AC_DEFUN([AC_INIT_BLUEZ], [
	AC_PREFIX_DEFAULT(/usr/local)

	if (test "${CFLAGS}" = ""); then
		CFLAGS="-Wall -O2"
	fi

	if (test "${prefix}" = "NONE"); then
		dnl no prefix and no sysconfdir, so default to /etc
		if (test "$sysconfdir" = '${prefix}/etc'); then
			AC_SUBST([sysconfdir], ['/etc'])
		fi

		dnl no prefix and no localstatedir, so default to /var
		if (test "$localstatedir" = '${prefix}/var'); then
			AC_SUBST([localstatedir], ['/var'])
		fi

		dnl no prefix and no libexecdir, so default to /lib
		if (test "$libexecdir" = '${exec_prefix}/libexec'); then
			AC_SUBST([libexecdir], ['/lib'])
		fi

		dnl no prefix and no mandir, so use ${prefix}/share/man as default
		if (test "$mandir" = '${prefix}/man'); then
			AC_SUBST([mandir], ['${prefix}/share/man'])
		fi

		prefix="${ac_default_prefix}"
	fi

	if (test "${libdir}" = '${exec_prefix}/lib'); then
		libdir="${prefix}/lib"
	fi

	if (test "$sysconfdir" = '${prefix}/etc'); then
		configdir="${prefix}/etc/bluetooth"
	else
		configdir="${sysconfdir}/bluetooth"
	fi

	if (test "$localstatedir" = '${prefix}/var'); then
		storagedir="${prefix}/var/lib/bluetooth"
	else
		storagedir="${localstatedir}/lib/bluetooth"
	fi

	servicedir="${libdir}/bluetooth"

	AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}",
				[Directory for the configuration files])
	AC_DEFINE_UNQUOTED(STORAGEDIR, "${storagedir}",
				[Directory for the storage files])
	AC_DEFINE_UNQUOTED(SERVICEDIR, "${servicedir}",
				[Directory for the service programs])
])

AC_DEFUN([AC_PATH_BLUEZ], [
	PKG_CHECK_MODULES(BLUEZ, bluez, dummy=yes,
				AC_MSG_ERROR(Bluetooth library is required))
	AC_SUBST(BLUEZ_CFLAGS)
	AC_SUBST(BLUEZ_LIBS)
])

AC_DEFUN([AC_PATH_DBUS], [
	PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.0, dummy=yes,
				AC_MSG_ERROR(D-Bus library is required))
	AC_CHECK_LIB(dbus-1, dbus_watch_get_unix_fd, dummy=yes,
		AC_DEFINE(NEED_DBUS_WATCH_GET_UNIX_FD, 1,
			[Define to 1 if you need the dbus_watch_get_unix_fd() function.]))
	AC_SUBST(DBUS_CFLAGS)
	AC_SUBST(DBUS_LIBS)
])

AC_DEFUN([AC_PATH_GLIB], [
	PKG_CHECK_MODULES(GLIB, glib-2.0, glib_found=yes, glib_found=no)
	AC_SUBST(GLIB_CFLAGS)
	AC_SUBST(GLIB_LIBS)
])

AC_DEFUN([AC_PATH_GMODULE], [
	PKG_CHECK_MODULES(GMODULE, gmodule-2.0, gmodule_found=yes, gmodule_found=no)
	AC_CHECK_LIB(dl, dlopen, dummy=yes, dummy=no)
	AC_SUBST(GMODULE_CFLAGS)
	AC_SUBST(GMODULE_LIBS)
])

AC_DEFUN([AC_PATH_GSTREAMER], [
	PKG_CHECK_MODULES(GSTREAMER, gstreamer-0.10 gstreamer-plugins-base-0.10, gstreamer_found=yes, gstreamer_found=no)
	AC_SUBST(GSTREAMER_CFLAGS)
	AC_SUBST(GSTREAMER_LIBS)
	GSTREAMER_PLUGINSDIR=`$PKG_CONFIG --variable=pluginsdir gstreamer-0.10`
	AC_SUBST(GSTREAMER_PLUGINSDIR)
])

AC_DEFUN([AC_PATH_PULSE], [
	PKG_CHECK_MODULES(PULSE, libpulse, pulse_found=yes, pulse_found=no)
	AC_SUBST(PULSE_CFLAGS)
	AC_SUBST(PULSE_LIBS)
])

AC_DEFUN([AC_PATH_ALSA], [
	PKG_CHECK_MODULES(ALSA, alsa, alsa_found=yes, alsa_found=no)
	AC_CHECK_LIB(rt, clock_gettime, ALSA_LIBS="$ALSA_LIBS -lrt", alsa_found=no)
	AC_SUBST(ALSA_CFLAGS)
	AC_SUBST(ALSA_LIBS)
])

AC_DEFUN([AC_PATH_USB], [
	PKG_CHECK_MODULES(USB, libusb, usb_found=yes, usb_found=no)
	AC_SUBST(USB_CFLAGS)
	AC_SUBST(USB_LIBS)
	AC_CHECK_LIB(usb, usb_get_busses, dummy=yes,
		AC_DEFINE(NEED_USB_GET_BUSSES, 1,
			[Define to 1 if you need the usb_get_busses() function.]))
	AC_CHECK_LIB(usb, usb_interrupt_read, dummy=yes,
		AC_DEFINE(NEED_USB_INTERRUPT_READ, 1,
			[Define to 1 if you need the usb_interrupt_read() function.]))
])

AC_DEFUN([AC_PATH_NETLINK], [
	PKG_CHECK_MODULES(NETLINK, libnl-1, netlink_found=yes, netlink_found=no)
	AC_SUBST(NETLINK_CFLAGS)
	AC_SUBST(NETLINK_LIBS)
])

AC_DEFUN([AC_PATH_SNDFILE], [
	PKG_CHECK_MODULES(SNDFILE, sndfile, sndfile_found=yes, sndfile_found=no)
	AC_SUBST(SNDFILE_CFLAGS)
	AC_SUBST(SNDFILE_LIBS)
])

AC_DEFUN([AC_ARG_BLUEZ], [
	debug_enable=no
	fortify_enable=yes
	pie_enable=yes
	sndfile_enable=${sndfile_found}
	netlink_enable=no
	usb_enable=${usb_found}
	alsa_enable=${alsa_found}
	glib_enable=yes
	gstreamer_enable=${gstreamer_found}
	audio_enable=yes
	input_enable=yes
	serial_enable=yes
	network_enable=yes
	tools_enable=yes
	hidd_enable=no
	pand_enable=no
	dund_enable=no
	cups_enable=no
	test_enable=no
	bccmd_enable=no
	hid2hci_enable=no
	dfutool_enable=no
	manpages_enable=yes
	configfiles_enable=yes
	initscripts_enable=no
	pcmciarules_enable=no

	AC_ARG_ENABLE(fortify, AC_HELP_STRING([--disable-fortify], [disable compile time buffer checks]), [
		fortify_enable=${enableval}
	])

	AC_ARG_ENABLE(pie, AC_HELP_STRING([--disable-pie], [disable position independent executables flag]), [
		pie_enable=${enableval}
	])

	AC_ARG_ENABLE(glib, AC_HELP_STRING([--disable-glib], [disable GLib support]), [
		glib_enable=${enableval}
	])

	AC_ARG_ENABLE(network, AC_HELP_STRING([--disable-network], [disable network plugin]), [
		network_enable=${enableval}
	])

	AC_ARG_ENABLE(serial, AC_HELP_STRING([--disable-serial], [disable serial plugin]), [
		serial_enable=${enableval}
	])

	AC_ARG_ENABLE(input, AC_HELP_STRING([--disable-input], [disable input plugin]), [
		input_enable=${enableval}
	])

	AC_ARG_ENABLE(audio, AC_HELP_STRING([--disable-audio], [disable audio plugin]), [
		audio_enable=${enableval}
	])

	AC_ARG_ENABLE(gstreamer, AC_HELP_STRING([--enable-gstreamer], [enable GStreamer support]), [
		gstreamer_enable=${enableval}
	])

	AC_ARG_ENABLE(alsa, AC_HELP_STRING([--enable-alsa], [enable ALSA support]), [
		alsa_enable=${enableval}
	])

	AC_ARG_ENABLE(usb, AC_HELP_STRING([--enable-usb], [enable USB support]), [
		usb_enable=${enableval}
	])

	AC_ARG_ENABLE(netlink, AC_HELP_STRING([--enable-netlink], [enable NETLINK support]), [
		netlink_enable=${enableval}
	])

	AC_ARG_ENABLE(tools, AC_HELP_STRING([--enable-tools], [install Bluetooth utilities]), [
		tools_enable=${enableval}
	])

	AC_ARG_ENABLE(bccmd, AC_HELP_STRING([--enable-bccmd], [install BCCMD interface utility]), [
		bccmd_enable=${enableval}
	])

	AC_ARG_ENABLE(hid2hci, AC_HELP_STRING([--enable-hid2hci], [install HID mode switching utility]), [
		hid2hci_enable=${enableval}
	])

	AC_ARG_ENABLE(dfutool, AC_HELP_STRING([--enable-dfutool], [install DFU firmware upgrade utility]), [
		dfutool_enable=${enableval}
	])

	AC_ARG_ENABLE(hidd, AC_HELP_STRING([--enable-hidd], [install HID daemon]), [
		hidd_enable=${enableval}
	])

	AC_ARG_ENABLE(pand, AC_HELP_STRING([--enable-pand], [install PAN daemon]), [
		pand_enable=${enableval}
	])

	AC_ARG_ENABLE(dund, AC_HELP_STRING([--enable-dund], [install DUN daemon]), [
		dund_enable=${enableval}
	])

	AC_ARG_ENABLE(cups, AC_HELP_STRING([--enable-cups], [install CUPS backend support]), [
		cups_enable=${enableval}
	])

	AC_ARG_ENABLE(test, AC_HELP_STRING([--enable-test], [install test programs]), [
		test_enable=${enableval}
	])

	AC_ARG_ENABLE(manpages, AC_HELP_STRING([--enable-manpages], [install Bluetooth manual pages]), [
		manpages_enable=${enableval}
	])

	AC_ARG_ENABLE(configfiles, AC_HELP_STRING([--enable-configfiles], [install Bluetooth config files]), [
		configfiles_enable=${enableval}
	])

	AC_ARG_ENABLE(initscripts, AC_HELP_STRING([--enable-initscripts], [install Bluetooth boot scripts]), [
		initscripts_enable=${enableval}
	])

	AC_ARG_ENABLE(pcmciarules, AC_HELP_STRING([--enable-pcmciarules], [install PCMCIA udev rules]), [
		pcmciarules_enable=${enableval}
	])

	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable compiling with debugging information]), [
		debug_enable=${enableval}
	])

	if (test "${fortify_enable}" = "yes"); then
		CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
	fi

	if (test "${pie_enable}" = "yes" && test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi

	if (test "${debug_enable}" = "yes" && test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g -O0"
	fi

	if (test "${usb_enable}" = "yes" && test "${usb_found}" = "yes"); then
		AC_DEFINE(HAVE_LIBUSB, 1, [Define to 1 if you have USB library.])
	fi

	if (test "${glib_enable}" = "yes" && test "${glib_found}" = "yes"); then
		AM_CONDITIONAL(GLIB, true)
	else
		AC_SUBST([GLIB_CFLAGS], ['-I$(top_srcdir)/eglib'])
		AC_SUBST([GLIB_LIBS], ['$(top_builddir)/eglib/libeglib.la -ldl -rdynamic'])
		AC_SUBST([GMODULE_CFLAGS], [''])
		AC_SUBST([GMODULE_LIBS], [''])
		AM_CONDITIONAL(GLIB, false)
	fi

	AC_SUBST([GDBUS_CFLAGS], ['-I$(top_srcdir)/gdbus'])
	AC_SUBST([GDBUS_LIBS], ['$(top_builddir)/gdbus/libgdbus.la'])

	AC_SUBST([SBC_CFLAGS], ['-I$(top_srcdir)/sbc'])
	AC_SUBST([SBC_LIBS], ['$(top_builddir)/sbc/libsbc.la'])

	AM_CONDITIONAL(SNDFILE, test "${sndfile_enable}" = "yes" && test "${sndfile_found}" = "yes")
	AM_CONDITIONAL(NETLINK, test "${netlink_enable}" = "yes" && test "${netlink_found}" = "yes")
	AM_CONDITIONAL(USB, test "${usb_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(SBC, test "${alsa_enable}" = "yes" || test "${gstreamer_enable}" = "yes")
	AM_CONDITIONAL(ALSA, test "${alsa_enable}" = "yes" && test "${alsa_found}" = "yes")
	AM_CONDITIONAL(GSTREAMER, test "${gstreamer_enable}" = "yes" && test "${gstreamer_found}" = "yes")
	AM_CONDITIONAL(AUDIOPLUGIN, test "${audio_enable}" = "yes")
	AM_CONDITIONAL(INPUTPLUGIN, test "${input_enable}" = "yes")
	AM_CONDITIONAL(SERIALPLUGIN, test "${serial_enable}" = "yes")
	AM_CONDITIONAL(NETWORKPLUGIN, test "${network_enable}" = "yes")
	AM_CONDITIONAL(HIDD, test "${hidd_enable}" = "yes")
	AM_CONDITIONAL(PAND, test "${pand_enable}" = "yes")
	AM_CONDITIONAL(DUND, test "${dund_enable}" = "yes")
	AM_CONDITIONAL(CUPS, test "${cups_enable}" = "yes")
	AM_CONDITIONAL(TEST, test "${test_enable}" = "yes")
	AM_CONDITIONAL(TOOLS, test "${tools_enable}" = "yes")
	AM_CONDITIONAL(BCCMD, test "${bccmd_enable}" = "yes")
	AM_CONDITIONAL(HID2HCI, test "${hid2hci_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(DFUTOOL, test "${dfutool_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(MANPAGES, test "${manpages_enable}" = "yes")
	AM_CONDITIONAL(CONFIGFILES, test "${configfiles_enable}" = "yes")
	AM_CONDITIONAL(INITSCRIPTS, test "${initscripts_enable}" = "yes")
	AM_CONDITIONAL(PCMCIARULES, test "${pcmciarules_enable}" = "yes")
])
