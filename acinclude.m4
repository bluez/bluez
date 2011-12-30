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

AC_DEFUN([COMPILER_FLAGS], [
	if (test "${CFLAGS}" = ""); then
		CFLAGS="-Wall -O2"
	fi
	if (test "$USE_MAINTAINER_MODE" = "yes"); then
		CFLAGS="$CFLAGS -Werror -Wextra"
		CFLAGS="$CFLAGS -Wno-unused-parameter"
		CFLAGS="$CFLAGS -Wno-missing-field-initializers"
		CFLAGS="$CFLAGS -Wdeclaration-after-statement"
		CFLAGS="$CFLAGS -Wmissing-declarations"
		CFLAGS="$CFLAGS -Wredundant-decls"
		CFLAGS="$CFLAGS -Wcast-align"
		CFLAGS="$CFLAGS -DG_DISABLE_DEPRECATED"
	fi
])

AC_DEFUN([AC_FUNC_PPOLL], [
	AC_CHECK_FUNC(ppoll, dummy=yes, AC_DEFINE(NEED_PPOLL, 1,
			[Define to 1 if you need the ppoll() function.]))
])

AC_DEFUN([AC_INIT_BLUEZ], [
	AC_PREFIX_DEFAULT(/usr/local)

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

	plugindir="${libdir}/bluetooth/plugins"

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

	AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}",
				[Directory for the configuration files])
	AC_DEFINE_UNQUOTED(STORAGEDIR, "${storagedir}",
				[Directory for the storage files])

	AC_SUBST(CONFIGDIR, "${configdir}")
	AC_SUBST(STORAGEDIR, "${storagedir}")

	UDEV_DIR="`$PKG_CONFIG --variable=udevdir udev`"
	if (test -z "${UDEV_DIR}"); then
		UDEV_DIR="/lib/udev"
	fi
	AC_SUBST(UDEV_DIR)
])

AC_DEFUN([AC_PATH_DBUS], [
	PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.0, dummy=yes,
				AC_MSG_ERROR(D-Bus library is required))
	AC_CHECK_LIB(dbus-1, dbus_watch_get_unix_fd, dummy=yes,
		AC_DEFINE(NEED_DBUS_WATCH_GET_UNIX_FD, 1,
			[Define to 1 if you need the dbus_watch_get_unix_fd() function.]))
	AC_CHECK_LIB(dbus-1, dbus_connection_can_send_type, dummy=yes,
		AC_DEFINE(NEED_DBUS_CONNECTION_CAN_SEND_TYPE, 1,
			[Define to 1 if you need the dbus_connection_can_send_type() function.]
))
	AC_SUBST(DBUS_CFLAGS)
	AC_SUBST(DBUS_LIBS)
])

AC_DEFUN([AC_PATH_GLIB], [
	PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16, dummy=yes,
				AC_MSG_ERROR(GLib library version 2.16 or later is required))
	AC_CHECK_LIB(glib-2.0, g_slist_free_full, dummy=yes,
		AC_DEFINE(NEED_G_SLIST_FREE_FULL, 1,
			[Define to 1 if you need g_slist_free_full() function.]))
	AC_SUBST(GLIB_CFLAGS)
	AC_SUBST(GLIB_LIBS)
])

AC_DEFUN([AC_PATH_GSTREAMER], [
	PKG_CHECK_MODULES(GSTREAMER, gstreamer-0.10 >= 0.10.30 gstreamer-plugins-base-0.10, gstreamer_found=yes,
				AC_MSG_WARN(GStreamer library version 0.10.30 or later is required);gstreamer_found=no)
	AC_SUBST(GSTREAMER_CFLAGS)
	AC_SUBST(GSTREAMER_LIBS)
	GSTREAMER_PLUGINSDIR=`$PKG_CONFIG --variable=pluginsdir gstreamer-0.10`
	AC_SUBST(GSTREAMER_PLUGINSDIR)
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

AC_DEFUN([AC_PATH_UDEV], [
	PKG_CHECK_MODULES(UDEV, libudev, udev_found=yes, udev_found=no)
	AC_SUBST(UDEV_CFLAGS)
	AC_SUBST(UDEV_LIBS)
])

AC_DEFUN([AC_PATH_SNDFILE], [
	PKG_CHECK_MODULES(SNDFILE, sndfile, sndfile_found=yes, sndfile_found=no)
	AC_SUBST(SNDFILE_CFLAGS)
	AC_SUBST(SNDFILE_LIBS)
])

AC_DEFUN([AC_PATH_READLINE], [
	AC_CHECK_HEADER(readline/readline.h,
		AC_CHECK_LIB(readline, main,
			[ readline_found=yes
			AC_SUBST(READLINE_LIBS, "-lreadline")
			], readline_found=no),
		[])
])

AC_DEFUN([AC_PATH_CHECK], [
	PKG_CHECK_MODULES(CHECK, check >= 0.9.6, check_found=yes, check_found=no)
	AC_SUBST(CHECK_CFLAGS)
	AC_SUBST(CHECK_LIBS)
])

AC_DEFUN([AC_PATH_OUI], [
	AC_ARG_WITH(ouifile,
		    AS_HELP_STRING([--with-ouifile=PATH],[Path to the oui.txt file @<:@auto@:>@]),
		    [ac_with_ouifile=$withval],
		    [ac_with_ouifile="/var/lib/misc/oui.txt"])
	AC_DEFINE_UNQUOTED(OUIFILE, ["$ac_with_ouifile"], [Define the OUI file path])
])

AC_DEFUN([AC_ARG_BLUEZ], [
	debug_enable=no
	optimization_enable=yes
	fortify_enable=yes
	pie_enable=yes
	sndfile_enable=${sndfile_found}
	hal_enable=no
	usb_enable=${usb_found}
	alsa_enable=${alsa_found}
	gstreamer_enable=${gstreamer_found}
	audio_enable=yes
	input_enable=yes
	serial_enable=yes
	network_enable=yes
	sap_enable=no
	proximity_enable=no
	time_enable=no
	alert_enable=no
	service_enable=yes
	health_enable=no
	pnat_enable=no
	gatt_example_enable=no
	tracer_enable=no
	tools_enable=yes
	hidd_enable=no
	pand_enable=no
	dund_enable=no
	cups_enable=no
	test_enable=no
	bccmd_enable=no
	pcmcia_enable=no
	hid2hci_enable=no
	dfutool_enable=no
	datafiles_enable=yes
	telephony_driver=dummy
	maemo6_enable=no
	sap_driver=dummy
	dbusoob_enable=no
	wiimote_enable=no
	thermometer_enable=no

	AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization], [disable code optimization]), [
		optimization_enable=${enableval}
	])

	AC_ARG_ENABLE(fortify, AC_HELP_STRING([--disable-fortify], [disable compile time buffer checks]), [
		fortify_enable=${enableval}
	])

	AC_ARG_ENABLE(pie, AC_HELP_STRING([--disable-pie], [disable position independent executables flag]), [
		pie_enable=${enableval}
	])

	AC_ARG_ENABLE(network, AC_HELP_STRING([--disable-network], [disable network plugin]), [
		network_enable=${enableval}
	])

	AC_ARG_ENABLE(sap, AC_HELP_STRING([--enable-sap], [enable sap plugin]), [
		sap_enable=${enableval}
	])

	AC_ARG_WITH(sap, AC_HELP_STRING([--with-sap=DRIVER], [select SAP driver]), [
		sap_driver=${withval}
	])
	AC_SUBST([SAP_DRIVER], [sap-${sap_driver}.c])

	AC_ARG_ENABLE(proximity, AC_HELP_STRING([--enable-proximity], [enable proximity plugin]), [
		proximity_enable=${enableval}
	])

	AC_ARG_ENABLE(time, AC_HELP_STRING([--enable-time], [enable Time Profile plugin]), [
		time_enable=${enableval}
	])

	AC_ARG_ENABLE(alert, AC_HELP_STRING([--enable-alert], [enable Phone Alert Profile plugin]), [
		alert_enable=${enableval}
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

	AC_ARG_ENABLE(service, AC_HELP_STRING([--disable-service], [disable service plugin]), [
		service_enable=${enableval}
	])

	AC_ARG_ENABLE(health, AC_HELP_STRING([--enable-health], [enable health plugin]), [
		health_enable=${enableval}
	])

	AC_ARG_ENABLE(pnat, AC_HELP_STRING([--enable-pnat], [enable pnat plugin]), [
		pnat_enable=${enableval}
	])

	AC_ARG_ENABLE(gatt-example, AC_HELP_STRING([--enable-gatt-example], [enable GATT example plugin]), [
		gatt_example_enable=${enableval}
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

	AC_ARG_ENABLE(tracer, AC_HELP_STRING([--enable-tracer], [install Tracing daemon]), [
		tracer_enable=${enableval}
	])

	AC_ARG_ENABLE(tools, AC_HELP_STRING([--enable-tools], [install Bluetooth utilities]), [
		tools_enable=${enableval}
	])

	AC_ARG_ENABLE(bccmd, AC_HELP_STRING([--enable-bccmd], [install BCCMD interface utility]), [
		bccmd_enable=${enableval}
	])

	AC_ARG_ENABLE(pcmcia, AC_HELP_STRING([--enable-pcmcia], [install PCMCIA serial script]), [
		pcmcia_enable=${enableval}
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

	AC_ARG_ENABLE(datafiles, AC_HELP_STRING([--enable-datafiles], [install Bluetooth configuration and data files]), [
		datafiles_enable=${enableval}
	])

	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable compiling with debugging information]), [
		debug_enable=${enableval}
	])

	AC_ARG_WITH(telephony, AC_HELP_STRING([--with-telephony=DRIVER], [select telephony driver]), [
		telephony_driver=${withval}
	])

	AC_SUBST([TELEPHONY_DRIVER], [telephony-${telephony_driver}.c])

	AC_ARG_ENABLE(maemo6, AC_HELP_STRING([--enable-maemo6], [compile with maemo6 plugin]), [
		maemo6_enable=${enableval}
	])

	AC_ARG_ENABLE(dbusoob, AC_HELP_STRING([--enable-dbusoob], [compile with D-Bus OOB plugin]), [
		dbusoob_enable=${enableval}
	])

	AC_ARG_ENABLE(wiimote, AC_HELP_STRING([--enable-wiimote], [compile with Wii Remote plugin]), [
		wiimote_enable=${enableval}
	])

	AC_ARG_ENABLE(hal, AC_HELP_STRING([--enable-hal], [Use HAL to determine adapter class]), [
		hal_enable=${enableval}
	])

	AC_ARG_ENABLE(thermometer, AC_HELP_STRING([--enable-thermometer], [enable thermometer plugin]), [
		thermometer_enable=${enableval}
	])

	if (test "${fortify_enable}" = "yes"); then
		CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
	fi

	if (test "${pie_enable}" = "yes" && test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIC"
		LDFLAGS="$LDFLAGS -pie"
	fi

	if (test "${debug_enable}" = "yes" && test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi

	if (test "${optimization_enable}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi

	if (test "${usb_enable}" = "yes" && test "${usb_found}" = "yes"); then
		AC_DEFINE(HAVE_LIBUSB, 1, [Define to 1 if you have USB library.])
	fi

	AM_CONDITIONAL(SNDFILE, test "${sndfile_enable}" = "yes" && test "${sndfile_found}" = "yes")
	AM_CONDITIONAL(USB, test "${usb_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(SBC, test "${alsa_enable}" = "yes" || test "${gstreamer_enable}" = "yes" ||
									test "${test_enable}" = "yes")
	AM_CONDITIONAL(ALSA, test "${alsa_enable}" = "yes" && test "${alsa_found}" = "yes")
	AM_CONDITIONAL(GSTREAMER, test "${gstreamer_enable}" = "yes" && test "${gstreamer_found}" = "yes")
	AM_CONDITIONAL(AUDIOPLUGIN, test "${audio_enable}" = "yes")
	AM_CONDITIONAL(INPUTPLUGIN, test "${input_enable}" = "yes")
	AM_CONDITIONAL(SERIALPLUGIN, test "${serial_enable}" = "yes")
	AM_CONDITIONAL(NETWORKPLUGIN, test "${network_enable}" = "yes")
	AM_CONDITIONAL(SAPPLUGIN, test "${sap_enable}" = "yes")
	AM_CONDITIONAL(PROXIMITYPLUGIN, test "${proximity_enable}" = "yes")
	AM_CONDITIONAL(TIMEPLUGIN, test "${time_enable}" = "yes")
	AM_CONDITIONAL(ALERTPLUGIN, test "${alert_enable}" = "yes")
	AM_CONDITIONAL(SERVICEPLUGIN, test "${service_enable}" = "yes")
	AM_CONDITIONAL(HEALTHPLUGIN, test "${health_enable}" = "yes")
	AM_CONDITIONAL(MCAP, test "${health_enable}" = "yes")
	AM_CONDITIONAL(HAL, test "${hal_enable}" = "yes")
	AM_CONDITIONAL(READLINE, test "${readline_found}" = "yes")
	AM_CONDITIONAL(GATT_EXAMPLE_PLUGIN, test "${gatt_example_enable}" = "yes")
	AM_CONDITIONAL(PNATPLUGIN, test "${pnat_enable}" = "yes")
	AM_CONDITIONAL(TRACER, test "${tracer_enable}" = "yes")
	AM_CONDITIONAL(HIDD, test "${hidd_enable}" = "yes")
	AM_CONDITIONAL(PAND, test "${pand_enable}" = "yes")
	AM_CONDITIONAL(DUND, test "${dund_enable}" = "yes")
	AM_CONDITIONAL(CUPS, test "${cups_enable}" = "yes")
	AM_CONDITIONAL(TEST, test "${test_enable}" = "yes" && test "${check_found}" = "yes")
	AM_CONDITIONAL(TOOLS, test "${tools_enable}" = "yes")
	AM_CONDITIONAL(BCCMD, test "${bccmd_enable}" = "yes")
	AM_CONDITIONAL(PCMCIA, test "${pcmcia_enable}" = "yes")
	AM_CONDITIONAL(HID2HCI, test "${hid2hci_enable}" = "yes" && test "${usb_found}" = "yes" && test "${udev_found}" = "yes")
	AM_CONDITIONAL(DFUTOOL, test "${dfutool_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(DATAFILES, test "${datafiles_enable}" = "yes")
	AM_CONDITIONAL(MAEMO6PLUGIN, test "${maemo6_enable}" = "yes")
	AM_CONDITIONAL(DBUSOOBPLUGIN, test "${dbusoob_enable}" = "yes")
	AM_CONDITIONAL(WIIMOTEPLUGIN, test "${wiimote_enable}" = "yes")
	AM_CONDITIONAL(THERMOMETERPLUGIN, test "${thermometer_enable}" = "yes")
])
