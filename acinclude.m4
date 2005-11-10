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

	AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}", [Directory for the configuration files])
	AC_DEFINE_UNQUOTED(STORAGEDIR, "${storagedir}", [Directory for the storage files])
])

AC_DEFUN([AC_PATH_BLUEZ], [
	bluez_prefix=${prefix}

	AC_ARG_WITH(bluez, AC_HELP_STRING([--with-bluez=DIR], [BlueZ library is installed in DIR]), [
		if (test "${withval}" != "yes"); then
			bluez_prefix=${withval}
		fi
	])

	ac_save_CPPFLAGS=$CPPFLAGS
	ac_save_LDFLAGS=$LDFLAGS

	BLUEZ_CFLAGS=""
	test -d "${bluez_prefix}/include" && BLUEZ_CFLAGS="$BLUEZ_CFLAGS -I${bluez_prefix}/include"

	CPPFLAGS="$CPPFLAGS $BLUEZ_CFLAGS"
	AC_CHECK_HEADER(bluetooth/bluetooth.h, dummy=yes, AC_MSG_ERROR(Bluetooth header files not found))

	BLUEZ_LIBS=""
	if (test "${prefix}" = "${bluez_prefix}"); then
		test -d "${libdir}" && BLUEZ_LIBS="$BLUEZ_LIBS -L${libdir}"
	else
		test -d "${bluez_prefix}/lib64" && BLUEZ_LIBS="$BLUEZ_LIBS -L${bluez_prefix}/lib64"
		test -d "${bluez_prefix}/lib" && BLUEZ_LIBS="$BLUEZ_LIBS -L${bluez_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $BLUEZ_LIBS"
	AC_CHECK_LIB(bluetooth, hci_open_dev, BLUEZ_LIBS="$BLUEZ_LIBS -lbluetooth", AC_MSG_ERROR(Bluetooth library not found))
	AC_CHECK_LIB(bluetooth, sdp_connect, dummy=yes, AC_CHECK_LIB(sdp, sdp_connect, BLUEZ_LIBS="$BLUEZ_LIBS -lsdp"))

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(BLUEZ_CFLAGS)
	AC_SUBST(BLUEZ_LIBS)
])

AC_DEFUN([AC_PATH_OPENOBEX], [
	openobex_prefix=${prefix}

	AC_ARG_WITH(openobex, AC_HELP_STRING([--with-openobex=DIR], [OpenOBEX library is installed in DIR]), [
		if (test "${withval}" != "yes"); then
			openobex_prefix=${withval}
		fi
	])

	ac_save_CPPFLAGS=$CPPFLAGS
	ac_save_LDFLAGS=$LDFLAGS

	OPENOBEX_CFLAGS=""
	test -d "${openobex_prefix}/include" && OPENOBEX_CFLAGS="$OPENOBEX_CFLAGS -I${openobex_prefix}/include"

	CPPFLAGS="$CPPFLAGS $OPENOBEX_CFLAGS"
	AC_CHECK_HEADER(openobex/obex.h, openobex_found=yes, openobex_found=no)

	OPENOBEX_LIBS=""
	if (test "${prefix}" = "${openobex_prefix}"); then
		test -d "${libdir}" && OPENOBEX_LIBS="$OPENOBEX_LIBS -L${libdir}"
	else
		test -d "${openobex_prefix}/lib64" && OPENOBEX_LIBS="$OPENOBEX_LIBS -L${openobex_prefix}/lib64"
		test -d "${openobex_prefix}/lib" && OPENOBEX_LIBS="$OPENOBEX_LIBS -L${openobex_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $OPENOBEX_LIBS"
	AC_CHECK_LIB(openobex, OBEX_Init, OPENOBEX_LIBS="$OPENOBEX_LIBS -lopenobex", openobex_found=no)
	AC_CHECK_LIB(openobex, BtOBEX_TransportConnect, AC_DEFINE(HAVE_BTOBEX_TRANSPORT_CONNECT, 1, [Define to 1 if you have the BtOBEX_TransportConnect() function.]))

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(OPENOBEX_CFLAGS)
	AC_SUBST(OPENOBEX_LIBS)
])

AC_DEFUN([AC_PATH_DBUS], [
	dbus_prefix=${prefix}

	AC_ARG_WITH(dbus, AC_HELP_STRING([--with-dbus=DIR], [D-BUS library is installed in DIR]), [
		if (test "${withval}" != "yes"); then
			dbus_prefix=${withval}
		fi
	])

	ac_save_CPPFLAGS=$CPPFLAGS
	ac_save_LDFLAGS=$LDFLAGS

	DBUS_CFLAGS="-DDBUS_API_SUBJECT_TO_CHANGE"
	test -d "${dbus_prefix}/include/dbus-1.0" && DBUS_CFLAGS="$DBUS_CFLAGS -I${dbus_prefix}/include/dbus-1.0"
	if (test "${prefix}" = "${bluez_prefix}"); then
		test -d "${libdir}/dbus-1.0/include" && DBUS_CFLAGS="$DBUS_CFLAGS -I${libdir}/dbus-1.0/include"
	else
		test -d "${dbus_prefix}/lib64/dbus-1.0/include" && DBUS_CFLAGS="$DBUS_CFLAGS -I${dbus_prefix}/lib64/dbus-1.0/include"
		test -d "${dbus_prefix}/lib/dbus-1.0/include" && DBUS_CFLAGS="$DBUS_CFLAGS -I${dbus_prefix}/lib/dbus-1.0/include"
	fi

	CPPFLAGS="$CPPFLAGS $DBUS_CFLAGS"
	AC_CHECK_HEADER(dbus/dbus.h, dbus_found=yes, dbus_found=no)

	DBUS_LIBS=""
	if (test "${prefix}" = "${dbus_prefix}"); then
		test -d "${libdir}" && DBUS_LIBS="$DBUS_LIBS -L${libdir}"
	else
		test -d "${dbus_prefix}/lib64" && DBUS_LIBS="$DBUS_LIBS -L${dbus_prefix}/lib64"
		test -d "${dbus_prefix}/lib" && DBUS_LIBS="$DBUS_LIBS -L${dbus_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $DBUS_LIBS"
	AC_CHECK_LIB(dbus-1, dbus_error_init, DBUS_LIBS="$DBUS_LIBS -ldbus-1", dbus_found=no)
	AC_CHECK_LIB(dbus-1, dbus_message_iter_get_basic, dummy=yes, dbus_found=no)

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(DBUS_CFLAGS)
	AC_SUBST(DBUS_LIBS)
])

AC_DEFUN([AC_PATH_FUSE], [
	fuse_prefix=${prefix}

	AC_ARG_WITH(fuse, AC_HELP_STRING([--with-fuse=DIR], [FUSE library is installed in DIR]), [
		if (test "${withval}" != "yes"); then
			fuse_prefix=${withval}
		fi
	])

	ac_save_CPPFLAGS=$CPPFLAGS
	ac_save_LDFLAGS=$LDFLAGS

	FUSE_CFLAGS="-D_FILE_OFFSET_BITS=64"
	test -d "${fuse_prefix}/include" && FUSE_CFLAGS="$FUSE_CFLAGS -I${fuse_prefix}/include"

	CPPFLAGS="$CPPFLAGS $FUSE_CFLAGS"
	AC_CHECK_HEADER(fuse.h, fuse_found=yes, fuse_found=no)

	FUSE_LIBS=""
	if (test "${prefix}" = "${fuse_prefix}"); then
		test -d "${libdir}" && FUSE_LIBS="$FUSE_LIBS -L${libdir}"
	else
		test -d "${fuse_prefix}/lib64" && FUSE_LIBS="$FUSE_LIBS -L${fuse_prefix}/lib64"
		test -d "${fuse_prefix}/lib" && FUSE_LIBS="$FUSE_LIBS -L${fuse_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $FUSE_LIBS"
	AC_CHECK_LIB(fuse, fuse_main, FUSE_LIBS="$FUSE_LIBS -lfuse", fuse_found=no)

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(FUSE_CFLAGS)
	AC_SUBST(FUSE_LIBS)
])

AC_DEFUN([AC_PATH_ALSA], [
	alsa_prefix=${prefix}

	AC_ARG_WITH(alsa, AC_HELP_STRING([--with-alsa=DIR], [ALSA library is installed in DIR]), [
		if (test "${withval}" != "yes"); then
			alsa_prefix=${withval}
		fi
	])

	ac_save_CPPFLAGS=$CPPFLAGS
	ac_save_LDFLAGS=$LDFLAGS

	AC_CHECK_HEADER(sys/soundcard.h, AC_DEFINE(HAVE_SYS_SOUNDCARD_H, 1, [Define to 1 if you have the <sys/soundcard.h> header file.]))

	ALSA_CFLAGS=""
	test -d "${alsa_prefix}/include" && ALSA_CFLAGS="$ALSA_CFLAGS -I${alsa_prefix}/include"

	CPPFLAGS="$CPPFLAGS $ALSA_CFLAGS -include alsa/asoundlib.h"
	AC_CHECK_HEADER(alsa/pcm_ioplug.h, alsa_found=yes, alsa_found=no)

	ALSA_LIBS=""
	if (test "${prefix}" = "${alsa_prefix}"); then
		test -d "${libdir}" && ALSA_LIBS="$ALSA_LIBS -L${libdir}"
	else
		test -d "${alsa_prefix}/lib64" && ALSA_LIBS="$ALSA_LIBS -L${alsa_prefix}/lib64"
		test -d "${alsa_prefix}/lib" && ALSA_LIBS="$ALSA_LIBS -L${alsa_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $ALSA_LIBS"
	AC_CHECK_LIB(asound, snd_pcm_ioplug_create, ALSA_LIBS="$ALSA_LIBS -lasound", alsa_found=no)

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(ALSA_CFLAGS)
	AC_SUBST(ALSA_LIBS)
])

AC_DEFUN([AC_PATH_USB], [
	usb_prefix=${prefix}

	AC_ARG_WITH(usb, AC_HELP_STRING([--with-usb=DIR], [USB library is installed in DIR]), [
		if (test "$withval" != "yes"); then
			usb_prefix=${withval}
		fi
	])

	ac_save_CPPFLAGS=$CPPFLAGS
	ac_save_LDFLAGS=$LDFLAGS

	USB_CFLAGS=""
	test -d "${usb_prefix}/include" && USB_CFLAGS="$USB_CFLAGS -I${usb_prefix}/include"

	CPPFLAGS="$CPPFLAGS $USB_CFLAGS"
	AC_CHECK_HEADER(usb.h, usb_found=yes, usb_found=no)

	USB_LIBS=""
	if (test "${prefix}" = "${usb_prefix}"); then
		test -d "${libdir}" && USB_LIBS="$USB_LIBS -L${libdir}"
	else
		test -d "${usb_prefix}/lib64" && USB_LIBS="$USB_LIBS -L${usb_prefix}/lib64"
		test -d "${usb_prefix}/lib" && USB_LIBS="$USB_LIBS -L${usb_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $USB_LIBS"
	AC_CHECK_LIB(usb, usb_open, USB_LIBS="$USB_LIBS -lusb", usb_found=no)
	AC_CHECK_LIB(usb, usb_get_busses, dummy=yes, AC_DEFINE(NEED_USB_GET_BUSSES, 1, [Define to 1 if you need the usb_get_busses() function.]))
	AC_CHECK_LIB(usb, usb_interrupt_read, dummy=yes, AC_DEFINE(NEED_USB_INTERRUPT_READ, 1, [Define to 1 if you need the usb_interrupt_read() function.]))

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(USB_CFLAGS)
	AC_SUBST(USB_LIBS)
])

AC_DEFUN([AC_ARG_BLUEZ], [
	fortify_enable=yes
	debug_enable=no
	pie_enable=no
	dbus_enable=${dbus_found}
	obex_enable=${openobex_found}
	fuse_enable=no
	alsa_enable=no
	test_enable=no
	cups_enable=no
	pcmcia_enable=no
	initscripts_enable=no
	bccmd_enable=no
	avctrl_enable=no
	hid2hci_enable=${usb_found}
	dfutool_enable=no
	bcm203x_enable=no
	bluepin_enable=yes

	AC_ARG_ENABLE(fortify, AC_HELP_STRING([--disable-fortify], [disable compile time buffer checks]), [
		fortify_enable=${enableval}
	])

	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable compiling with debugging information]), [
		debug_enable=${enableval}
	])

	AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie], [enable position independent executables flag]), [
		pie_enable=${enableval}
	])

	AC_ARG_ENABLE(all, AC_HELP_STRING([--enable-all], [enable all extra options below]), [
		dbus_enable=${enableval}
		obex_enable=${enableval}
		fuse_enable=${enableval}
		alsa_enable=${enableval}
		test_enable=${enableval}
		cups_enable=${enableval}
		pcmcia_enable=${enableval}
		initscripts_enable=${enableval}
		bccmd_enable=${enableval}
		avctrl_enable=${enableval}
		hid2hci_enable=${enableval}
		dfutool_enable=${enableval}
		bcm203x_enable=${enableval}
		bluepin_enable=${enableval}
	])

	AC_ARG_ENABLE(dbus, AC_HELP_STRING([--enable-dbus], [enable D-BUS support]), [
		dbus_enable=${enableval}
	])

	AC_ARG_ENABLE(obex, AC_HELP_STRING([--enable-obex], [enable OBEX support]), [
		obex_enable=${enableval}
	])

	AC_ARG_ENABLE(fuse, AC_HELP_STRING([--enable-fuse], [enable FUSE support]), [
		fuse_enable=${enableval}
	])

	AC_ARG_ENABLE(alsa, AC_HELP_STRING([--enable-alsa], [enable ALSA support]), [
		alsa_enable=${enableval}
	])

	AC_ARG_ENABLE(test, AC_HELP_STRING([--enable-test], [install test programs]), [
		test_enable=${enableval}
	])

	AC_ARG_ENABLE(cups, AC_HELP_STRING([--enable-cups], [install CUPS backend support]), [
		cups_enable=${enableval}
	])

	AC_ARG_ENABLE(pcmcia, AC_HELP_STRING([--enable-pcmcia], [install PCMCIA configuration files ]), [
		pcmcia_enable=${enableval}
	])

	AC_ARG_ENABLE(initscripts, AC_HELP_STRING([--enable-initscripts], [install Bluetooth boot scripts]), [
		initscripts_enable=${enableval}
	])

	AC_ARG_ENABLE(bccmd, AC_HELP_STRING([--enable-bccmd], [install BCCMD interface utility]), [
		bccmd_enable=${enableval}
	])

	AC_ARG_ENABLE(avctrl, AC_HELP_STRING([--enable-avctrl], [install Audio/Video control utility]), [
		avctrl_enable=${enableval}
	])

	AC_ARG_ENABLE(hid2hci, AC_HELP_STRING([--enable-hid2hci], [install HID mode switching utility]), [
		hid2hci_enable=${enableval}
	])

	AC_ARG_ENABLE(dfutool, AC_HELP_STRING([--enable-dfutool], [install DFU firmware upgrade utility]), [
		dfutool_enable=${enableval}
	])

	AC_ARG_ENABLE(bcm203x, AC_HELP_STRING([--enable-bcm203x], [install Broadcom 203x firmware loader]), [
		bcm203x_enable=${enableval}
	])

	AC_ARG_ENABLE(bluepin, AC_HELP_STRING([--enable-bluepin], [install Python based PIN helper]), [
		bluepin_enable=${enableval}
	])

	if (test "${fortify_enable}" = "yes"); then
		CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
	fi

	if (test "${debug_enable}" = "yes" && test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi

	if (test "${pie_enable}" = "yes" && test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi

	AM_CONDITIONAL(DBUS, test "${dbus_enable}" = "yes" && test "${dbus_found}" = "yes")
	AM_CONDITIONAL(OBEX, test "${obex_enable}" = "yes" && test "${openobex_found}" = "yes")
	AM_CONDITIONAL(FUSE, test "${fuse_enable}" = "yes" && test "${openobex_found}" = "yes" && test "${fuse_found}" = "yes")
	AM_CONDITIONAL(ALSA, test "${alsa_enable}" = "yes" && test "${alsa_found}" = "yes")
	AM_CONDITIONAL(TEST, test "${test_enable}" = "yes")
	AM_CONDITIONAL(CUPS, test "${cups_enable}" = "yes")
	AM_CONDITIONAL(PCMCIA, test "${pcmcia_enable}" = "yes")
	AM_CONDITIONAL(INITSCRIPTS, test "${initscripts_enable}" = "yes")
	AM_CONDITIONAL(BCCMD, test "${bccmd_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(AVCTRL, test "${avctrl_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(HID2HCI, test "${hid2hci_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(DFUTOOL, test "${dfutool_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(BCM203X, test "${bcm203x_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(BLUEPIN, test "${bluepin_enable}" = "yes")
])
