dnl
dnl  $Id$
dnl

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
	AC_PREFIX_DEFAULT(/usr)

	CFLAGS="-Wall -O2"

	if (test "${prefix}" = "NONE"); then
		dnl no prefix and no sysconfdir, so default to /etc
		if (test "$sysconfdir" = '${prefix}/etc'); then
			AC_SUBST([sysconfdir], ['/etc'])
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

	AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}", [Directory for the configuration files])
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
	AC_CHECK_HEADER(bluetooth/bluetooth.h,, AC_MSG_ERROR(Bluetooth header files not found))

	BLUEZ_LIBS=""
	if (test "${prefix}" = "${bluez_prefix}"); then
		test -d "${libdir}" && BLUEZ_LIBS="$BLUEZ_LIBS -L${libdir}"
	else
		test -d "${bluez_prefix}/lib64" && BLUEZ_LIBS="$BLUEZ_LIBS -L${bluez_prefix}/lib64"
		test -d "${bluez_prefix}/lib" && BLUEZ_LIBS="$BLUEZ_LIBS -L${bluez_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $BLUEZ_LIBS"
	AC_CHECK_LIB(bluetooth, hci_open_dev, BLUEZ_LIBS="$BLUEZ_LIBS -lbluetooth", AC_MSG_ERROR(Bluetooth library not found))
	AC_CHECK_LIB(sdp, sdp_connect, BLUEZ_LIBS="$BLUEZ_LIBS -lsdp")

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(BLUEZ_CFLAGS)
	AC_SUBST(BLUEZ_LIBS)
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

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(DBUS_CFLAGS)
	AC_SUBST(DBUS_LIBS)
])

AC_DEFUN([AC_ARG_BLUEZ], [
	pie_enable=no
	debug_enable=no
	dbus_enable=${dbus_found}
	test_enable=no
	cups_enable=no
	pcmcia_enable=no
	initscripts_enable=no
	bluepin_enable=yes
	hid2hci_enable=${usb_found}
	bcm203x_enable=no

	AC_ARG_ENABLE(all, AC_HELP_STRING([--enable-all], [enable all extra options]), [
		pie_enable=${enableval}
		debug_enable=${enableval}
		dbus_enable=${enableval}
		test_enable=${enableval}
		cups_enable=${enableval}
		pcmcia_enable=${enableval}
		initscripts_enable=${enableval}
		bluepin_enable=${enableval}
		hid2hci_enable=${enableval}
		bcm203x_enable=${enableval}
	])

	AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie], [enable position independent executables option]), [
		pie_enable=${enableval}
	])

	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable compiling with debugging information]), [
		debug_enable=${enableval}
	])

	AC_ARG_ENABLE(dbus, AC_HELP_STRING([--enable-dbus], [enable D-BUS support]), [
		dbus_enable=${enableval}
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

	AC_ARG_ENABLE(bluepin, AC_HELP_STRING([--enable-bluepin], [install Python based PIN helper utility]), [
		bluepin_enable=${enableval}
	])

	AC_ARG_ENABLE(hid2hci, AC_HELP_STRING([--enable-hid2hci], [install HID mode switching utility]), [
		hid2hci_enable=${enableval}
	])

	AC_ARG_ENABLE(bcm203x, AC_HELP_STRING([--enable-bcm203x], [install Broadcom 203x firmware loader]), [
		bcm203x_enable=${enableval}
	])

	if (test "${pie_enable}" = "yes" && test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi

	if (test "${debug_enable}" = "yes" && test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi

	AM_CONDITIONAL(DBUS, test "${dbus_enable}" = "yes" && test "${dbus_found}" = "yes")
	AM_CONDITIONAL(TEST, test "${test_enable}" = "yes")
	AM_CONDITIONAL(CUPS, test "${cups_enable}" = "yes")
	AM_CONDITIONAL(PCMCIA, test "${pcmcia_enable}" = "yes")
	AM_CONDITIONAL(INITSCRIPTS, test "${initscripts_enable}" = "yes")
	AM_CONDITIONAL(BLUEPIN, test "${bluepin_enable}" = "yes")
	AM_CONDITIONAL(HID2HCI, test "${hid2hci_enable}" = "yes" && test "${usb_found}" = "yes")
	AM_CONDITIONAL(BCM203X, test "${bcm203x_enable}" = "yes" && test "${usb_found}" = "yes")
])
