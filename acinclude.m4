dnl
dnl  $Id$
dnl

AC_DEFUN(AC_PREFIX_BLUEZ, [
	AC_PREFIX_DEFAULT(/usr)

	if test "$prefix" = "NONE"; then
		dnl no prefix and no sysconfdir, so default to /etc
		if test "$sysconfdir" = '${prefix}/etc'; then
			AC_SUBST([sysconfdir], ['/etc'])
		fi

		dnl no prefix and no mandir, so use ${prefix}/share/man as default
		if test "$mandir" = '${prefix}/man'; then
			AC_SUBST([mandir], ['${prefix}/share/man'])
		fi
	fi
])

AC_DEFUN(AC_PATH_BLUEZ, [
	AC_ARG_WITH(bluez, [  --with-bluez=DIR        BlueZ library is installed in DIR], [
		if (test "$withval" = "yes"); then
			bluez_includes=/usr/include
			bluez_libraries=/usr/lib
		else
			bluez_includes=$withval/include
			bluez_libraries=$withval/lib
		fi
	])

	BLUEZ_INCLUDES=""
	BLUEZ_LDFLAGS=""
	BLUEZ_LIBS=""

	ac_save_CFLAGS=$CFLAGS
	test -n "$bluez_includes" && CFLAGS="$CFLAGS -I$bluez_includes"

	ac_save_LDFLAGS=$LDFLAGS
	test -n "$bluez_libraries" && LDFLAGS="$LDFLAGS -L$bluez_libraries"

	AC_CHECK_HEADER(bluetooth/bluetooth.h,,
		AC_MSG_ERROR(Bluetooth header files not found))

	AC_CHECK_LIB(bluetooth, hci_open_dev,
		BLUEZ_LIBS="$BLUEZ_LIBS -lbluetooth",
		AC_MSG_ERROR(Bluetooth library not found))

	AC_CHECK_LIB(sdp, sdp_connect,
		BLUEZ_LIBS="$BLUEZ_LIBS -lsdp")

	CFLAGS=$ac_save_CFLAGS
	test -n "$bluez_includes" && BLUEZ_INCLUDES="-I$bluez_includes"

	LDFLAGS=$ac_save_LDFLAGS
	test -n "$bluez_libraries" && BLUEZ_LDFLAGS="-L$bluez_libraries"
	test -n "$bluez_libraries" && BLUEZ_LIBS="-L$bluez_libraries $BLUEZ_LIBS"

	AC_SUBST(BLUEZ_INCLUDES)
	AC_SUBST(BLUEZ_LDFLAGS)
	AC_SUBST(BLUEZ_LIBS)
])

AC_DEFUN(AC_PATH_DBUS, [
	AC_ARG_ENABLE(dbus, [  --enable-dbus           enable D-BUS support],
		dbus_enable=$enableval,
		dbus_enable=no
	)

	AC_ARG_WITH(dbus, [  --with-dbus=DIR         D-BUS library is installed in DIR], [
		if (test "$withval" = "yes"); then
			dbus_includes=/usr/include
			dbus_libraries=/usr/lib
		else
			dbus_includes=$withval/include
			dbus_libraries=$withval/lib
		fi
		dbus_enable=yes
	])

	DBUS_INCLUDES=""
	DBUS_LDFLAGS=""
	DBUS_LIBS=""

	ac_save_CFLAGS=$CFLAGS
	if test -n "$dbus_includes"; then 
		CFLAGS="$CFLAGS -I$dbus_includes -I$dbus_includes/dbus-1.0"
	else
		CFLAGS="$CFLAGS -I/usr/include/dbus-1.0"
	fi
	CFLAGS="$CFLAGS -DDBUS_API_SUBJECT_TO_CHANGE"

	ac_save_LDFLAGS=$LDFLAGS
	if test -n "$dbus_libraries"; then
		CFLAGS="$CFLAGS -I$dbus_libraries/dbus-1.0/include"
		LDFLAGS="$LDFLAGS -L$dbus_libraries"
	else
		CFLAGS="$CFLAGS -I/usr/lib/dbus-1.0/include"
	fi

	if test "$dbus_enable" = "yes"; then
		AC_CHECK_HEADER(dbus/dbus.h,,
			dbus_enable=no)

		AC_CHECK_LIB(dbus-1, dbus_error_init,
			DBUS_LIBS="$DBUS_LIBS -ldbus-1",
			dbus_enable=no)
	fi

	CFLAGS=$ac_save_CFLAGS
	if test -n "$dbus_includes"; then
		DBUS_INCLUDES="-I$dbus_includes -I$dbus_includes/dbus-1.0"
	else
		DBUS_INCLUDES="-I/usr/include/dbus-1.0"
	fi

	LDFLAGS=$ac_save_LDFLAGS
	if test -n "$dbus_libraries"; then
		DBUS_INCLUDES="$DBUS_INCLUDES -I$dbus_libraries/dbus-1.0/include"
		DBUS_LDFLAGS="-L$dbus_libraries"
		DBUS_LIBS="-L$dbus_libraries $DBUS_LIBS"
	else
		DBUS_INCLUDES="$DBUS_INCLUDES -I/usr/lib/dbus-1.0/include"
	fi

	AC_SUBST(DBUS_INCLUDES)
	AC_SUBST(DBUS_LDFLAGS)
	AC_SUBST(DBUS_LIBS)

	AM_CONDITIONAL(DBUS, test "$dbus_enable" = "yes")
])
