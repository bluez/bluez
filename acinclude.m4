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
		bluez_includes=$withval/include
		bluez_libraries=$withval/lib
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
