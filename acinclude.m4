dnl
dnl  $Id$
dnl

AC_DEFUN(AC_PATH_BLUEZ, [
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
