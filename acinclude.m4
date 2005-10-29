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

AC_DEFUN([AC_ARG_BLUEZ], [
	fortify_enable=yes
	debug_enable=no

	AC_ARG_ENABLE(fortify, AC_HELP_STRING([--disable-fortify], [disable compile time buffer checks]), [
		fortify_enable=${enableval}
	])

	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable compiling with debugging information]), [
		debug_enable=${enableval}
	])

	if (test "${fortify_enable}" = "yes"); then
		CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2"
	fi

	if (test "${debug_enable}" = "yes" && test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])
