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

AC_DEFUN([AC_PROG_CC_ASAN], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=address],
						ac_cv_prog_cc_asan, [
		echo 'void f(){}' > asan.c
		if test -z "`${CC-cc} -fsanitize=address -c asan.c 2>&1`"; then
			ac_cv_prog_cc_asan=yes
		else
			ac_cv_prog_cc_asan=no
		fi
		rm -rf asan*
       ])
])

AC_DEFUN([AC_PROG_CC_LSAN], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=leak],
						ac_cv_prog_cc_lsan, [
		echo 'void f(){}' > lsan.c
		if test -z "`${CC-cc} -fsanitize=leak -c lsan.c 2>&1`"; then
			ac_cv_prog_cc_lsan=yes
		else
			ac_cv_prog_cc_lsan=no
		fi
		rm -rf lsan*
	])
])

AC_DEFUN([AC_PROG_CC_UBSAN], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fsanitize=undefined],
						ac_cv_prog_cc_ubsan, [
		echo 'void f(){}' > ubsan.c
		if test -z "`${CC-cc} -fsanitize=undefined -c ubsan.c 2>&1`"; then
			ac_cv_prog_cc_ubsan=yes
		else
			ac_cv_prog_cc_ubsan=no
		fi
		rm -rf ubsan*
	])
])

AC_DEFUN([COMPILER_FLAGS], [
	with_cflags=""
	if (test "$USE_MAINTAINER_MODE" = "yes"); then
		with_cflags="$with_cflags -Wall -Werror -Wextra"
		with_cflags="$with_cflags -Wno-unused-parameter"
		with_cflags="$with_cflags -Wno-missing-field-initializers"
		with_cflags="$with_cflags -Wdeclaration-after-statement"
		with_cflags="$with_cflags -Wmissing-declarations"
		with_cflags="$with_cflags -Wredundant-decls"
		with_cflags="$with_cflags -Wcast-align"
		with_cflags="$with_cflags -Wswitch-enum"
		with_cflags="$with_cflags -Wformat -Wformat-security"
		with_cflags="$with_cflags -DG_DISABLE_DEPRECATED"
		with_cflags="$with_cflags -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_28"
		with_cflags="$with_cflags -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32"
	fi
	AC_SUBST([WARNING_CFLAGS], $with_cflags)
])

AC_DEFUN([MISC_FLAGS], [
	misc_cflags=""
	misc_ldflags=""
	AC_ARG_ENABLE(optimization, AS_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
		if (test "${enableval}" = "no"); then
			misc_cflags="$misc_cflags -O0"
		fi
	])
	AC_ARG_ENABLE(asan, AS_HELP_STRING([--enable-asan],
			[enable linking with address sanitizer]), [
		save_LIBS=$LIBS
		AC_CHECK_LIB(asan, _init)
		LIBS=$save_LIBS
		if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_asan__init}" = "yes" &&
				test "${ac_cv_prog_cc_asan}" = "yes"); then
			misc_cflags="$misc_cflags -fsanitize=address";
			misc_ldflags="$misc_ldflags -fsanitize=address"
			AC_SUBST([ASAN_LIB], ${ac_cv_lib_asan__init})
		fi
	])
	AC_ARG_ENABLE(lsan, AS_HELP_STRING([--enable-lsan],
			[enable linking with address sanitizer]), [
		save_LIBS=$LIBS
		AC_CHECK_LIB(lsan, _init)
		LIBS=$save_LIBS
		if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_lsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_lsan}" = "yes"); then
			misc_cflags="$misc_cflags -fsanitize=leak";
			misc_ldflags="$misc_ldflags -fsanitize=leak"
			AC_SUBST([ASAN_LIB], ${ac_cv_lib_lsan__init})
		fi
	])
	AC_ARG_ENABLE(ubsan, AS_HELP_STRING([--enable-ubsan],
			[enable linking with address sanitizer]), [
		save_LIBS=$LIBS
		AC_CHECK_LIB(ubsan, _init)
		LIBS=$save_LIBS
		if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_ubsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_ubsan}" = "yes"); then
			misc_cflags="$misc_cflags -fsanitize=undefined";
			misc_ldflags="$misc_ldflags -fsanitize=undefined";
		fi
	])
	AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
		if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
			misc_cflags="$misc_cflags -g"
		fi
	])
	AC_ARG_ENABLE(pie, AS_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
		if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
			misc_cflags="$misc_cflags -fPIC"
			misc_ldflags="$misc_ldflags -pie -Wl,-z,now"
		fi
	])
	if (test "$enable_coverage" = "yes"); then
		misc_cflags="$misc_cflags --coverage"
		misc_ldflags="$misc_ldflags --coverage"
	fi
	AC_SUBST([MISC_CFLAGS], $misc_cflags)
	AC_SUBST([MISC_LDFLAGS], $misc_ldflags)
])
