dnl Add directory level
AC_DEFUN( AC_ADD_DIRLEVEL,
[
    for i in $1; do
	eval o=\$$i
	o=`echo $o | sed 's#.\.\./#&../#g'`
	eval $i=\$o	
    done
])

dnl Test file
AC_DEFUN( AC_TEST_FILE,
[
    if test -f $1; then
	ifelse([$2], , :,[$2])
    else
	ifelse([$3], , :,[$3])
    fi
])

dnl Test dir
AC_DEFUN( AC_TEST_DIR,
[
    if test -d $1; then
	ifelse([$2], , :,[$2])
    else
	ifelse([$3], , :,[$3])
    fi
])

dnl Test files
AC_DEFUN( AC_TEST_FILES,
[
    ac_file_found=yes
    for f in $1; do
	if test ! -f $2/$f; then
    	   ac_file_found=no
	   break;
	fi
    done

    if test "$ac_file_found" = "yes" ; then
	ifelse([$3], , :,[$3])
    else
	ifelse([$4], , :,[$4])
    fi
])

dnl Search for headers, add path to CPPFLAGS if found 
AC_DEFUN( AC_SEARCH_HEADERS, 
[
    AC_MSG_CHECKING("for $1") 
    ac_hdr_found=no
    for p in $2; do
	AC_TEST_FILES($1, $p, 
	    [ 
     	       ac_hdr_found=yes
	       break
	    ]
	)
    done 
    if test "$ac_hdr_found" = "yes" ; then
	CPPFLAGS="$CPPFLAGS -I$p"
        AC_MSG_RESULT( [($p) yes] ) 
	ifelse([$3], , :,[$3])
    else
        AC_MSG_RESULT("no") 
	ifelse([$4], , :,[$4])
    fi
])

dnl Search for library, add path to LIBS if found 
AC_DEFUN( AC_SEARCH_LIB, 
[
    AC_MSG_CHECKING("for lib$1")

    ac_save_LDFLAGS=$LDFLAGS

    ac_lib_found=no
    for p in $3; do
	test -d $p || continue;

	# Check for libtool library
	if test -f $p/lib$1.la; then
		path=$p/.libs
	else
		path=$p
	fi
	
	LDFLAGS="-L$path -l$1"
	AC_TRY_LINK_FUNC($2,
	    [ 
	       LIBS="$LIBS -L$p -l$1"
     	       ac_lib_found=yes
	       break
	    ]
	)
    done 
    if test "$ac_lib_found" = "yes" ; then
        AC_MSG_RESULT( [($p) yes] ) 
	ifelse([$4], , :,[$4])
    else
        AC_MSG_RESULT("no") 
	ifelse([$5], , :,[$5])
    fi

    LDFLAGS=$ac_save_LDFLAGS
])
