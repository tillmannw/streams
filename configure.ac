# -*- mode: m4; -*-
# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# $Id$

AC_PREREQ(2.59)
AC_INIT([streams], [0.1.0], [tillmann.werner@gmx.de])
AM_INIT_AUTOMAKE([streams], [0.1.0])
AC_REVISION([$Id$])

AC_PREFIX_DEFAULT(/opt/streams)
AM_CONFIG_HEADER([config.h])
# AM_MAINTAINER_MODE

AC_CANONICAL_HOST
AC_C_CONST
AC_C_BIGENDIAN

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

AC_TYPE_SIZE_T

dnl **************************************************
dnl * debug code & debug messages                    *
dnl **************************************************

AC_MSG_CHECKING(whether debug code generation should be enabled)
AC_ARG_ENABLE([debug],
		[AS_HELP_STRING(--enable-debug, enable debug code generation [[default=no]])],
		[enable_debug=${enableval}], [enable_debug="no"])
if test x"$enable_debug" = "xyes"; then
	echo "--- enabling debug codee"
	AC_DEFINE([DEBUG], 1, [enable debug code generation])
fi
AC_MSG_RESULT($enable_debug)


dnl **************************************************
dnl * pcap                                           *
dnl **************************************************

AC_ARG_WITH(libpcap_includes,
	[  --with-libpcap-includes=DIR     libpcap include directory],
	[with_libpcap_includes="$withval"],[with_libpcap_includes=no])

AC_ARG_WITH(libpcap_libraries,
	[  --with-libpcap-libraries=DIR    libpcap library directory],
	[with_libpcap_libraries="$withval"],[with_libpcap_libraries=no])

if test "$with_libpcap_includes" != "no"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
fi
HPCAP=""
AC_CHECK_HEADER(pcap.h,, HPCAP="no")
if test "$HPCAP" = "no"; then
	echo "   Error - libpcap headers not found."
	exit 1
fi

if test "$with_libpcap_libraries" != "no"; then
	LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
fi
LPCAP=""
AC_CHECK_LIB(pcap, pcap_datalink,, LPCAP="no")
if test "$LPCAP" = "no"; then
	echo "   Error - libpcap library not found."
	exit 1
fi


dnl **************************************************
dnl * readline                                       *
dnl **************************************************

AC_ARG_WITH(libreadline_includes,
	[  --with-libreadline-includes=DIR     libreadline include directory],
	[with_libreadline_includes="$withval"],[with_libreadline_includes=no])

AC_ARG_WITH(libreadline_libraries,
	[  --with-libreadline-libraries=DIR    libreadline library directory],
	[with_libreadline_libraries="$withval"],[with_libreadline_libraries=no])

if test "$with_libreadline_includes" != "no"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libreadline_includes}"
fi
HPCAP=""
AC_CHECK_HEADER(readline.h,, HPCAP="no")
if test "$HPCAP" = "no"; then
	echo "   Error - libreadline headers not found."
	exit 1
fi

if test "$with_libreadline_libraries" != "no"; then
	LDFLAGS="${LDFLAGS}  -L${with_libreadline_libraries}"
fi
LPCAP=""
AC_CHECK_LIB(readline, readline,, LPCAP="no")
if test "$LPCAP" = "no"; then
	echo "   Error - libreadline library not found."
	exit 1
fi


AC_DEFUN([AC_DEFINE_DIR], [
  prefix_NONE=
  exec_prefix_NONE=
  test "x$prefix" = xNONE && prefix_NONE=yes && prefix=$ac_default_prefix
  test "x$exec_prefix" = xNONE && exec_prefix_NONE=yes && exec_prefix=$prefix
dnl In Autoconf 2.60, ${datadir} refers to ${datarootdir}, which in turn
dnl refers to ${prefix}.  Thus we have to use `eval' twice.
  eval ac_define_dir="\"[$]$2\""
  eval ac_define_dir="\"$ac_define_dir\""
  AC_SUBST($1, "$ac_define_dir")
  AC_DEFINE_UNQUOTED($1, "$ac_define_dir", [$3])
  test "$prefix_NONE" && prefix=NONE
  test "$exec_prefix_NONE" && exec_prefix=NONE
])

AC_DEFINE_DIR(PREFIX, prefix, [default working directory])

AC_CONFIG_FILES([Makefile
		src/Makefile
		])

AC_OUTPUT
