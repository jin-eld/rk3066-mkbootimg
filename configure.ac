#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.66])
AC_INIT([mkbootimg], [1.0], [jin@mediatomb.cc])
AC_CONFIG_AUX_DIR(configure_aux)
AC_CONFIG_SRCDIR([src/bootimg.h])
AC_CONFIG_HEADERS([autoconfig.h])
AM_INIT_AUTOMAKE([1.10 -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

if test "x${prefix}" = "xNONE"; then
    prefix="${ac_default_prefix}"
fi

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strerror strtoul])

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([LIBSSL], [libssl],
    [
        AC_DEFINE([HAVE_LIBSSL], [1], [libssl is available])
    ],
    [
        AC_MSG_ERROR([$LIBSSL_PKG_ERRORS])
    ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
