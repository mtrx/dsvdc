AC_INIT([dSvDC], [0.0.0], [michael@tross.org], [digitalStrom Virtual Device], [http://digitalstrom.tross.org/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Wall no-define])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])
AC_CHECK_HEADER([utlist.h], [],
        [AC_MSG_ERROR([required header utlist.h not found])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strdup])

dnl libdsvdc
PKG_CHECK_MODULES([LIBDSVDC], [libdsvdc])
AC_SUBST(LIBDSVDC_CFLAGS)
AC_SUBST(LIBDSVDC_LIBS)

dnl libdsuid
PKG_CHECK_MODULES([LIBDSUID], [libdsuid])
AC_SUBST(LIBDSUID_CFLAGS)
AC_SUBST(LIBDSUID_LIBS)

dnl libjson
PKG_CHECK_MODULES([JSONC], [json])
AC_SUBST(JSONC_CFLAGS)
AC_SUBST(JSONC_LIBS)

dnl libconfig
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])
AC_SUBST(LIBCONFIG_CFLAGS)
AC_SUBST(LIBCONFIG_LIBS)

dnl curl
PKG_CHECK_MODULES([CURL], [libcurl])
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

