#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dhcpsnoopingd],[0.2],[michael-dev@fami-braun.de])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_LANG(C)
GCC_STACK_PROTECTOR

PKG_CHECK_MODULES(LIBNL, libnl-3.0)
AC_SUBST(LIBNL_CFLAGS)
AC_SUBST(LIBNL_LIBS)

PKG_CHECK_MODULES(LIBNLGENL, libnl-genl-3.0)
AC_SUBST(LIBNLGENL_CFLAGS)
AC_SUBST(LIBNLGENL_LIBS)

PKG_CHECK_MODULES(LIBNLNF, libnl-nf-3.0)
AC_SUBST(LIBNLNF_CFLAGS)
AC_SUBST(LIBNLNF_LIBS)

PKG_CHECK_MODULES(LIBNLROUTE, libnl-route-3.0)
AC_SUBST(LIBNLROUTE_CFLAGS)
AC_SUBST(LIBNLROUTE_LIBS)

#check if we want a debug build
AC_ARG_ENABLE(debug, [  --enable-debug          enable debug output], [
	if test "x$enableval" != "xno"; then
		AC_DEFINE([DEBUG], , [Enable debug output])
	fi
])

#check if version is given
AC_ARG_WITH(rev, [  --with-rev          enable rev output], [
	if test "x$withval" != "x"; then
		AC_DEFINE_UNQUOTED([REV],"$withval",[revision])
	fi
])

AC_ARG_WITH([nflog-group],
     	  [AS_HELP_STRING([--with-nflog-group], [nflog group id, defaults to 3])],
	  AC_DEFINE_UNQUOTED([NFLOG_GROUP], $withval , [nflog group]),
	  AC_DEFINE([NFLOG_GROUP], 3 , [nflog group]))

# Checks for header files.
AC_HEADER_STDC

# Checks for library functions.
AC_FUNC_MEMCMP

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

