#
#  configure.ac
#
#  Author: Johnny Mnemonic <johnny@themnemonic.org>
#
#  Copyright (C) 2002 Johnny Mnemonic
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

dnl without this order in this file, autoconf will not work!
dnl the argument is a source file out of your sources.
AC_INIT(ChangeLog)

dnl put any platform specific stuff here
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(netcat,0.1.0)
AC_PREREQ(2.52)

dnl without this order in this file, automake will be confused!
AM_CONFIG_HEADER(config.h)

dnl checks for programs.
dnl first check for c compiler
AC_PROG_CC
AC_PROG_CPP

dnl check for pod2man since we need it for building documentation
dnl although it's not mandatory
dnl AC_CHECK_PROG(netcat_pod2man, pod2man, yes, no)

AC_PATH_PROGS(PERL, perl5 perl, no)
AC_PATH_PROG(POD2MAN, pod2man, no)

dnl create only shared libtool-libraries
AC_ENABLE_SHARED(yes)
 
dnl set the following to yes, if you want to create static
dnl libtool-libraries
AC_ENABLE_STATIC(no)

dnl create a working libtool-script
if test -z "$LIBTOOL"; then
  AC_LANG_SAVE
  AC_LANG_C
  AC_LIBTOOL_DLOPEN
  AM_PROG_LIBTOOL
  dnl LIBTOOL="$LIBTOOL --silent"
  dnl AC_SUBST(LIBTOOL)
  AC_LANG_RESTORE
  LIBTOOL_SHELL='/bin/sh ./libtool'
else
  LIBTOOL_SHELL=$LIBTOOL
fi
AC_PROG_LIBTOOL

dnl add --with-extra-includes and --with-extra-libs switch to ./configure
dnl
all_libraries="$all_libraries $USER_LDFLAGS"
all_includes="$all_includes $USER_INCLUDES"
AC_SUBST(all_includes)
AC_SUBST(all_libraries)

AC_SUBST(AUTODIRS)

dnl check for the resolver function
AC_CHECK_FUNC(res_init, , AC_CHECK_LIB(resolv, res_init, [LIBRESOLV="-lresolv"], , $LIBSOCKET))

AC_CHECK_FUNCS(srandom random)
if test $ac_cv_func_srandom = no; then
  # let's try with the older srand/rand functions
  AC_CHECK_FUNCS(srand rand)
fi

dnl *********************************************************************
dnl ** CONFIGURE SWITCHES ***********************************************
dnl *********************************************************************

AC_ARG_ENABLE(debug,
[  --enable-debug          enable use of Memory Debug (default: no)],
	debug=$enableval, debug=no)

AM_CONDITIONAL(DO_DEBUG, test "x$debug" = "xyes")


dnl add here all your Makefiles. These will be created by configure.
dnl
AC_CONFIG_FILES(Makefile doc/Makefile src/Makefile)

dnl this one is special, it needs the executable flag
dnl
AC_CONFIG_FILES(doc/texi2pod.pl, chmod +x doc/texi2pod.pl)
AC_OUTPUT
