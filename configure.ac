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

AM_INIT_AUTOMAKE(netcat,0.2.2)
AC_PREREQ(2.52)

dnl without this order in this file, automake will be confused!
AM_CONFIG_HEADER(config.h)

dnl checks for programs.
dnl first check for c compiler
AC_PROG_CC
AC_PROG_CPP
AC_PROG_RANLIB

dnl check for pod2man since we need it for building documentation
dnl although it's not mandatory
dnl AC_CHECK_PROG(netcat_pod2man, pod2man, yes, no)

AC_PATH_PROGS(PERL, perl5 perl, no)
AC_PATH_PROG(POD2MAN, pod2man, no)

dnl add --with-extra-includes and --with-extra-libs switch to ./configure
dnl
all_libraries="$all_libraries $USER_LDFLAGS"
all_includes="$all_includes $USER_INCLUDES"
AC_SUBST(all_includes)
AC_SUBST(all_libraries)

AC_SUBST(AUTODIRS)

dnl I18n support
ALL_LINGUAS="it"
AM_GNU_GETTEXT([external], need-ngettext)

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

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
	[enable use of Memory Debug (default: no)]),
	[CFLAGS="$CFLAGS -O0 -Wall -g3 -ggdb3 -DDEBUG"],
	[CFLAGS="$CFLAGS -Wall -DNDEBUG"])

AC_ARG_ENABLE(oldhexdump, AC_HELP_STRING([--enable-oldhexdump],
	[use the old style hexdump format (default: no)]),
	AC_DEFINE(USE_OLD_HEXDUMP,  , use the old style hexdump format))

AC_ARG_WITH(included-getopt, AC_HELP_STRING([--with-included-getopt],
	[use the internal getopt library (default: auto)]),
	nc_need_getopt=yes)

dnl *********************************************************************
dnl ** SPECIAL FUNCTIONS VALIDITY CHECKING ******************************
dnl *********************************************************************

dnl Try to see if we need the included getopt
dnl NOTE: with this configuration, it could happen on a really broken
dnl       system, that we have the header file but not the library
dnl       functio, and i don't know what would happen.
dnl AC_CHECK_HEADER(getopt.h)
dnl AM_CONDITIONAL(NEED_GETOPT_H, test ac_cv_header_getopt_h = no)

# don't run the check if --with-included-getopt was specified
if test "x$nc_need_getopt" != "xyes"; then
  AC_CHECK_FUNCS(getopt_long)
  if test $ac_cv_func_getopt_long = no; then
    # automatically use the internal getopt library
    nc_need_getopt=yes
  fi
fi

dnl *********************************************************************
dnl ** AUTOMAKE CONDITIONALS ********************************************
dnl *********************************************************************

AM_CONDITIONAL(NEED_GETOPT, test "x$nc_need_getopt" = "xyes")

dnl *********************************************************************
dnl ** OUTPUT SECTION ***************************************************
dnl *********************************************************************
	
dnl add here all your Makefiles. These will be created by configure.
dnl
AC_CONFIG_FILES(Makefile m4/Makefile lib/Makefile lib/contrib/Makefile
	src/Makefile doc/Makefile po/Makefile.in)

dnl this one is special, it needs the executable flag
dnl
AC_CONFIG_FILES(doc/texi2pod.pl, chmod +x doc/texi2pod.pl)
AC_OUTPUT
