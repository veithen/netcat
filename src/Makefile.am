## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.9 2002-05-06 14:53:59 themnemonic Exp $

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"\$(localedir)\" @DEFS@

if NEED_GETOPT
INCLUDES = -I../lib/contrib
endif

bin_PROGRAMS = netcat
netcat_SOURCES = \
	flagset.c \
	misc.c \
	netcat.c \
	network.c \
	telnet.c

if NEED_GETOPT
netcat_LDADD = \
	../lib/contrib/libcontrib.a
endif

EXTRA_DIST = *.h

## Proceed to subdirs

## there isn't any
