## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.7 2002-05-01 14:37:15 themnemonic Exp $

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"\$(localedir)\" @DEFS@

if NEED_GETOPT
INCLUDES = -I../contrib
endif

bin_PROGRAMS = netcat
netcat_SOURCES = \
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
