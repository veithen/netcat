## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.6 2002-04-30 20:47:59 themnemonic Exp $

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"\$(localedir)\" @DEFS@

bin_PROGRAMS = netcat
netcat_SOURCES = \
	misc.c \
	netcat.c \
	network.c \
	telnet.c

EXTRA_DIST = *.h

## Proceed to subdirs

## there isn't any
