## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.4 2002-04-29 14:50:27 themnemonic Exp $

## if DO_DEBUG
## CFLAGS = -O0 -Wall -g3 -ggdb3 -DDEBUG
## else
## CFLAGS = -O2 -Wall -DNDEBUG
## endif

CFLAGS = -O0 -Wall -g3 -ggdb3 -DDEBUG

bin_PROGRAMS = netcat
netcat_SOURCES = \
	misc.c \
	netcat.c \
	network.c \
	telnet.c

EXTRA_DIST = *.h

## Proceed to subdirs

## there isn't any
