## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.13 2002-08-22 21:14:42 themnemonic Exp $

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"\$(localedir)\" @DEFS@

if NEED_GETOPT
INCLUDES = -I../lib/contrib
endif

bin_PROGRAMS = netcat
netcat_SOURCES = \
	core.c \
	flagset.c \
	misc.c \
	netcat.c \
	network.c \
	telnet.c \
	udphelper.c

netcat_LDADD = @CONTRIBLIBS@ @INTLLIBS@

EXTRA_DIST = *.h

#
# Follows the local installation procedures
#
netcat_nc = $(DESTDIR)$(bindir)/nc

install-exec-hook:
	@if [ ! -L $(netcat_nc) -a ! -e $(netcat_nc) ]; then \
		echo "Creating symlink to the shorter executable name"; \
		ln -s netcat $(netcat_nc); \
	fi

uninstall-hook:
	@if [ -L $(netcat_nc) ]; then \
		echo "Removing symlink to the shorter executable name"; \
		rm -f $(netcat_nc); \
	fi
