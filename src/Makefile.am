## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.10 2002-05-07 17:47:07 themnemonic Exp $

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
