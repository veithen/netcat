## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.4 2002-04-30 08:24:22 themnemonic Exp $

info_TEXINFOS = netcat.texi

man_MANS = netcat.1


# Netcat custom building rules

TEXI2POD = $(srcdir)/texi2pod.pl

netcat.pod: $(srcdir)/netcat.texi $(TEXI2POD)
	$(TEXI2POD) $(srcdir)/netcat.texi $@

$(man_MANS): netcat.pod
	$(POD2MAN) --center="Netcat" --release="GNU Netcat @VERSION@" $? > $@

CLEANFILES = netcat.1 netcat.pod

## EXTRA_DIST = 

## Proceed to subdirs

## there isn't any
