## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.6 2002-06-10 11:32:17 themnemonic Exp $

info_TEXINFOS = netcat.texi

man_MANS = netcat.1


# Netcat custom building rules

TEXI2POD = $(srcdir)/texi2pod.pl

netcat.pod: $(srcdir)/netcat.texi
	$(TEXI2POD) $(srcdir)/netcat.texi $@

$(man_MANS): netcat.pod
	$(POD2MAN) --center="Netcat" --release="GNU Netcat @VERSION@" $? > $@

MAINTAINERCLEANFILES = netcat.1 netcat.pod

EXTRA_DIST = netcat.1 netcat.pod migration

## Proceed to subdirs

## there isn't any
