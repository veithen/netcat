## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.7 2002-08-22 21:10:42 themnemonic Exp $

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

SUBDIRS = drafts
