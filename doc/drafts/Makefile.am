## Process this file with automake to produce Makefile.in
# $Id: Makefile.am,v 1.2 2002-11-28 20:59:41 themnemonic Exp $

corerw.png: $(srcdir)/corerw.xml
	dia -e $@ $(srcdir)/corerw.xml

docs: corerw.png

# clean images generated at packaging time, and DIA's backup files
MAINTAINERCLEANFILES = *.png *.xml~

EXTRA_DIST = *.txt

## Proceed to subdirs

## there isn't any
