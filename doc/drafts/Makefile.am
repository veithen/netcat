## Process this file with automake to create Makefile.in.

## Makefile of the GNU netcat project.
## Copyright (C) 2002  Giovanni Giacobbi

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2, or (at your option)
## any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.


# $Id: Makefile.am,v 1.3 2002-12-06 18:05:09 themnemonic Exp $

corerw.png: $(srcdir)/corerw.xml
	dia -e $@ $(srcdir)/corerw.xml

docs: corerw.png

# clean images generated at packaging time, and DIA's backup files
MAINTAINERCLEANFILES = corerw.png *.xml~

##dist-hook: docs
##	@cp -p $(srcdir)/corerw.png $(distdir)

EXTRA_DIST = *.txt

## Proceed to subdirs

## there aren't any
