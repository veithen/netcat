## Copyright (C) 2013  Andreas Veithen <andreas.veithen@gmail.com>

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2, or (at your option)
## any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

TESTS =

if HAVE_CHECK
TESTS += check_portsrange
check_PROGRAMS = check_portsrange
check_portsrange_SOURCES = check_portsrange.c ../src/netcat.h
check_portsrange_CFLAGS = @CHECK_CFLAGS@
# ncprint.o is required when configured with --enable-debug
check_portsrange_LDADD = ../src/portsrange.o ../src/ncprint.o @CHECK_LIBS@
endif

if HAVE_PYTHON
TESTS += exec-with-close-after-write.py remote-port-range.py
check_SCRIPTS = exec-with-close-after-write.py remote-port-range.py
endif
