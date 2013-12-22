if HAVE_CHECK
TESTS = check_portsrange
check_PROGRAMS = check_portsrange
check_portsrange_SOURCES = check_portsrange.c ../src/netcat.h
check_portsrange_CFLAGS = @CHECK_CFLAGS@
check_portsrange_LDADD = ../src/portsrange.o @CHECK_LIBS@
endif
