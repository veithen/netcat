/*
 * netcat.h -- main header project file
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: netcat.h,v 1.13 2002-05-05 08:40:59 themnemonic Exp $
 */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 ***************************************************************************/

#ifndef NETCAT_H
#define NETCAT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>		/* inet_ntop(), inet_pton() */

/* other misc unchecked includes */
#include <sys/time.h>		/* timeval, time_t */
#include <netinet/in.h>		/* sockaddr_in, htons, in_addr */
#include <netinet/in_systm.h>	/* misc crud that netinet/ip.h references */
#include <netinet/ip.h>		/* IPOPT_LSRR, header stuff */
#include <time.h>

/* #undef _POSIX_SOURCE	*/	/* might need this for something? */

#ifdef HAVE_RANDOM		/* try with most modern random routines */
#define SRAND srandom
#define RAND random
#elif defined HAVE_RAND		/* otherwise fallback to the older rand() */
#define SRAND srand
#define RAND rand
#else				/* if none of them are here, CHANGE OS! */
#error "Couldn't find any random() library function"
#endif

/* handy stuff: */
#define SA struct sockaddr	/* FIXME: this needs to be removed ASAP */
#define SLEAZE_PORT 31337	/* for UDP-scan RTT trick, change if ya want */
#define USHORT unsigned short	/* use these for options an' stuff */
#define BIGSIZ 8192		/* big buffers */

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif
#ifdef MAXHOSTNAMELEN
#undef MAXHOSTNAMELEN		/* might be too small on aix, so fix it */
#endif
#define MAXHOSTNAMELEN 256

/* TRUE and FALSE values for logical type `bool' */
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/* this is just a logical type, but helps a lot */
#ifndef __cplusplus
#ifndef bool
#define bool unsigned char
#endif
#endif

/* Debugging output routines */
#ifdef DEBUG
#define dprintf(__n__, __msg__)		\
  printf __msg__

#define debug(fmt, args...) debug_output(FALSE, fmt, ## args)
#define debug_d(fmt, args...) debug_output(FALSE, fmt, ## args); usleep(500000)
#define debug_v(fmt, args...) debug_output(TRUE, fmt, ## args)
#define debug_dv(fmt, args...) debug_output(TRUE, fmt, ## args); usleep(500000)

#else
#define dprintf(__n__, __msg__)		\
  if (opt_verbose >= __n__)		\
    printf __msg__

#define debug(fmt, args...)
#define debug_d(fmt, args...)
#define debug_v(fmt, args...)
#define debug_dv(fmt, args...)
#endif


typedef struct netcat_host_struct {
  char name[MAXHOSTNAMELEN];	/* dns name */
  char addrs[8][24];		/* ascii-format IP addresses */
  struct in_addr iaddrs[8];	/* real addresses: in_addr.s_addr: ulong */
} netcat_host;

typedef struct netcat_port_struct {
  char name[64];
  char ascnum[8];
  unsigned short num;
} netcat_port;

#include "proto.h"
#include "intl.h"

#endif	/* !NETCAT_H */
