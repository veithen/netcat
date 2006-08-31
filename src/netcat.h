/*
 * netcat.h -- main header project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: netcat.h,v 1.37 2006-08-31 15:23:00 themnemonic Exp $
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
#include <sys/types.h>		/* basic types definition */
#include <sys/time.h>		/* timeval, time_t */
#include <sys/socket.h>
#include <sys/uio.h>		/* needed for reading/writing vectors */
#include <sys/param.h>		/* defines MAXHOSTNAMELEN and other stuff */
#include <netinet/in.h>
#include <arpa/inet.h>		/* inet_ntop(), inet_pton() */

/* These are useful to keep the source readable */
#ifndef STDIN_FILENO
# define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO 2
#endif

/* Find a random routine */
#if defined(HAVE_RANDOM) && defined(HAVE_SRANDOM)
# define USE_RANDOM		/* try with most modern random routines */
# define SRAND srandom
# define RAND random
#elif defined(HAVE_RAND) && defined(HAVE_SRAND)
# define USE_RANDOM		/* otherwise fallback to the older rand() */
# define SRAND srand
# define RAND rand
#endif				/* if none of them are here, CHANGE OS! */

/* This must be defined to the longest possible internet address length in
   string notation.
   Bugfix: Looks like Solaris 7 doesn't define this standard. It's ok to use
   the following workaround since this is going to change to introduce IPv6
   support. */
#ifdef INET_ADDRSTRLEN
# define NETCAT_ADDRSTRLEN INET_ADDRSTRLEN
#else
# define NETCAT_ADDRSTRLEN 16
#endif

/* FIXME: I should search more about this portnames standards.  At the moment
   I'll fix my own size for this */
#define NETCAT_MAXPORTNAMELEN 64

/* Find out whether we can use the RFC 2292 extensions on this machine
   (I've found out only linux supporting this feature so far) */
#ifdef HAVE_STRUCT_IN_PKTINFO
# if defined(SOL_IP) && defined(IP_PKTINFO)
#  define USE_PKTINFO
# endif
#endif

/* MAXINETADDR defines the maximum number of host aliases that are saved after
   a successfully hostname lookup.  This will have impact on following lookups,
   in case `-v' switch was specified, and on memory usage. Each struct takes
   approximately:
   MAXINETADDRS * (NETCAT_ADDRSTRLEN + sizeof(struct in_addr)) */
#define MAXINETADDRS 6

#ifndef INADDR_NONE
# define INADDR_NONE 0xffffffff
#endif

/* FIXME: shall we really change this define? probably not. */
#ifdef MAXHOSTNAMELEN
# undef MAXHOSTNAMELEN		/* might be too small on aix, so fix it */
#endif
#define MAXHOSTNAMELEN 256

/** TRUE and FALSE values for logical type `bool' */
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

/** This is just a logical type, but helps a lot. */
#ifndef __cplusplus
# ifndef bool
#  define bool unsigned char
# endif
#endif
#define BOOL_TO_STR(__var__) (__var__ ? "TRUE" : "FALSE")
#define NULL_STR(__var__) (__var__ ? __var__ : "(null)")

/* Redefine MAX functions as it's non-standard */
#ifdef MAX
# undef MAX
#endif
#define MAX(__a,__b) (((int)(__a) > (int)(__b)) ? (__a) : (__b))

/* there are some OS that still doesn't support POSIX standards */
#ifndef HAVE_IN_PORT_T
typedef unsigned short in_port_t;
#endif

/**
 * Netcat basic operating modes
 *
 * This special enumeration is used as global specification of the Netcat
 * operating mode, used only in the main execution flux.
 */

typedef enum {
  NETCAT_UNSPEC,	/**< Netcat mode not specified yet. */
  NETCAT_CONNECT,	/**< Netcat is in Connect mode (the default). */
  NETCAT_LISTEN,	/**< Listen mode */
  NETCAT_TUNNEL		/**< Tunnel mode, embeds Connect and Listen modes. */
} nc_mode_t;

/**
 * Supported Internet protocols
 *
 * This enumeration specifies the domain used by a specified socket. Note that
 * different sockets (e.g. Input/Output) may work with different domains.
 */

typedef enum {
  NETCAT_DOMAIN_UNSPEC,	/**< Domain not specified yet. */
  NETCAT_DOMAIN_IPV4,	/**< Socket uses IPv4. */
  NETCAT_DOMAIN_IPV6	/**< Socket uses IPv6. */
} nc_domain_t;

/**
 * Supported protocols
 */

typedef enum {
  NETCAT_PROTO_UNSPEC,	/**< Protocol not specified yet. */
  NETCAT_PROTO_TCP,	/**< Socket uses TCP protocol. */
  NETCAT_PROTO_UDP	/**< Socket uses UDP protocol. */
} nc_proto_t;

/**
 * ASCII conversion targets
 *
 * This enumeration specifies the ASCII conversion that is to be performed
 * from an input stream while forwarding it to the output stream.
 *
 * The conversion is performed regardeless the format of the input stream.
 * Any known format is recognized and translated to the target format.
 */

typedef enum {
  NETCAT_CONVERT_NONE,	/**< Means that no conversion is performed, i.e. good
			 * for binary data. */
  NETCAT_CONVERT_CRLF,	/**< All data is converted to CRLF. */
  NETCAT_CONVERT_CR,	/**< All data is converted to CR. */
  NETCAT_CONVERT_LF	/**< All data is converted to LF. */
} nc_convert_t;

/**
 * Standard buffer struct
 *
 * This is used for queues buffering and data tracking purposes.  The `head'
 * field is a pointer to the begin of the buffer segment, while `pos'
 * indicates the actual position of the data stream.  If `head' is NULL, it
 * means that there is no dynamically-allocated data in this buffer, *BUT* it
 * MAY still contain some local data segment (for example allocated inside
 * the stack).  `len' indicates the length of the buffer starting from `pos'.
 */

/* FIXME: how do i recover original len? */

typedef struct {
  unsigned char *head;		/**< Head of the buffer */
  unsigned char *pos;		/**< Position in the stream */
  int len;			/**< Length from `pos' to the end of the buffer */
} nc_buffer_t;

/**
 * Standard Netcat hosts record.
 *
 * This is the standard netcat hosts record.  It contains an "authoritative"
 * `name' field, which may be empty, and a list of IP addresses in the network
 * notation and in the dotted string notation.
 */

typedef struct {
  char name[MAXHOSTNAMELEN];			/**< Dns name. */
  char addrs[MAXINETADDRS][NETCAT_ADDRSTRLEN];	/**< Ascii-format IP
						 * addresses. */
  struct in_addr iaddrs[MAXINETADDRS];		/**< Real addresses. */
} nc_host4_t;

#ifdef USE_IPV6

/**
 * Standard Netcat hosts record for IPv6 domain.
 *
 * This is the host record for IPv6 hosts, which have a slightly different
 * structure.  For example they are 128 bits long while IPv4 addresses are
 * just 32 bits long.
 */

typedef struct {
  char name[MAXHOSTNAMELEN];			/**< Dns name. */
  char addrs[MAXINETADDRS][NETCAT_ADDRSTRLEN];	/**< Ascii-format IP
						 * addresses. */
  struct in6_addr iaddrs[MAXINETADDRS];		/**< Real addresses. */
} nc_host6_t;

#endif

typedef struct { /* FIXME: shouldn't become an union??? */
  nc_host4_t host;
#ifdef USE_IPV6
  nc_host6_t host6;
#endif
} nc_host_t;

/**
 * Standard Netcat port record.
 *
 * It contains the port `name', which can be empty, and the port number both
 * as number and as string.
 */

typedef struct {
  char name[NETCAT_MAXPORTNAMELEN];	/**< Canonical port name. */
  char ascnum[8];			/**< Ascii port number. */
  unsigned short num;			/**< Port number. */
  /* FIXME: this is just a test -- update: looks good, but maybe not */
  in_port_t netnum;			/**< Port number in network byte order. */
} nc_port_t;

/**
 * Declare a private object that represents a ports set
 *
 * The definition and handling of this object is delegated to the ports range
 * manager module.
 */

typedef struct nc_ports_st *nc_ports_t;

/**
 * \brief This is the main socket object.
 *
 * This is a more complex struct that holds socket records.
 */

typedef struct {
  int fd;		/**< The Unix socket descriptor. */
  int timeout;		/**< Timeout, in seconds, before giving up any
			 *   operation on the socket. */
  nc_convert_t conversion; /**< Specifies the type of EOL conversion to
			 * perform on the socket. */
  nc_domain_t domain;	/**< Specifies the level 3 domain of the socket */
  nc_proto_t proto;	/**< Specifies the level 4 protocol used by the
			 * socket */
  nc_host_t local;	/**< Local host information */
  nc_port_t local_port;	/**< Local port information */
  nc_host_t remote;	/**< Remote host information */
  nc_port_t port;	/**< Remote port information */
  nc_buffer_t sendq;	/**< Queue for outgoing data */
  nc_buffer_t recvq;	/**< Queue for incoming data */
} nc_sock_t;

/* Netcat includes */

#include "proto.h"
#include "intl.h"
#include "misc.h"

#endif	/* !NETCAT_H */
