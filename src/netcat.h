/*
 * netcat.h -- main header project file
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: netcat.h,v 1.2 2002-04-26 16:40:36 themnemonic Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>



// #include "generic.h"         /* same as with L5, skey, etc */

/* conditional includes -- a very messy section which you may have to dink
   for your own architecture [and please send diffs...]: */
/* #undef _POSIX_SOURCE		/* might need this for something? */
#define HAVE_BIND		/* ASSUMPTION -- seems to work everywhere! */
#define HAVE_HELP		/* undefine if you dont want the help text */
/* #define ANAL			/* if you want case-sensitive DNS matching */

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
#include <malloc.h>
#endif
#ifdef HAVE_SELECT_H		/* random SV variants need this */
#include <sys/select.h>
#endif

/* have to do this *before* including types.h. xxx: Linux still has it wrong */
#ifdef FD_SETSIZE		/* should be in types.h, butcha never know. */
#undef FD_SETSIZE		/* if we ever need more than 16 active */
#endif /* fd's, something is horribly wrong! */
#define FD_SETSIZE 16		/* <-- this'll give us a long anyways, wtf */
#include <sys/types.h>		/* *now* do it.  Sigh, this is broken */

#ifdef HAVE_RANDOM		/* aficionados of ?rand48() should realize */
#define SRAND srandom		/* that this doesn't need *strong* random */
#define RAND random		/* numbers just to mix up port numbers!! */
#else
#define SRAND srand
#define RAND rand
#endif /* HAVE_RANDOM */

/* includes: */
#include <sys/time.h>		/* timeval, time_t */
#include <setjmp.h>		/* jmp_buf et al */
#include <sys/socket.h>		/* basics, SO_ and AF_ defs, sockaddr, ... */
#include <netinet/in.h>		/* sockaddr_in, htons, in_addr */
#include <netinet/in_systm.h>	/* misc crud that netinet/ip.h references */
#include <netinet/ip.h>		/* IPOPT_LSRR, header stuff */
#include <netdb.h>		/* hostent, gethostby*, getservby* */
#include <arpa/inet.h>		/* inet_ntoa */
#include <stdio.h>
#include <string.h>		/* strcpy, strchr, yadda yadda */
#include <errno.h>
#include <signal.h>
#include <fcntl.h>		/* O_WRONLY et al */

/* handy stuff: */
#define SA struct sockaddr	/* socket overgeneralization braindeath */
#define SAI struct sockaddr_in	/* ... whoever came up with this model */
#define IA struct in_addr	/* ... should be taken out and shot, */
				/* ... not that TLI is any better.  sigh.. */
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

struct host_poop
{
  char name[MAXHOSTNAMELEN];	/* dns name */
  char addrs[8][24];		/* ascii-format IP addresses */
  struct in_addr iaddrs[8];	/* real addresses: in_addr.s_addr: ulong */
};

#define HINF struct host_poop

struct port_poop
{
  char name[64];		/* name in /etc/services */
  char anum[8];			/* ascii-format number */
  USHORT num;			/* real host-order number */
};

#define PINF struct port_poop

/* Debug macro: squirt whatever message and sleep a bit so we can see it go
   by.  need to call like Debug ((stuff)) [with no ; ] so macro args match!
   Beware: writes to stdOUT... */
#ifdef DEBUG
#define Debug(x) printf x; printf ("\n"); fflush (stdout); sleep (1);
#else
#define Debug(x)		/* nil... */
#endif
