/*
 * telnet.c -- contains the telnet protocol routines
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: telnet.c,v 1.5 2002-05-05 09:05:59 themnemonic Exp $
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

#include "netcat.h"

/* RFC0854 DEFINES */
#define TELNET_SE	240	/* End of subnegotiation parameters. */
#define TELNET_NOP	241	/* No operation. */
#define TELNET_DM	242	/* (Data Mark) The data stream portion of a
				 * Synch. This should always be accompanied
				 * by a TCP Urgent notification. */
#define TELNET_BRK	243	/* (Break) NVT character BRK. */
#define TELNET_IP	244	/* (Interrupt Process) The function IP. */
#define TELNET_AO	245	/* (Abort output) The function AO. */
#define TELNET_AYT	246	/* (Are You There) The function AYT. */
#define TELNET_EC	247	/* (Erase character) The function EC. */
#define TELNET_EL	248	/* (Erase Line) The function EL. */
#define TELNET_GA	249	/* (Go ahead) The GA signal. */
#define TELNET_SB	250	/* Indicates that what follows is
				 * subnegotiation of the indicated option. */
#define TELNET_WILL	251	/* Indicates the desire to begin performing,
				 * or confirmation that you are now performing,
				 * the indicated option. */
#define TELNET_WONT	252	/* Indicates the refusal to perform, or
				 * continue performing, the indicated option. */
#define TELNET_DO	253	/* Indicates the request that the other party
				 * perform, or confirmation that you are
				 * expecting the other party to perform, the
				 * indicated option. */
#define TELNET_DONT	254	/* Indicates the demand that the other party
				 * stop performing, or confirmation that you
				 * are no longer expecting the other party
				 * to perform, the indicated option. */
#define TELNET_IAC	255	/* Data Byte 255. */

/* Answer anything that looks like telnet negotiation with don't/won't.
   This doesn't modify any data buffers, update the global output count,
   or show up in a hexdump -- it just shits into the outgoing stream.
   Idea and codebase from Mudge@l0pht.com. */

void atelnet(unsigned char *buf, unsigned int size)
{
  static unsigned char obuf[4];	/* tiny thing to build responses into */
  register int x;
  register unsigned char y;
  register unsigned char *p;

  y = 0;
  p = buf;
  x = size;
  while (x > 0) {
    if (*p != TELNET_IAC)		/* IAC? */
      goto notiac;
    obuf[0] = TELNET_IAC;
    p++;
    x--;
    if ((*p == TELNET_WILL) || (*p == TELNET_WONT))
      y = TELNET_DONT;			/* -> DONT */
    if ((*p == TELNET_DO) || (*p == TELNET_DONT))
      y = TELNET_WONT;			/* -> WONT */
    if (y) {
      obuf[1] = y;
      p++;
      x--;
      obuf[2] = *p;		/* copy actual option byte */
      //(void) write(netfd, obuf, 3); FIXME!
/* if one wanted to bump wrote_net or do a hexdump line, here's the place */
      y = 0;
    }				/* if y */
  notiac:
    p++;
    x--;
  }				/* while x */
}
