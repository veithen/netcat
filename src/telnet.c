/*
 * telnet.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: telnet.c,v 1.1 2002-04-29 14:50:27 themnemonic Exp $
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

/* atelnet :
   Answer anything that looks like telnet negotiation with don't/won't.
   This doesn't modify any data buffers, update the global output count,
   or show up in a hexdump -- it just shits into the outgoing stream.
   Idea and codebase from Mudge@l0pht.com. */
 /* it has to be unsigned here! */
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
    if (*p != 255)		/* IAC? */
      goto notiac;
    obuf[0] = 255;
    p++;
    x--;
    if ((*p == 251) || (*p == 252))	/* WILL or WONT */
      y = 254;			/* -> DONT */
    if ((*p == 253) || (*p == 254))	/* DO or DONT */
      y = 252;			/* -> WONT */
    if (y) {
      obuf[1] = y;
      p++;
      x--;
      obuf[2] = *p;		/* copy actual option byte */
      (void) write(netfd, obuf, 3);
/* if one wanted to bump wrote_net or do a hexdump line, here's the place */
      y = 0;
    }				/* if y */
  notiac:
    p++;
    x--;
  }				/* while x */
}				/* atelnet */
