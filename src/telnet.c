/*
 * telnet.c -- a small implementation of the telnet protocol routines
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: telnet.c,v 1.6 2002-05-12 21:22:48 themnemonic Exp $
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

/* Handle the RFC0854 telnet codes found in the buffer `buf' which is `size'
   bytes long.  This is a reliable implementation of the rfc, which understands
   most of the described codes, and automatically replies to `sock' with the
   appropriate code.
   The buffer `buf' is then rewritten with the telnet codes stripped, and the
   size is updated to the new length which is less than or equal to the
   original one.
   The case where a telnet code is broken down (i.e. if the buffering block
   cuts it into two different calls to netcat_telnet_parse() is also handled
   properly with an internal buffer. */

void netcat_telnet_parse(int sock, unsigned char *buf, int *size)
{
  static unsigned char getrq[4];
  static int l = 0;
  char putrq[4];
  int i, eat_chars = 0, ref_size = *size;
  debug_v("netcat_telnet_parse(sock=%d, buf=%p, size=%d", sock, (void *)buf,
	  *size);

  /* parse ALL chars of the string */
  for (i = 0; i < ref_size; i++) {
    if ((buf[i] != TELNET_IAC) && (l == 0))
      continue;

    eat_chars++;

    if (l == 0) {
      getrq[l++] = buf[i];
      continue;
    }

    getrq[l++] = buf[i];

    switch (getrq[1]) {
    case TELNET_SE:
    case TELNET_NOP:
      goto do_eat_chars;
    case TELNET_DM:
    case TELNET_BRK:
    case TELNET_IP:
    case TELNET_AO:
    case TELNET_AYT:
    case TELNET_EC:
    case TELNET_EL:
    case TELNET_GA:
    case TELNET_SB:
      goto do_eat_chars;
    case TELNET_WILL:
    case TELNET_WONT:
      if (l < 3) /* need more data */
        continue;

      /* refuse this option */
      putrq[0] = 0xFF;
      putrq[1] = TELNET_DONT;
      putrq[2] = getrq[2];
      write(sock, putrq, 3);
      goto do_eat_chars;
    case TELNET_DO:
    case TELNET_DONT:
      if (l < 3) /* need more data */
        continue;

      /* refuse this option */
      putrq[0] = 0xFF;
      putrq[1] = TELNET_WONT;
      putrq[2] = getrq[2];
      write(sock, putrq, 3);
      goto do_eat_chars;
    case TELNET_IAC:
      /* insert a byte 255 in the buffer.  Note that we don't know in which
         position we are, but there must be at least 1 eaten char where we
         can park our data byte. */
      buf[i - --eat_chars] = 0xFF;
      goto do_eat_chars;
    }


    continue;

 do_eat_chars:
    /* ... */
    l = 0;

    if (eat_chars > 0) {
      char *from, *to;

      debug("telnet: ate %d chars\n", eat_chars);

      /* move the index to the overlapper character */
      i++;

      /* if this is the end of the string, memmove() does not care of a null
         size, it simply does nothing. */
      from = &buf[i];
      to = &buf[i - eat_chars];
      memmove(to, from, ref_size - i);

      /* fix the index. since the loop will auto-increment the index we need to
         put it one char before. this means that it can become negative but it
         isn't a big problem since it is signed. */
      i -= eat_chars + 1;
      ref_size -= eat_chars;
      eat_chars = 0;
    }
  }

  /* we are at the end of the buffer. all we have to do now is updating the
     authoritative buffer size.  In case that there is a broken-down telnet
     code, the do_eat_chars section is not executed, thus there may be some
     pending chars that needs to be removed.  This is handled here in an easy
     way: since they are at the end of the buffer, just cut them playing with
     the buffer length. */
  *size = ref_size - eat_chars;
}
