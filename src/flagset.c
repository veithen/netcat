/*
 * flagset.c -- description
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: flagset.c,v 1.2 2002-05-05 09:05:58 themnemonic Exp $
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

static char *flagset = NULL;
static size_t flagset_len = 0;

/* ... */

bool netcat_flag_init()
{
  /* safe double-init */
  if (flagset)
    return TRUE;

  flagset_len = 8192;

  /* we are asking a bigger amount of memory, this call could fail */
  flagset = malloc(flagset_len);
  if (!flagset)
    return FALSE;

  memset(flagset, 0, flagset_len);
  return TRUE;
}

/* ... */

void netcat_flag_set(unsigned short port, bool flag)
{
  register char *p = flagset + (int) (port / 8);
  register int offset = port % 8;

  assert(flagset);
  if (flag)
    *p |= 1 << offset;
  else
    *p &= ~(1 << offset);
}

/* ... */

bool netcat_flag_get(unsigned short port)
{
  register char *p = flagset + (int) (port / 8);

  assert(flagset);
  if (*p & (1 << (port % 8)))
    return TRUE;
  else
    return FALSE;
}

/* ... */

unsigned short netcat_flag_next(unsigned short port)
{
  register int offset, pos = (int) (++port / 8);

  assert(flagset);
  if (port == 0)
    return 0;
  while ((offset = port % 8)) {
    if (flagset[pos] & (1 << offset))
      return port;
    if (port == 65535)
      return 0;
    port++;
  }

  pos = (int) (port / 8);

  /* ora siamo all'inizio di un byte, proseguo con il controllo rapido */
  while ((flagset[pos] == 0) && (port < 65528)) {
    pos++;
    port += 8;
  }

  offset = 0;
  do {
    if ((flagset[pos] & (1 << offset++)))
      return port;
  } while (port++ < 65535);

  return 0;
}

/* ... */

int netcat_flag_count()
{
  register char c;
  register int i;
  int ret = 0;

  assert(flagset);
  /* scan the block for set bits, if found, it counts them */
  for (i = 0; i < flagset_len; i++) {
    c = flagset[i];
    while (c) {
      ret -= (c >> 7);		/* FIXME! WHY do I have to -=? */
      c <<= 1;
    }
  }

  return ret;
}

/* ... */

unsigned short netcat_flag_rand()
{
  int rand, randmax = netcat_flag_count() - 1;
  unsigned short ret = 0;

  assert(flagset);
  /* if there are no ports at all */
  if (randmax < 0)
    return 0;

  /* fetch a random number from the high-order bits */
  rand = 1 + (int) ((float)randmax * RAND() / (RAND_MAX + 1.0));

  /* loop until we find the specified port */
  while (rand) {
    ret = netcat_flag_next(ret);
    rand--;
  }

  /* don't return this port again */
  netcat_flag_set(ret, FALSE);
  return ret;
}
