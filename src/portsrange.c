/*
 * portsrange.c -- keeps track of various port ranges
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: portsrange.c,v 1.1 2004-10-24 01:50:33 themnemonic Exp $
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

/* private struct */
struct nc_ports_st {
  int first;
  int last;
  struct nc_ports_st *next;
};

/* Initializes the flagset to the given len. */

nc_ports_t netcat_ports_init(void)
{
  nc_ports_t ret = malloc(sizeof(*ret));
  memset(ret, 0, sizeof(*ret));

  debug_v(("netcat_ports_init() [p=%p]", (void *)ret));

  return ret;
}

/* Inserts a new range performing drop-down merging to avoid overlapping */

void netcat_ports_insert(nc_ports_t portsrange, unsigned short first, unsigned short last)
{
  nc_ports_t tmp_prev = portsrange, tmp = portsrange->next;

  debug_v(("netcat_ports_insert(): p=%p  %hu - %hu", portsrange, first, last));

  /* skip all sub-ranges that doesn't fit with our one */
  while (tmp && (first > tmp->first)) {
    tmp_prev = tmp;
    tmp = tmp->next;
  }

  /* the following two lines are a sort of "keep-trying-until-it-works".
     Actually I had an idea that using `tmp_prev' was the right choice because
     otherwise there was no way to find out when I'm in the Middle Point. */

  if (tmp && (first <= tmp_prev->last)) {
    tmp_prev->last = MAX(tmp_prev->last, last);
    tmp = tmp_prev;
  }
  else {	/* we are fully after the previous range. add a new one */
    nc_ports_t tmp_ins = malloc(sizeof(*tmp_ins));

    tmp_ins->first = first;
    tmp_ins->last = last;
    tmp_ins->next = tmp;
    tmp_prev->next = tmp_ins;
    tmp = tmp_ins;	/* switch to the latest added */
  }

  /* now, either we added a new range or recycled the previous one, we might
     have overlapped one or more of the following ranges.  Check this and
     merge when this happens. */

  while (tmp->next && (tmp->last >= tmp->next->first)) {
    nc_ports_t tmp_del = tmp->next;

    tmp->last = MAX(tmp->last, tmp->next->last);
    tmp->next = tmp->next->next;
    free(tmp_del);
  }
}

/* Returns the complexive number of ports included in the various ranges */

int netcat_ports_count(nc_ports_t portsrange)
{
  nc_ports_t tmp = portsrange;
  int count = 0;

  debug_v(("netcat_ports_count(): p=%p", portsrange));

  while (tmp) {
    count += (tmp->last - tmp->first + 1);
    tmp = tmp->next;
  }

  return count;
}

/* Returns TRUE if the specified port `port' is inside any range */

bool netcat_ports_isset(nc_ports_t portsrange, unsigned short port)
{
  nc_ports_t tmp = portsrange;

  debug_v(("netcat_ports_isset(): p=%p port=%hu", portsrange, port));

  while (tmp && (tmp->first <= port)) {
    if (tmp->last >= port)
      return TRUE;
    tmp = tmp->next;
  }
  return FALSE;
}

/* Returns the numerically following port included in any range */

unsigned short netcat_ports_next(nc_ports_t portsrange, unsigned short port)
{
  nc_ports_t tmp = portsrange;

  debug_v(("netcat_ports_next(): p=%p port=%hu", portsrange, port));

  while (tmp && ((tmp->first > port) || (tmp->last < port)))
    tmp = tmp->next;

  if (!tmp)
    return 0;

  if (port != tmp->last)
    return (port + 1);
  else if (tmp->next)
    return tmp->next->first;

  return 0;
}

/* Returns the number of a random port (FIXME).
   If there are no other ports left the function
   returns 0. */

unsigned short netcat_ports_rand(nc_ports_t portsrange)
{
  int randnum, randmax = netcat_ports_count(portsrange) - 1;
  unsigned short ret = 0;

  /* if there are no other flags set */
  if (randmax < 0)
    return 0;

#ifdef USE_RANDOM
  /* fetch a random number from the high-order bits */
  randnum = 1 + (int) ((float)randmax * RAND() / (RAND_MAX + 1.0));
#else
# ifdef __GNUC__
#  warning "random routines not found, removed random support"
# endif
  randnum = 1;				/* simulates a random number */
#endif

  /* loop until we find the specified flag */
  while (randnum--)
    ret = netcat_ports_next(portsrange, ret);

  /* FIXME: don't return this same flag again */

  return ret;
}
