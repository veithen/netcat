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

/* private struct; invariant: begin < end && end < next->begin */
struct nc_ports_st {
  int start;	/* the start of the range, inclusive, i.e. first */
  int end;	/* the end of the range, exclusive, i.e. last+1 */
  struct nc_ports_st *next;
};

/* Inserts a new range performing drop-down merging to avoid overlapping */

void netcat_ports_insert(nc_ports_t *portsrange, unsigned short first, unsigned short last)
{
  nc_ports_t prev = NULL, next = *portsrange, ins;
  int start = first, end = last+1;

  debug_v(("netcat_ports_insert(): p=%p  %hu - %hu", *portsrange, first, last));

  /* find tmp_prev and tmp such that prev->start <= start && start < next->start */

  while (next && (start >= next->start)) {
    prev = next;
    next = next->next;
  }

  /* if the range to be inserted overlaps with prev then just modify
     the existing range */

  if (prev && (start <= prev->end)) {
    prev->end = MAX(prev->end, end);
    ins = prev;
  }
  else {	/* we are fully after the previous range. add a new one */
    ins = malloc(sizeof(*ins));

    ins->start = start;
    ins->end = end;
    ins->next = next;
    if (prev) {
      prev->next = ins;
    } else {
      /* we insert the range as the first element of the chained list; modify
         the pointer stored by the caller */
      *portsrange = ins;
    }
  }

  /* now, either we added a new range or recycled the previous one, we might
     have overlapped one or more of the following ranges.  Check this and
     merge when this happens. */

  while (ins->next && (ins->end >= ins->next->start)) {
    nc_ports_t tmp_del = ins->next;

    ins->end = MAX(ins->end, ins->next->end);
    ins->next = ins->next->next;
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
    count += (tmp->end - tmp->start);
    tmp = tmp->next;
  }

  return count;
}

/* Returns TRUE if the specified port `port' is inside any range */

bool netcat_ports_isset(nc_ports_t portsrange, unsigned short port)
{
  nc_ports_t tmp = portsrange;

  debug_v(("netcat_ports_isset(): p=%p port=%hu", portsrange, port));

  while (tmp && (tmp->start <= port)) {
    if (tmp->end > port)
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

  if (port == 0)
    return tmp ? tmp->start : 0;

  while (tmp && ((tmp->start > port) || (tmp->end <= port)))
    tmp = tmp->next;

  if (!tmp)
    return 0;

  if (port+1 < tmp->end)
    return (port + 1);
  else if (tmp->next)
    return tmp->next->start;

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
