/*
 * misc.h -- description
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: misc.h,v 1.1 2002-05-06 15:05:54 themnemonic Exp $
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

/* constants */
#define NCPRINT_WAITTIME 500000

/* flags */
#define NCPRINT_STDERR		0x01
#define NCPRINT_STDOUT		0x02
#define NCPRINT_NONEWLINE	0x04
#define NCPRINT_DELAY		0x08
#define NCPRINT_EXIT		0x10

/* commands */
#define NCPRINT_NORMAL		0x0000
#define NCPRINT_DEBUG		0x1000
#define NCPRINT_ERROR		0x1100
#define NCPRINT_WARNING		0x1200
#define NCPRINT_VERB1		0x2100
#define NCPRINT_VERB2		0x2200


/* Debugging output routines */
#ifdef DEBUG
#define dprintf(__n__, __msg__)		\
  printf __msg__

/*
#define debug(fmt, args...) debug_output(FALSE, fmt, ## args)
#define debug_d(fmt, args...) debug_output(FALSE, fmt, ## args); usleep(500000)
#define debug_v(fmt, args...) debug_output(TRUE, fmt, ## args)
#define debug_dv(fmt, args...) debug_output(TRUE, fmt, ## args); usleep()
*/

#define debug(fmt, args...) ncprint(NCPRINT_NONEWLINE, fmt, ## args)
#define debug_d(fmt, args...) ncprint(NCPRINT_DELAY | NCPRINT_NONEWLINE, fmt, ## args)
#define debug_v(fmt, args...) ncprint(NCPRINT_DEBUG, fmt, ## args)
#define debug_dv(fmt, args...) ncprint(NCPRINT_DEBUG | NCPRINT_DELAY, fmt, ## args)

#else
#define dprintf(__n__, __msg__)		\
  if (opt_verbose >= __n__)		\
    printf __msg__

#define debug(fmt, args...)
#define debug_d(fmt, args...)
#define debug_v(fmt, args...)
#define debug_dv(fmt, args...)
#endif

