/*
 * misc.h -- ncprint header symbols and constants
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: misc.h,v 1.2 2002-05-06 18:42:02 themnemonic Exp $
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

/* time to wait when DELAY is requested (debug mode) */
#define NCPRINT_WAITTIME 500000

/* flags */
#define NCPRINT_STDERR		0x01	/* force output to stderr */
#define NCPRINT_STDOUT		0x02	/* force output to stderr */
#define NCPRINT_NONEWLINE	0x04	/* don't print a newline at the end */
#define NCPRINT_DELAY		0x08	/* delay WAITTIME before returning */
#define NCPRINT_EXIT		0x10	/* exit() after printing the string */
#define NCPRINT_VERB1		0x20	/* require verbosity level 1 */
#define NCPRINT_VERB2		0x40	/* require verbosity level 2 */

/* commands */
/* normal message to stdout */
#define NCPRINT_NORMAL		0x0000

/* special debug message. prepends "(debug)" before the actual string */
#define NCPRINT_DEBUG		0x1000

/* prepends "Error:" and sends the string to stderr */
#define NCPRINT_ERROR		0x1100

/* prepends "Warning:" and sends the string to stderr */
#define NCPRINT_WARNING		0x1200

/* Debugging output routines */
#ifdef DEBUG
# define debug(fmt, args...) ncprint(NCPRINT_NONEWLINE, fmt, ## args)
# define debug_d(fmt, args...) ncprint(NCPRINT_DELAY | NCPRINT_NONEWLINE, fmt, ## args)
# define debug_v(fmt, args...) ncprint(NCPRINT_DEBUG, fmt, ## args)
# define debug_dv(fmt, args...) ncprint(NCPRINT_DEBUG | NCPRINT_DELAY, fmt, ## args)
#else
# define debug(fmt, args...)
# define debug_d(fmt, args...)
# define debug_v(fmt, args...)
# define debug_dv(fmt, args...)
#endif
