/*
 * misc.h -- ncprint constants and debugging functions definition
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2006  Giovanni Giacobbi
 *
 * $Id: misc.h,v 1.9 2006-08-31 22:57:03 themnemonic Exp $
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

/** Time to wait (in microseconds) when DELAY is requested (debug mode). */
#define NCPRINT_WAITTIME 500000

/** @name NCPRINT flags */
#define NCPRINT_STDOUT		0x0001	/**< Force output to stdout. */
#define NCPRINT_NONEWLINE	0x0002	/**< Do not print newline at end. */
#define NCPRINT_DELAY		0x0004	/**< Delay WAITTIME before returning. */
#define NCPRINT_EXIT		0x0008	/**< Call exit() after printing. */
#define NCPRINT_VERB1		0x0010	/**< Require level 1 verbosity. */
#define NCPRINT_VERB2		0x0020	/**< Require level 2 verbosity. */
#define NCPRINT_NOFMT		0x0040	/**< Do not interpret format strings. */

/** @name NCPRINT commands */
/** Normal message printed to stderr by default. */
#define NCPRINT_NORMAL		0x0000

/** Debug message. This type of message is only printed if `opt_debug' is true. */
#define NCPRINT_DEBUG		0x1000

/** Special debug message. Same as DEBUG but prepends "(debug)". */
#define NCPRINT_DEBUG_V		0x1100

/** Prepends "Error:" and marks the message as <b>ERROR</b>. */
#define NCPRINT_ERROR		0x1200

/** Prepends "Warning:" and marks the message as <b>WARNING</b>. */
#define NCPRINT_WARNING		0x1300

/** Prepends "Notice:" and marks the message as <b>NOTICE</b>. */
#define NCPRINT_NOTICE		0x1400

/** @name Debugging output macros */
#ifdef DEBUG
# define debug(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_NONEWLINE | NCPRINT_DEBUG, debug_fmt fmtstring)
# define debug_d(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_NONEWLINE | NCPRINT_DEBUG | NCPRINT_DELAY, debug_fmt fmtstring)
# define debug_v(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_DEBUG_V, debug_fmt fmtstring)
# define debug_dv(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_DEBUG_V | NCPRINT_DELAY, debug_fmt fmtstring)
#else
/** Simple debug format string message. No newline is appended. */
# define debug(fmtstring)
/** Same as simple debug, but forces a delay after output. */
# define debug_d(fmtstring)
/** Debug message that includes label prefix. */
# define debug_v(fmtstring)
/** Debug message with label prefix and delay after output. */
# define debug_dv(fmtstring)
#endif
