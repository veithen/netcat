/*
 * ncprint.c -- ncprint constants and debugging functions
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 *         Andreas Veithen <andreas.veithen@gmail.com>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *           (C) 2013 Andreas Veithen
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "ncprint.h"
#include "intl.h"

static bool opt_debug = 0;		/* debugging output */
static int opt_verbose = 0;		/* be verbose (> 1 to be MORE verbose) */

void set_debug(bool debug)
{
  opt_debug = debug;
}

void set_verbose(int level)
{
  opt_verbose = level;
}

/* Check if there is any logging (debug or verbose) enabled. */
bool is_logging_enabled(void)
{
  return opt_debug || opt_verbose;
}

/* This is an advanced function for printing normal and error messages for the
   user.  It supports various types and flags which are declared in ncprint.h. */

void ncprint(int type, const char *fmt, ...)
{
  int flags = type & 0xFF;
  char buf[512], newline = '\n';
  FILE *fstream = stderr;		/* output stream */
  va_list args;

  /* clear the flags section so we obtain the pure command */
  type &= ~0xFF;

  /* return if this requires some verbosity levels and we haven't got it */
  if (!opt_debug) {
    if ((flags & NCPRINT_VERB2) && (opt_verbose < 2))
      goto end;

    if ((flags & NCPRINT_VERB1) && (opt_verbose < 1))
      goto end;
  }

  /* known flags */
  if (flags & NCPRINT_STDOUT)
    fstream = stdout;
  if (flags & NCPRINT_NONEWLINE)
    newline = 0;

  /* from now on, it's very probable that we will need the string formatted,
     so unless we have the NOFMT flag, resolve it */
  if (!(flags & NCPRINT_NOFMT)) {
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
  }
  else {
    strncpy(buf, fmt, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;
  }

  switch (type) {
  case NCPRINT_NORMAL:
    fprintf(fstream, "%s%c", buf, newline);
    break;
#ifdef DEBUG
  case NCPRINT_DEBUG:
    if (opt_debug)
      fprintf(fstream, "%s%c", buf, newline);
    else
      return;		/* other flags has no effect with this flag */
    break;
  case NCPRINT_DEBUG_V:
    if (opt_debug)
      fprintf(fstream, "(debug) %s%c", buf, newline);
    else
      return;		/* other flags has no effect with this flag */
    break;
#endif
  case NCPRINT_ERROR:
    fprintf(fstream, "%s %s%c", _("Error:"), buf, newline);
    break;
  case NCPRINT_WARNING:
    fprintf(fstream, "%s %s%c", _("Warning:"), buf, newline);
    break;
  case NCPRINT_NOTICE:
    fprintf(fstream, "%s %s%c", _("Notice:"), buf, newline);
    break;
  }
  /* discard unknown types */

  /* post-output effects flags */
  if (flags & NCPRINT_DELAY)
    usleep(NCPRINT_WAITTIME);

 end:
  /* now resolve the EXIT flag. If this was a verbosity message but we don't
     have the required level, exit anyway. */
  if (flags & NCPRINT_EXIT)
    exit(EXIT_FAILURE);
}

#ifdef DEBUG
/* This function resolves in a totally non-threadsafe way the format strings in
   the debug messages in order to wrap the call to the ncprint facility */

const char *debug_fmt(const char *fmt, ...)
{
  static char buf[512];
  va_list args;

  /* resolve the format strings only if it is really needed */
  if (opt_debug) {
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
  }
  else {
    strncpy(buf, fmt, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;
  }

  return buf;
}
#endif

