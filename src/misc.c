/*
 * misc.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: misc.c,v 1.12 2002-05-01 13:47:29 themnemonic Exp $
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

/* Hexdump `datalen' bytes starting at `data' to the file pointed to by `stream'.
   If the given block generates a partial line it's rounded up with blank spaces.
   This function was written by Johnny Mnemonic for the netcat project,
   credits must be given for any use of this code outside this project */

int netcat_fhexdump(FILE *stream, const unsigned char *data, size_t datalen)
{
  size_t pos;
  char buf[80], *ascii_dump, *p = NULL;
  int flag = 0;

#ifndef USE_OLD_HEXDUMP
  buf[78] = 0;
  ascii_dump = &buf[62];
#else
  buf[77] = 0;
  ascii_dump = &buf[61];
#endif

  for (pos = 0; pos < datalen; pos++) {
    unsigned char x;

    /* save the offset */
    if ((flag = pos % 16) == 0) {
      /* we are at the beginning of the line, reset output buffer */
      p = buf;
#ifndef USE_OLD_HEXDUMP
      p += sprintf(p, "%08X  ", (unsigned int) pos);
#else
      p += sprintf(p, "? %08X ", (unsigned int) pos);
#endif
    }

    x = (unsigned char) *(data + pos);
#ifndef USE_OLD_HEXDUMP
    p += sprintf(p, "%02hhX ", x);
#else
    p += sprintf(p, "%02hhx ", x);
#endif

    if ((x < 32) || (x > 126))
      ascii_dump[flag] = '.';
    else
      ascii_dump[flag] = x;

#ifndef USE_OLD_HEXDUMP
    if ((pos + 1) % 4 == 0)
      *p++ = ' ';
#endif

    /* if the offset is 15 then we go for the newline */
    if (flag == 15) {
#ifdef USE_OLD_HEXDUMP
      *p++ = '#';
      *p++ = ' ';
#endif
      fprintf(stream, "%s\n", buf);
    }
  }

  /* if last line was incomplete (len % 16) != 0, complete it */
  for (pos = datalen; (flag = pos % 16); pos++) {
    ascii_dump[flag] = ' ';
    strcpy(p, "   ");
    p += 3;

#ifndef USE_OLD_HEXDUMP
    if ((pos + 1) % 4 == 0)
      *p++ = ' ';
#endif

    if (flag == 15) {
#ifdef USE_OLD_HEXDUMP
      *p++ = '#';
      *p++ = ' ';
#endif
      fprintf(stream, "%s\n", buf);
    }
  }

  return 0;
}

/* ... */

void debug_output(bool wrap, const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  if (wrap)
    printf("(debug) ");
  vprintf(fmt, args);
  if (wrap)
    printf("\n");
  va_end(args);
}

/* ... */

char *netcat_string_split(char **buf)
{
  register char *o, *r;

  if (!buf)
    return *buf = "";
  for (o = *buf; isspace(*o); o++);	/* split all initial spaces */
  for (r = o; *o && !isspace(*o); o++);	/* save the pointer and move to the next token */
  if (*o)
    *o++ = 0;
  *buf = o;
  return r;
}

/* construct an argv, and hand anything left over to readwrite(). */

void netcat_commandline(int *argc, char ***argv)
{
  int my_argc = 1;
  char **my_argv = *argv;
  char *saved_argv0 = my_argv[0];
  char buf[4096], *p, *rest;

  fprintf(stderr, _("Cmd line: "));
  fflush(stderr);
  p = fgets(buf, sizeof(buf), stdin);
  my_argv = malloc(128 * sizeof(char *));
  my_argv[0] = saved_argv0;		/* leave the program name intact */

  do {
    rest = netcat_string_split(&p);
    my_argv[my_argc++] = (rest[0] ? strdup(rest) : NULL);
  } while (rest[0]);

  /* now my_argc counts one more, because we have a NULL element at
   * the end of the list */
  my_argv = realloc(my_argv, my_argc-- * sizeof(char *));

  /* sends out the results */
  *argc = my_argc;
  *argv = my_argv;

#if 0
  /* debug this routine */
  debug_v("new argc is: %d", *argc);
  for (my_argc = 0; my_argc < *argc; my_argc++) {
    printf("my_argv[%d] = \"%s\"\n", my_argc, my_argv[my_argc]);
  }
#endif
}

/* ... */

void netcat_printhelp(char *argv0)
{
  printf(_("GNU netcat %s, a rewrite of the famous networking tool.\n"), VERSION);
  printf(_("Basic usages:\n"));
  printf(_("connect to somewhere:  %s [options] hostname port [port] ...\n"), argv0);
  printf(_("listen for inbound:    %s -l -p port [options] [hostname] [port]\n"), argv0);
  printf("\n");
  printf(_("Mandatory arguments to long options are mandatory for short options too.\n"));
  printf(_("Options:\n"
"  -g, --gateway=LIST         source-routing hop point[s], up to 8\n"
"  -G, --pointer=NUM          source-routing pointer: 4, 8, 12, ...\n"
"  -h, --help                 display this help and exit\n"
"  -i, --interval=SECS        delay interval for lines sent, ports scanned\n"
"  -l, --listen               listen mode, for inbound connects\n"
"  -n, --dont-resolve         numeric-only IP addresses, no DNS\n"
"  -o, --output=FILE          output hexdump traffic to FILE (implies -x)\n"
"  -p, --local-port=NUM       local port number\n"
"  -r, --randomize            randomize local and remote ports\n"
"  -t, --telnet               answer using TELNET negotiation\n"
"  -u, --udp                  UDP mode\n"
"  -v, --verbose              verbose (use twice to be more verbose)\n"
"  -V, --version              output version information and exit\n"
"  -x, --hexdump              hexdump incoming and outgoing traffic\n"
"  -w, --wait=SECS            timeout for connects and final net reads\n"
"  -z, --zero                 zero-I/O mode (used for scanning)\n\n"));
}

/* ... */

void netcat_printversion(void)
{
  printf("netcat (The GNU Netcat) %s\n", VERSION);
  printf(_("Copyright (c) 2002 Johnny Mnemonic\n\n"
"This program comes with NO WARRANTY, to the extent permitted by law.\n"
"You may redistribute copies of this program under the terms of\n"
"the GNU General Public License.\n"
"For more information about these matters, see the file named COPYING.\n\n"
"Original design by Avian Research,\n"
"Written by Johnny Mnemonic.\n"));
}


 /* "	-e prog			program to exec after connect [dangerous!!]\n"
"	-s addr			local source address\n"

"port numbers can be individual or ranges: lo-hi [inclusive]"); */
