/*
 * misc.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: misc.c,v 1.3 2002-04-27 14:55:37 themnemonic Exp $
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

  fprintf(stderr, "Cmd line: ");
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

  /* debug */
/*  {
  int i;
    printf("my_argc=%d\n", my_argc);
    for (i = 0; i < my_argc; i++) {
      printf("my_argv[%d] = \"%s\"\n", i, my_argv[i]);
    }
  } */
}

/* ... */
void netcat_printhelp(char *argv0)
{
  printf("GNU netcat %s, a rewrite of the famous networking tool.\n", VERSION);
  printf("Basic usages:\n");
  printf("connect to somewhere:  %s [options] hostname port [port] ...\n", argv0);
  printf("listen for inbound:    %s -l -p port [options] [hostname] [port]\n", argv0);
  printf("\nMandatory arguments to long options are mandatory for short options too.\n");
  printf("Options:\n"
"  -h, --help                 display this help and exit\n"
"  -g, --gateway=LIST         source-routing hop point[s], up to 8\n"
"  -G, --pointer=NUM          source-routing pointer: 4, 8, 12, ...\n"
"  -i, --interval=SECS        delay interval for lines sent, ports scanned\n"
"  -l, --listen               listen mode, for inbound connects\n"
"  -u, --udp                  UDP mode\n"
"  -v, --verbose              verbose (use twice to be more verbose)\n"
"  -z, --zero                 zero-I/O mode (used for scanning)\n"
"  -n, --dont-resolve         numeric-only IP addresses, no DNS\n"
"  -o, --output=FILE          hex dump traffic on FILE\n"
"  -p, --local-port=NUM       local port number\n"
"  -r, --randomize            randomize local and remote ports\n\n");
}

 /* "	-e prog			program to exec after connect [dangerous!!]\n"
"	-s addr			local source address\n"
"	-t			answer TELNET negotiation"
"	-w secs			timeout for connects and final net reads\n"
"port numbers can be individual or ranges: lo-hi [inclusive]"); */
