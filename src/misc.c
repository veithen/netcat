/*
 * misc.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: misc.c,v 1.2 2002-04-27 12:44:33 themnemonic Exp $
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

void netcat_printhelp()
{
  printf("[v1.10]\n"
"connect to somewhere:	nc [-options] hostname port[s] [ports] ... \n"
"listen for inbound:	nc -l -p port [-options] [hostname] [port]\n");

printf("options:\n"
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
