/*
 * misc.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: misc.c,v 1.1 2002-04-26 21:33:57 themnemonic Exp $
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
"listen for inbound:	nc -l -p port [-options] [hostname] [port]\n"
"options:\n"
"	-e prog			program to exec after connect [dangerous!!]\n"
"	-g gateway		source-routing hop point[s], up to 8\n"
"	-G num			source-routing pointer: 4, 8, 12, ...\n"
"	-h			this cruft\n"
"	-i secs			delay interval for lines sent, ports scanned\n"
"	-l			listen mode, for inbound connects\n"
"	-n			numeric-only IP addresses, no DNS\n"
"	-o file			hex dump of traffic\n"
"	-p port			local port number\n"
"	-r			randomize local and remote ports\n"
"	-s addr			local source address\n"
"	-t			answer TELNET negotiation"
"	-u			UDP mode\n"
"	-v			verbose [use twice to be more verbose]\n"
"	-w secs			timeout for connects and final net reads\n"
"	-z			zero-I/O mode [used for scanning]\n"
"port numbers can be individual or ranges: lo-hi [inclusive]");
}
