/*
 * proto.h -- main header project file
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: proto.h,v 1.6 2002-04-29 23:41:00 themnemonic Exp $
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

/* misc.c */
char *netcat_string_split(char **buf);
int netcat_fhexdump(FILE *stream, const unsigned char *data, size_t datalen);
void debug_output(bool wrap, const char *fmt, ...);
void netcat_commandline(int *argc, char ***argv);
void netcat_printhelp(char *argv0);
void netcat_printversion(void);

/* netcat.c */
extern bool opt_listen, opt_numeric, opt_random, opt_hexdump, opt_udpmode,
		opt_telnet, opt_zero;
extern int opt_verbose, opt_wait;
extern char *opt_outputfile;
extern char unknown[];
extern int netfd;

/* network.c */
netcat_host *netcat_resolvehost(char *name);
bool netcat_getport(netcat_port *dst, const char *port_string,
		    unsigned short port_num);

/* telnet.c */
void atelnet(unsigned char *buf, unsigned int size);
