/*
 * proto.h -- main header project file
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: proto.h,v 1.10 2002-05-04 15:13:43 themnemonic Exp $
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

/* flagset.c */
bool netcat_flag_init();
void netcat_flag_set(unsigned short port, bool flag);
bool netcat_flag_get(unsigned short port);
unsigned short netcat_flag_next(unsigned short port);
int netcat_flag_count();
unsigned short netcat_flag_rand();

/* misc.c */
char *netcat_string_split(char **buf);
int netcat_fhexdump(FILE *stream, const unsigned char *data, size_t datalen);
void debug_output(bool wrap, const char *fmt, ...);
void netcat_commandline_read(int *argc, char ***argv);
void netcat_printhelp(char *argv0);
void netcat_printversion(void);

/* netcat.c */
extern bool opt_listen, opt_numeric, opt_random, opt_hexdump, opt_udpmode,
		opt_telnet, opt_zero;
extern int opt_interval, opt_verbose, opt_wait;
extern char *opt_outputfile;
extern int netfd;

/* network.c */
bool netcat_resolvehost(netcat_host *dst, char *name);
bool netcat_getport(netcat_port *dst, const char *port_string,
		    unsigned short port_num);
int netcat_socket_new();
int netcat_socket_new_connect(const struct in_addr *addr, unsigned short port,
		const struct in_addr *local_addr, unsigned short local_port);
int netcat_socket_new_listen(const struct in_addr *addr, unsigned short port);
int netcat_socket_accept(int fd, int timeout);



/* telnet.c */
void atelnet(unsigned char *buf, unsigned int size);
