/*
 * proto.h -- main header project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: proto.h,v 1.16 2002-05-11 19:46:08 themnemonic Exp $
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

/* core.c */
int core_readwrite(int sock, int sock2);
int core_udp_connect(struct in_addr *host, unsigned short port);
int core_udp_listen(struct in_addr *local_host, unsigned short local_port);
int core_tcp_connect(struct in_addr *host, unsigned short port, int timeout);
int core_tcp_listen(struct in_addr *local_host, unsigned short local_port, int timeout);

/* flagset.c */
bool netcat_flag_init();
void netcat_flag_set(unsigned short port, bool flag);
bool netcat_flag_get(unsigned short port);
unsigned short netcat_flag_next(unsigned short port);
int netcat_flag_count();
unsigned short netcat_flag_rand();

/* misc.c */
char *netcat_string_split(char **buf);
int netcat_fhexdump(FILE *stream, char c, const unsigned char *data,
		    size_t datalen);
void ncprint(int type, const char *fmt, ...);
void netcat_commandline_read(int *argc, char ***argv);
void netcat_printhelp(char *argv0);
void netcat_printversion(void);

/* netcat.c */
extern bool opt_listen, opt_tunnel, opt_numeric, opt_random, opt_hexdump,
		opt_udpmode, opt_telnet, opt_zero;
extern int opt_interval, opt_verbose, opt_wait;
extern char *opt_outputfile;
extern FILE *output_fd;
extern netcat_host local_host, remote_host;
extern netcat_port local_port, remote_port;
extern unsigned long bytes_sent, bytes_recv;

/* network.c */
bool netcat_resolvehost(netcat_host *dst, char *name);
bool netcat_getport(netcat_port *dst, const char *port_string,
		    unsigned short port_num);
int netcat_inet_pton(const char *src, void *dst);
const char *netcat_inet_ntop(const void *src);
int netcat_socket_new(int domain, int type);
int netcat_socket_new_connect(int domain, int type, const struct in_addr *addr,
		unsigned short port, const struct in_addr *local_addr,
		unsigned short local_port);
int netcat_socket_new_listen(const struct in_addr *addr, unsigned short port);
int netcat_socket_accept(int fd, int timeout);

/* telnet.c */
void atelnet(unsigned char *buf, unsigned int size);
