/*
 * netcat.c -- main project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: netcat.c,v 1.28 2002-05-08 20:34:11 themnemonic Exp $
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
#include <arpa/nameser.h>
#include <resolv.h>
#include <signal.h>
#include <getopt.h>

int gatesidx = 0;		/* LSRR hop count */
int gatesptr = 4;		/* initial LSRR pointer, settable */
USHORT Single = 1;		/* zero if scanning */
unsigned int insaved = 0;	/* stdin-buffer size for multi-mode */
unsigned long bytes_sent = 0;	/* total bytes received (statistics) */
unsigned long bytes_recv = 0;	/* total bytes sent (statistics) */

/* will malloc up the following globals: */
netcat_host **gates = NULL;		/* LSRR hop hostpoop */
char *optbuf = NULL;		/* LSRR or sockopts */
static FILE *output_fd = NULL;	/* output fd (FIXME: i don't like this) */

/* global options flags */
bool opt_listen = FALSE;		/* listen mode */
bool opt_tunnel = FALSE;		/* tunnel mode */
bool opt_numeric = FALSE;	/* don't resolve hostnames */
bool opt_random = FALSE;		/* use random ports */
bool opt_udpmode = FALSE;	/* use udp protocol instead of tcp */
bool opt_telnet = FALSE;		/* answer in telnet mode */
bool opt_hexdump = FALSE;	/* hexdump traffic */
bool opt_zero = FALSE;		/* zero I/O mode (don't expect anything) */
int opt_interval = 0;		/* delay (in seconds) between lines/ports */
int opt_verbose = 0;		/* be verbose (> 1 to be MORE verbose) */
int opt_wait = 0;		/* wait time */
char *opt_outputfile = NULL;	/* hexdump output file */
char *opt_exec = NULL;		/* program to exec after connecting */

/* common functions */

static void printstats()
{
  ncprint(NCPRINT_VERB2 | NCPRINT_NONEWLINE,
	  _("Total received bytes: %ld\nTotal sent bytes: %ld\n"),
	  bytes_recv, bytes_sent);
}
static char *netcat_strid(netcat_host *host, unsigned short port)
{
  static char buf[MAXHOSTNAMELEN + NETCAT_ADDRSTRLEN + 10];

  if (host->name[0])
    snprintf(buf, sizeof(buf), "%s [%s] %d", host->name, host->addrs[0], port);
  else
    snprintf(buf, sizeof(buf), "%s %d", host->addrs[0], port);

  return buf;
}

/* signal handling */

static void got_term(int z)
{
  fprintf(stderr, "Terminated\n");
  exit(EXIT_FAILURE);
}
static void got_int(int z)
{
  ncprint(NCPRINT_VERB1, _("Exiting."));
  printstats();
  exit(EXIT_FAILURE);
}

#if 0

/* ... */

static void ncexec(int fd)
{
  register char *p;

  dup2(fd, 0);			/* the precise order of fiddlage */
  close(fd);			/* is apparently crucial; this is */
  dup2(0, 1);			/* swiped directly out of "inetd". */
  dup2(0, 2);
  if ((p = strrchr(opt_exec, '/')))
    p++;			/* shorter argv[0] */
  else
    p = opt_exec;

  execl(opt_exec, p, NULL);
  fprintf(stderr, "exec %s failed", opt_exec);
}				/* end of ncexec */
#endif

/* handle stdin/stdout/network I/O. */

static int readwrite(int sock, int sock2)
{
  int fd_stdin, fd_stdout, fd_max;
  int read_ret, write_ret, pbuf_len = 0;
  char buf[1024], *pbuf = NULL, *ptmp = NULL;
  fd_set ins;
  bool inloop = TRUE;
  struct timeval delayer;

  delayer.tv_sec = 0;
  delayer.tv_usec = 0;

  debug_v("readwrite(sock=%d)", sock);

  if (sock2 < 0) {
    fd_stdin = STDIN_FILENO;
    fd_stdout = STDOUT_FILENO;
  }
  else {
    fd_stdin = fd_stdout = sock2;
  }
  fd_max = 1 + (fd_stdin > sock ? fd_stdin : sock);

  while (inloop) {
    FD_ZERO(&ins);
    FD_SET(sock, &ins);

    if (ptmp == NULL)
      FD_SET(fd_stdin, &ins);
    else if ((delayer.tv_sec == 0) && (delayer.tv_usec == 0))
      delayer.tv_sec = opt_interval;

    debug_v("entering select()...");
    select(fd_max, &ins, NULL, NULL,
	   (delayer.tv_sec || delayer.tv_usec ? &delayer : NULL));

    /* reading from stdin.  We support the buffered output by lines, which is
       controlled by the global variable opt_interval.  If it is set, we fetch
       the buffer in the usual way, but we park it in a temporary buffer.  Once
       finished, the buffer is flushed and everything returns normal. */
    if (FD_ISSET(fd_stdin, &ins)) {
      read_ret = read(fd_stdin, buf, sizeof(buf));
      debug_dv("read(stdin) = %d", read_ret);

      if (read_ret < 0) {
	perror("read(stdin)");
	exit(EXIT_FAILURE);
      }
      else if (read_ret == 0) {
	debug_v("EOF Received from stdin! (not exiting)");
	/* FIXME: So, it seems that nc110 stops from setting 0 in the &ins
	   after it got an eof.. in fact in some circumstances after the initial
	   eof it won't be recovered and will keep triggering select() for nothing. */
	/* inloop = FALSE; */
      }
      else {
	if (opt_interval) {
	  int i = 0;

	  while (i < read_ret)
	    if (buf[i++] == '\n')
	      break;

	  if (i < read_ret) {
	    pbuf_len = read_ret - i;
	    pbuf = ptmp = malloc(pbuf_len);
	    memcpy(pbuf, &buf[i], pbuf_len);
	    /* prepare the timeout timer so we don't fall back to the following
	       buffer-handling section.  We already sent out something and we
	       have to wait the right time before sending more. */
	    delayer.tv_sec = opt_interval;
	  }

	  read_ret = i;
        }
	write_ret = write(sock, buf, read_ret);
	bytes_sent += write_ret;		/* update statistics */
	debug_dv("write(net) = %d", write_ret);

	if (write_ret < 0) {
	  perror("write(net)");
	  exit(EXIT_FAILURE);
	}

	/* if the option is set, hexdump the received data */
	if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	  fprintf(output_fd, "Sent %u bytes to the socket\n", write_ret);
#endif
	  netcat_fhexdump(output_fd, '>', buf, write_ret);
	}

      }
    }				/* end of reading from stdin section */

    /* reading from the socket (net). */
    if (FD_ISSET(sock, &ins)) {
      read_ret = read(sock, buf, sizeof(buf));
      debug_dv("read(net) = %d", read_ret);

      if (read_ret < 0) {
	perror("read(net)");
	exit(EXIT_FAILURE);
      }
      else if (read_ret == 0) {
	debug_v("EOF Received from the net");
	inloop = FALSE;
      }
      else {
	write_ret = write(fd_stdout, buf, read_ret);
	bytes_recv += write_ret;
	debug_dv("write(stdout) = %d", write_ret);

	if (write_ret < 0) {
	  perror("write(stdout)");
	  exit(EXIT_FAILURE);
	}

	/* FIXME: handle write_ret != read_ret */

	/* if option is set, hexdump the received data */
	if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	  fprintf(output_fd, "Received %u bytes from the socket\n", write_ret);
#endif
	  netcat_fhexdump(output_fd, '<', buf, write_ret);
	}

      }
    }			/* end of reading from the socket section */

    /* now handle the buffered data (if any) */
    if (ptmp && (delayer.tv_sec == 0) && (delayer.tv_usec == 0)) {
      int i = 0;

      while (i < pbuf_len)
	if (pbuf[i++] == '\n')
	  break;

      /* if this reaches 0, the buffer is over and we can clean it */
      pbuf_len -= i;

      write_ret = write(sock, pbuf, i);
      bytes_sent += write_ret;
      debug_dv("write(stdout)[buf] = %d", write_ret);

      if (write_ret < 0) {
	perror("write(stdout)[buf]");
	exit(EXIT_FAILURE);
      }

      bytes_sent += write_ret;

      /* check if the buffer is over.  If so, clean it and start back reading
         the stdin (or the other socket in case of tunnel mode) */
      if (pbuf_len == 0) {
	free(ptmp);
	ptmp = NULL;
	pbuf = NULL;
      }
      else
	pbuf += i;
    }				/* end of buffered data section */
  }				/* end of while (inloop) */

  return 0;
}				/* end of readwrite() */

/* main: handle command line arguments and listening status */

int main(int argc, char *argv[])
{
  int c, total_ports, sock_accept = -1, sock_connect = -1;
  netcat_host local_host, remote_host;
  netcat_port local_port, remote_port;
  struct in_addr *ouraddr;
  struct sigaction sv;

  memset(&local_host, 0, sizeof(local_host));
  memset(&remote_host, 0, sizeof(remote_host));

#ifdef ENABLE_NLS
  setlocale(LC_MESSAGES, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  /* FIXME: what do i need this for? */
  res_init();

  /* set up the signal handling system */
  sigemptyset(&sv.sa_mask);
  sv.sa_flags = 0;
  sv.sa_handler = got_int;
  sigaction(SIGINT, &sv, NULL);
  sv.sa_handler = got_term;
  sigaction(SIGTERM, &sv, NULL);

  /* ignore some boring signals */
  sv.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sv, NULL);
  sigaction(SIGURG, &sv, NULL);

  /* if no args given at all, get them from stdin */
  if (argc == 1)
    netcat_commandline_read(&argc, &argv);

  /* check for command line switches */
  while (TRUE) {
    int option_index = 0;
    static const struct option long_options[] = {
	{ "exec",	required_argument,	NULL, 'e' },
	{ "gateway",	required_argument,	NULL, 'g' },
	{ "pointer",	required_argument,	NULL, 'G' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "listen",	no_argument,		NULL, 'l' },
	{ "tunnel",	no_argument,		NULL, 'L' },
	{ "dont-resolve", no_argument,		NULL, 'n' },
	{ "output",	required_argument,	NULL, 'o' },
	{ "local-port",	required_argument,	NULL, 'p' },
	{ "randomize",	no_argument,		NULL, 'r' },
	{ "source",	required_argument,	NULL, 's' },
	{ "telnet",	no_argument,		NULL, 't' },
	{ "udp",		no_argument,		NULL, 'u' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "hexdump",	no_argument,		NULL, 'x' },
	{ "wait",	required_argument,	NULL, 'w' },
	{ "zero",	no_argument,		NULL, 'z' },
	{ 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "e:g:G:hi:lLno:p:rs:tuvxw:z", long_options,
		    &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'e':			/* prog to exec */
      if (opt_exec)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Cannot specify `-e' option double"));
      opt_exec = strdup(optarg);
      break;
    case 'G':			/* srcrt gateways pointer val */
      break;
    case 'g':			/* srcroute hop[s] */
      break;
    case 'h':			/* display help and exit */
      netcat_printhelp(argv[0]);
      exit(EXIT_SUCCESS);
    case 'i':			/* line/ports interval time (seconds) */
      opt_interval = atoi(optarg);
      if (opt_interval <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid interval time \"%s\""), optarg);
      break;
    case 'l':			/* listen mode */
      if (opt_tunnel)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and '-l' options are incompatible"));
      opt_listen = TRUE;
      break;
    case 'L':			/* tunnel mode */
      if (opt_listen)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and '-l' options are incompatible"));
      opt_tunnel = TRUE;
      break;
    case 'n':			/* numeric-only, no DNS lookups */
      opt_numeric++;
      break;
    case 'o':			/* output hexdump log to file */
      opt_outputfile = strdup(optarg);
      opt_hexdump = TRUE;	/* implied */
      break;
    case 'p':			/* local source port */
      if (!netcat_getport(&local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid local port: %s"),
		optarg);
      break;
    case 'r':			/* randomize various things */
      opt_random = TRUE;
      break;
    case 's':			/* local source address */
      /* lookup the source address and assign it to the connection address */
      if (!netcat_resolvehost(&local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't resolve local host: %s"),
		optarg);
      ouraddr = &local_host.iaddrs[0];
      break;
    case 't':			/* do telnet fakeout */
      opt_telnet++;
      break;
    case 'u':			/* use UDP protocol */
      opt_udpmode = TRUE;
      break;
    case 'v':			/* be verbose (twice=more verbose) */
      opt_verbose++;
      break;
    case 'V':			/* display version and exit */
      netcat_printversion();
      exit(EXIT_SUCCESS);
    case 'w':			/* wait time (in seconds) */
      opt_wait = atoi(optarg);
      if (opt_wait <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid wait-time: %s"),
		optarg);
      break;
    case 'x':			/* hexdump traffic */
      opt_hexdump = TRUE;
      break;
    case 'z':			/* little or no data xfer */
      opt_zero++;
      break;
    default:
      fprintf(stderr, _("Try `%s --help' for more information.\n"), argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  /* initialize the flag buffer to keep track of the specified ports */
  netcat_flag_init();

  /* randomize only if needed */
  if (opt_random)
    SRAND(time(0));

  if (opt_outputfile) {
    output_fd = fopen(opt_outputfile, "w");
    if (!output_fd) {
      perror(_("Failed to open output file"));
      exit(EXIT_FAILURE);
    }
  }
  else
    output_fd = stdout;

  debug_v("Trying to parse non-args parameters (argc=%d, optind=%d)", argc, optind);

  /* try to get an hostname parameter */
  if (optind < argc) {
    char *myhost = argv[optind++];
    if (!netcat_resolvehost(&remote_host, myhost))
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't resolve host \"%s\""),
	      myhost);
  }

  /* now loop all the other (maybe optional) parameters for port-ranges */
  while (optind < argc) {
    const char *get_argv = argv[optind++];
    char *q, *parse = strdup(get_argv);
    int port_lo = 0, port_hi = 65535;

    if (!(q = strchr(parse, '-'))) {		/* simple number */
      if (netcat_getport(&remote_port, parse, 0))
	netcat_flag_set(remote_port.num, TRUE);
      else
	goto got_err;
    }
    else {		/* could be in the forms: N1-N2, -N2, N1- */
      *q++ = 0;
      /* FIXME: the form "-" seems to be accepted, but i think it should not */
      if (*parse) {
	if (netcat_getport(&remote_port, parse, 0))
	  port_lo = remote_port.num;
	else
	  goto got_err;
      }
      if (*q) {
	if (netcat_getport(&remote_port, q, 0))
	  port_hi = remote_port.num;
	else
	  goto got_err;
      }
      /* now update the flagset (this is int, so it's ok even if hi == 65535) */
      while (port_lo <= port_hi)
	netcat_flag_set(port_lo++, TRUE);
    }

    free(parse);
    continue;

 got_err:
    free(parse);
    ncprint(NCPRINT_ERROR, _("Invalid port specification: %s"), get_argv);
    exit(EXIT_FAILURE);
  }

  debug_dv("Arguments parsing complete! Total ports=%d", netcat_flag_count());

#ifdef DEBUG
  c = 0;
  while ((c = netcat_flag_next(c))) {
    printf("Got port=%d\n", c);
  }
#endif

  /* since ports are the second argument, checking ports might be enough */
  /* FIXME: i don't like this check here but we must do that in order to make
     sure it doesn't fail after we accepted a connection for the tunnel mode */
  if ((netcat_flag_count() == 0) && !opt_listen)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "No ports specified for connection");

  /* Handle listen mode and tunnel mode */
  if (opt_listen || opt_tunnel) {
    int sock_listen;

    sock_listen = netcat_socket_new_listen(&local_host.iaddrs[0], local_port.num);

    if (sock_listen < 0)
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Couldn't setup listen socket (err=%d)",
	      sock_listen);

    debug_dv("Entering SELECT loop");

    do {
      struct sockaddr_in my_addr;
      socklen_t my_len = sizeof(my_addr);

      sock_accept = netcat_socket_accept(sock_listen, opt_wait);

      if (sock_accept < 0)
	ncprint(NCPRINT_VERB1 | NCPRINT_EXIT, _("Listen mode failed: %s"),
		strerror(errno));

      getpeername(sock_accept, (struct sockaddr *)&my_addr, &my_len);

      /* if a remote address (and optionally some ports) have been specified
         AND we are NOT in tunnnel mode, we assume it as the only ip and port
         that it is allowed to connect to this socket */
      if (!opt_tunnel) {
	if ((remote_host.iaddrs[0].s_addr && memcmp(&remote_host.iaddrs[0],
	     &my_addr.sin_addr, sizeof(local_host.iaddrs[0]))) ||
	    (netcat_flag_count() && !netcat_flag_get(ntohs(my_addr.sin_port)))) {
	  ncprint(NCPRINT_VERB2, _("Unwanted connection from %s:%hu (refused)"),
		  netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));
	  shutdown(sock_accept, 2);
	  close(sock_accept);
	  continue;
	}
      }
      ncprint(NCPRINT_VERB1, _("Connection from %s:%hu"),
	      netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));

      /* we don't need a listening socket anymore */
      close(sock_listen);
      break;
    } while (TRUE);

    /* if we are in listen mode, run the core loop and exit when it returns.
       otherwise now it's the time to connect to the target host and tunnel
       them together. */
    if (opt_listen) {
      readwrite(sock_accept, -1);

      debug_dv("Listen: EXIT");
      exit(0);
    }
  }				/* end of listen mode handling */

  /* we need to connect outside */

  total_ports = netcat_flag_count();
  c = 0;
  while (total_ports > 0) {
    int ret;
    struct timeval timeout;
    fd_set ins;
    fd_set outs;

    /* `c' is the port number independently of the sorting method (linear
       or random).  While in linear mode it is also used to fetch the next
       port number */
    if (opt_random)
      c = netcat_flag_rand();
    else
      c = netcat_flag_next(c);
    total_ports--;		/* decrease the total ports number to try */

    debug_dv("Trying connection to %s[:%d]",
	     netcat_inet_ntop(&remote_host.iaddrs[0]), c);

    /* since we are nonblocking now, we can start as many connections as we want
       but it's not a great idea connecting more than one host at time */
    sock_connect = netcat_socket_new_connect(&remote_host.iaddrs[0], c, NULL,
					     local_port.num);
    /* FIXME: missing some vital checks about the creation of that socket */
    assert(sock_connect > 0);

    /* initialize select()'s variables */
    FD_ZERO(&ins);
    FD_ZERO(&outs);
    FD_SET(sock_connect, &ins);
    FD_SET(sock_connect, &outs);
    timeout.tv_sec = opt_wait;
    timeout.tv_usec = 0;

    /* FIXME: what happens if: Connection Refused, or calling select on an already
       connected host */
    debug_dv("Entering SELECT sock=%d, timeout=%d", sock_connect, opt_wait);
    select(sock_connect + 1, &ins, &outs, NULL,
	   (opt_wait > 0 ? &timeout : NULL));

    /* FIXME: why do i get both these? */
    if (FD_ISSET(sock_connect, &ins)) {
      char tmp;
      debug_v("Connect-flag: ins");

      /* since the select() returned flag set for reading, this means that EOF
         arrived on a closed socket, which means that the connection failed.
         Because of this, a read() on that socket MUST fail. */
      ret = read(sock_connect, &tmp, 1);
      assert(ret < 0);

      /* output the hostname in the message only if it's authoritative */
      ncprint(NCPRINT_VERB1, "%s: %s", netcat_strid(&remote_host, c),
	      strerror(errno));

      close(sock_connect);
      continue;			/* go on with next port */
    }

    /* connection was successful, enter the core loop */
    if (FD_ISSET(sock_connect, &outs)) {
      debug_v("Connect-flag: outs");

      ncprint(NCPRINT_VERB1, _("%s open"), netcat_strid(&remote_host, c));

      if (opt_tunnel)
	readwrite(sock_connect, sock_accept);
      else {
	assert(sock_accept == -1);
	readwrite(sock_connect, -1);
      }

    }

    if (!FD_ISSET(sock_connect, &ins) && !FD_ISSET(sock_connect, &outs)) {
      errno = ETIMEDOUT;
      ncprint(NCPRINT_VERB1, "%s: %s", netcat_strid(&remote_host, c),
	      strerror(errno));
    }

    debug_dv("Connect-loop for port %d finished", c);

  }
  debug_v("EXIT");

  printstats();			/* FIXME: is this the RIGHT place? */
  return 0;
}				/* end of main */
