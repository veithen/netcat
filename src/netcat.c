/*
 * netcat.c -- main project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: netcat.c,v 1.39 2002-05-24 18:06:47 themnemonic Exp $
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

/* int gatesidx = 0; */		/* LSRR hop count */
/* int gatesptr = 4; */		/* initial LSRR pointer, settable */
/* nc_host_t **gates = NULL; */	/* LSRR hop hostpoop */
unsigned long bytes_sent = 0;	/* total bytes received (statistics) */
unsigned long bytes_recv = 0;	/* total bytes sent (statistics) */
char *optbuf = NULL;		/* LSRR or sockopts */
FILE *output_fd = NULL;		/* output fd (FIXME: i don't like this) */
bool use_stdin = TRUE;		/* tells wether stdin was closed or not */

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
nc_proto_t opt_proto = NETCAT_PROTO_TCP;	/* protocol to use for connections */

/* prints statistics to stderr with the right verbosity level */

static void printstats(void)
{
  ncprint(NCPRINT_VERB2 | NCPRINT_NONEWLINE,
	  _("Total received bytes: %ld\nTotal sent bytes: %ld\n"),
	  bytes_recv, bytes_sent);
}

/* returns a pointer to a static buffer containing a description of the remote
   host in the best form available (using hostnames and portnames) */

static char *netcat_strid(nc_host_t *host, unsigned short port)
{
  static char buf[MAXHOSTNAMELEN + NETCAT_ADDRSTRLEN + 10];

  /* FIXME: this should use the portnames also */
  /* FIXME: this is broken, cause they fill in (unknown) */
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

/* main: handle command line arguments and listening status */

int main(int argc, char *argv[])
{
  int c, total_ports, sock_accept = -1, sock_connect = -1;
  struct sigaction sv;
  nc_port_t local_port;		/* local port specified with -p option */
  nc_host_t local_host;		/* local host for bind()ing operations */
  nc_host_t remote_host;
  nc_sock_t listen_sock;
  nc_sock_t connect_sock;

  memset(&local_host, 0, sizeof(local_host));
  memset(&remote_host, 0, sizeof(remote_host));
  memset(&listen_sock, 0, sizeof(listen_sock));
  memset(&connect_sock, 0, sizeof(listen_sock));
  listen_sock.domain = PF_INET;
  connect_sock.domain = PF_INET;

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
	{ "tunnel",	required_argument,	NULL, 'L' },
	{ "dont-resolve", no_argument,		NULL, 'n' },
	{ "output",	required_argument,	NULL, 'o' },
	{ "local-port",	required_argument,	NULL, 'p' },
	{ "tunnel-port", required_argument,	NULL, 'P' },
	{ "randomize",	no_argument,		NULL, 'r' },
	{ "source",	required_argument,	NULL, 's' },
	{ "tunnel-source", required_argument,	NULL, 'S' },
	{ "telnet",	no_argument,		NULL, 't' },
	{ "udp",		no_argument,		NULL, 'u' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "hexdump",	no_argument,		NULL, 'x' },
	{ "wait",	required_argument,	NULL, 'w' },
	{ "zero",	no_argument,		NULL, 'z' },
	{ 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "e:g:G:hi:lL:no:p:P:rs:S:tuvxw:z", long_options,
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
		_("`-L' and `-l' options are incompatible"));
      opt_listen = TRUE;
      break;
    case 'L':			/* tunnel mode */
      if (opt_listen)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-l' options are incompatible"));
      if (opt_zero)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      do {
	char *div = strchr(optarg, ':');

	if (div && *(div + 1))
	  *div++ = '\0';
	else
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid target string for `-L' option"));

	/* lookup the remote address and the remote port for tunneling */
	if (!netcat_resolvehost(&connect_sock.host, optarg))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't resolve tunnel target host: %s"),
		  optarg);
	if (!netcat_getport(&connect_sock.port, div, 0))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid tunnel target port: %s"),
		  div);

	connect_sock.proto = opt_proto;
	connect_sock.timeout = opt_wait;
	opt_tunnel = TRUE;
      } while (FALSE);
      break;
    case 'n':			/* numeric-only, no DNS lookups */
      opt_numeric = TRUE;
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
    case 'P':			/* used only in tunnel mode (source port) */
      if (!netcat_getport(&connect_sock.local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid tunnel connect port: %s"),
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
      break;
    case 'S':			/* used only in tunnel mode (source ip) */
      if (!netcat_resolvehost(&connect_sock.local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't resolve tunnel local host: %s"),
		optarg);
      break;
    case 't':			/* do telnet fakeout */
      opt_telnet = TRUE;
      break;
    case 'u':			/* use UDP protocol */
      opt_proto = NETCAT_PROTO_UDP;
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
      if (opt_tunnel)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      opt_zero = TRUE;
      break;
    default:
      fprintf(stderr, _("Try `%s --help' for more information.\n"), argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  /* initialize the flag buffer to keep track of the specified ports */
  netcat_flag_init(65535);

  /* randomize only if needed */
  if (opt_random)
    SRAND(time(0));

  /* handle the -o option. exit on failure */
  if (opt_outputfile) {
    output_fd = fopen(opt_outputfile, "w");
    if (!output_fd) {
      perror(_("Failed to open output file"));
      exit(EXIT_FAILURE);
    }
  }
  else
    output_fd = stderr;

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
    nc_port_t port_tmp;

    if (!(q = strchr(parse, '-')))		/* simple number? */
      q = strchr(parse, ':');			/* try with the other separator */

    if (!q) {
      if (netcat_getport(&port_tmp, parse, 0))
	netcat_flag_set(port_tmp.num, TRUE);
      else
	goto got_err;
    }
    else {		/* could be in the forms: N1-N2, -N2, N1- */
      *q++ = 0;
      if (*parse) {
	if (netcat_getport(&port_tmp, parse, 0))
	  port_lo = port_tmp.num;
	else
	  goto got_err;
      }
      if (*q) {
	if (netcat_getport(&port_tmp, q, 0))
	  port_hi = port_tmp.num;
	else
	  goto got_err;
      }
      if (!*parse && !*q)		/* don't accept the form '-' */
	goto got_err;

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
#if 0
  c = 0;
  while ((c = netcat_flag_next(c))) {
    printf("Got port=%d\n", c);
  }
#endif

  /* Handle listen mode and tunnel mode */
  if (opt_listen || opt_tunnel) {
    /* in tunnel mode the opt_zero flag is illegal, while on listen mode it
       means that no connections should be accepted.  For UDP it means that
       no remote addresses should be used as default endpoint, which means
       that we can't send anything.  In both situations, stdin is no longer
       useful, so close it. */
    if (opt_zero) {
      close(STDIN_FILENO);
      use_stdin = FALSE;
    }

    /* prepare the socket var */
    listen_sock.proto = opt_proto;
    listen_sock.timeout = opt_wait;
    memcpy(&listen_sock.local_host, &local_host, sizeof(listen_sock.local_host));
    memcpy(&listen_sock.local_port, &local_port, sizeof(listen_sock.local_port));
    memcpy(&listen_sock.host, &remote_host, sizeof(listen_sock.host));

    sock_accept = core_listen(&listen_sock);

    /* in zero I/O mode the core_tcp_listen() call will always return -1
       (ETIMEDOUT) since no connections are accepted, because of this our job
       is completed now. */
    /* FIXME: *FIRST* handle sock_accept < 0 and THEN sort out the "REASON"
       that caused this error to happen. i'm planning to make -z compatible
       with -L, so this is broken. */
    if (opt_zero)
      exit(0);

    if (sock_accept < 0)
      ncprint(NCPRINT_VERB1 | NCPRINT_EXIT, _("Listen mode failed: %s"),
	      strerror(errno));

    /* if we are in listen mode, run the core loop and exit when it returns.
       otherwise now it's the time to connect to the target host and tunnel
       them together (which means passing to the next section. */
    if (opt_listen) {
      core_readwrite(&listen_sock, NULL);

      debug_dv("Listen: EXIT");
      exit(EXIT_SUCCESS);
    }
    if (opt_tunnel) {
      /* ok we are in tunnel mode.  The connect_sock var was already
         initialized by the command line arguments. */
      sock_connect = core_connect(&connect_sock);

      /* connection failure? (we cannot get this in UDP mode) */
      if (sock_connect < 0) {
	assert(opt_proto != NETCAT_PROTO_UDP);
	ncprint(NCPRINT_VERB1, "%s: %s", netcat_strid(&remote_host, c),
	strerror(errno));
      }
      core_readwrite(&listen_sock, &connect_sock);
      debug_dv("Tunnel: EXIT");
      exit(EXIT_SUCCESS);
    }
    abort();
  }				/* end of listen and tunnel mode handling */

  /* we need to connect outside */

  /* since ports are the second argument, checking ports might be enough */
  if (netcat_flag_count() == 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	_("No ports specified for connection"));

  total_ports = netcat_flag_count();
  c = 0;	/* must be set to 0 for netcat_flag_next() */
  while (total_ports > 0) {
    /* `c' is the port number independently of the sorting method (linear
       or random).  While in linear mode it is also used to fetch the next
       port number */
    if (opt_random)
      c = netcat_flag_rand();
    else
      c = netcat_flag_next(c);
    total_ports--;		/* decrease the total ports number to try */

    /* since we are nonblocking now, we can start as many connections as we want
       but it's not a great idea connecting more than one host at time */
    connect_sock.proto = opt_proto;
    connect_sock.timeout = opt_wait;
    memcpy(&connect_sock.local_host, &local_host, sizeof(connect_sock.local_host));
    memcpy(&connect_sock.local_port, &local_port, sizeof(connect_sock.local_port));
    memcpy(&connect_sock.host, &remote_host, sizeof(connect_sock.host));
    connect_sock.port.num = c;

    sock_connect = core_connect(&connect_sock);

    /* connection failure? (we cannot get this in UDP mode) */
    if (sock_connect < 0) {
      assert(opt_proto != NETCAT_PROTO_TCP);
      ncprint(NCPRINT_VERB1, "%s: %s", netcat_strid(&remote_host, c),
	      strerror(errno));
      continue;			/* go with next port */
    }

    if (connect_sock.proto == NETCAT_PROTO_TCP)	/* FIXME: move this to core? */
      ncprint(NCPRINT_VERB1, _("%s open"), netcat_strid(&remote_host, c));

    if (opt_tunnel)
      core_readwrite(&connect_sock, &listen_sock);
    else if (opt_zero) {
      /* if we are not in tunnel mode, sock_accept must be untouched */
      assert(sock_accept == -1);
      shutdown(sock_connect, 2);
      close(sock_connect);
    }
    else {
      /* if we are not in tunnel mode, sock_accept must be untouched */
      assert(sock_accept == -1);
      core_readwrite(&connect_sock, NULL);
    }
  }			/* end of while (total_ports > 0) */

  debug_v("EXIT");

  printstats();			/* FIXME: is this the RIGHT place? */
  return 0;
}				/* end of main */
