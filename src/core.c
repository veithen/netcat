/*
 * core.c -- description
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: core.c,v 1.4 2002-05-12 21:22:48 themnemonic Exp $
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

int core_udp_connect(struct in_addr *host, unsigned short port)
{
  int sock;
  struct sockaddr_in myaddr;
  debug_v("core_udp_connect(host=%p, port=%hu)", (void *)host, port);

  sock = netcat_socket_new(PF_INET, SOCK_DGRAM);

  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(port);
  memcpy(&myaddr.sin_addr, host, sizeof(myaddr.sin_addr));

  connect(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));

  return sock;
}

/* Returns a new socket */

int core_udp_listen(struct in_addr *local_host, unsigned short local_port)
{
  int ret, sock;
  struct sockaddr_in myaddr;
  debug_v("core_udp_listen(local_host=%p, local_port=%hu)",
	  (void *)local_host, local_port);

  sock = netcat_socket_new(PF_INET, SOCK_DGRAM);
  if (sock < 0)
    return sock;

  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(local_port);
  if (local_host)
    memcpy(&myaddr.sin_addr, local_host, sizeof(myaddr.sin_addr));
  else
    memset(&myaddr.sin_addr, 0, sizeof(myaddr.sin_addr));

  ret = bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
  if (ret < 0)
    return -11;

  return sock;
}

/* ... */

int core_tcp_connect(struct in_addr *host, unsigned short port, int timeout)
{
  int ret, sock;
  struct timeval timest;
  fd_set ins;
  fd_set outs;
  debug_v("core_tcp_connect(host=%p, port=%hu, timeout=%d)", (void *)host,
	  port, timeout);

  debug_dv("Trying TCP connection to %s[:%hu]", netcat_inet_ntop(host), port);

  /* since we are nonblocking now, we can start as many connections as we want
     but it's not a great idea connecting more than one host at time */
  sock = netcat_socket_new_connect(PF_INET, SOCK_STREAM, host, port,
			NULL, (opt_tunnel ? 0 : local_port.num));
  /* FIXME: we should use our specified address (if any) */

  if (sock < 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Couldn't create connection (err=%d): %s",
	    sock, strerror(errno));

  /* FIXME: missing some vital checks about the creation of that socket */
  assert(sock > 0);

  /* initialize select()'s variables */
  FD_ZERO(&ins);
  FD_ZERO(&outs);
  FD_SET(sock, &ins);
  FD_SET(sock, &outs);
  timest.tv_sec = timeout;
  timest.tv_usec = 0;

  /* FIXME: what happens if: Connection Refused, or calling select on an already
     connected host */
  select(sock + 1, &ins, &outs, NULL, (timeout > 0 ? &timest : NULL));

  /* FIXME: why do i get both these? */
  if (FD_ISSET(sock, &ins)) {
    char tmp;
    debug_v("Connect-flag: ins");

    /* since the select() returned flag set for reading, this means that EOF
       arrived on a closed socket, which means that the connection failed.
       Because of this, a read() on that socket MUST fail. */
    ret = read(sock, &tmp, 1);
    assert(ret < 0);

    close(sock);
    return -1;			/* FIXME: close() MAY overwrite errno */
  }

  /* connection was successful, this is the right thing to return */
  if (FD_ISSET(sock, &outs)) {
    debug_v("Connect-flag: outs");
    return sock;
  }

  /* FIXME: i don't remember what is this and WHY this is here */
  if (!FD_ISSET(sock, &ins) && !FD_ISSET(sock, &outs)) {
    /* aborts the connection try, sets the proper errno and returns */
    shutdown(sock, 2);
    close(sock);
    errno = ETIMEDOUT;
    return -1;
  }

  /* connection failed, errno was set by the connect() call, so we can return
     safely our error code */
  return -1;
}

/* This function loops inside the accept() loop until a *VALID* connection is
   fetched.  If an unwanted connection arrives, it is shutdown() and close()d.
   If zero I/O mode is enabled, ALL connections are refused and it stays
   unconditionally in listen mode until timeout elapses, if given, otherwise
   forever.
   Returns: The new socket descriptor for the fetched connection */

int core_tcp_listen(struct in_addr *local_host, unsigned short local_port, int timeout)
{
  int sock_listen, sock_accept;
  debug_v("core_tcp_listen(local_host=%p, local_port=%hu, timeout=%d)",
	  (void *)local_host, local_port, timeout);

  sock_listen = netcat_socket_new_listen(local_host, local_port);

  if (sock_listen < 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Couldn't setup listen socket (err=%d)",
	    sock_listen);

  while (TRUE) {
    struct sockaddr_in my_addr;
    unsigned int my_len = sizeof(my_addr);	/* this *IS* socklen_t */

    sock_accept = netcat_socket_accept(sock_listen, timeout);
    /* reset the timeout to the "use remaining time" value (see network.c file)
       if it exited with timeout we also return this function, so losing the
       original value is not a bad thing. */
    timeout = -1;

    /* failures in netcat_socket_accept() cause this function to return */
    if (sock_accept < 0)
      return -1;

    /* FIXME: i want a library function like netcat_peername() that fetches it
       and resolves with netcat_resolvehost().
       i also must check _resolvehost() */
    getpeername(sock_accept, (struct sockaddr *)&my_addr, &my_len);

    /* if a remote address (and optionally some ports) have been specified
       AND we are NOT in tunnnel mode, we assume it as the only ip and port
       that it is allowed to connect to this socket */
    if (!opt_tunnel) {
      if ((remote_host.iaddrs[0].s_addr && memcmp(&remote_host.iaddrs[0],
	   &my_addr.sin_addr, sizeof(remote_host.iaddrs[0]))) ||
	  (netcat_flag_count() && !netcat_flag_get(ntohs(my_addr.sin_port)))) {
	ncprint(NCPRINT_VERB2, _("Unwanted connection from %s:%hu (refused)"),
		netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));
	goto refuse;
      }
    }
    ncprint(NCPRINT_VERB1, _("Connection from %s:%hu"),
	    netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));

    /* with zero I/O mode we don't really accept any connection */
    if (opt_zero)
      goto refuse;

    /* we have got our socket, now exit the loop */
    break;

 refuse:
    shutdown(sock_accept, 2);
    close(sock_accept);
    continue;
  }			/* end of infinite accepting loop */

  /* we don't need a listening socket anymore */
  close(sock_listen);
  return sock_accept;
}

/* handle stdin/stdout/network I/O. */

int core_readwrite(int sock, int sock2)
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
	debug_v("EOF Received from stdin! (ignored!)");
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
	/* check for telnet codes (if enabled).  Note that the buffered output
           interval does NOT apply to telnet code answers */
	if (opt_telnet)
	  netcat_telnet_parse(sock, buf, &read_ret);

	/* the telnet parsing could have returned 0 chars! */
	if (read_ret) {
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

