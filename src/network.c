/*
 * network.c -- description
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: network.c,v 1.18 2002-05-11 20:07:59 themnemonic Exp $
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
#include <netdb.h>		/* hostent, gethostby*, getservby* */
#include <fcntl.h>		/* fcntl() */

/* Tries to resolve the hostname (or IP address) pointed to by `name'.
   The allocated structure `dst' is filled with the result or with
   ...
   TODO: this function requires much testings
*/

bool netcat_resolvehost(netcat_host *dst, char *name)
{
  struct hostent *hostent;
  struct in_addr res_addr;
  int i, ret;

  assert(name[0]);
  debug_v("netcat_resolvehost(dst=%p, name=\"%s\")", (void *)dst, name);

  /* reset the dst struct for debugging cleanup purposes */
  memset(dst, 0, sizeof(*dst));
  strcpy(dst->name, "(unknown)");

  ret = netcat_inet_pton(name, &res_addr);
  if (!ret) {			/* couldn't translate: it must be a name! */

    /* if the opt_numeric option is set, we must not use DNS in any kind */
    if (opt_numeric)
      return FALSE;

    /* failures to look up a name are reported to the calling function */
    if (!(hostent = gethostbyname(name)))
      return FALSE;

    strncpy(dst->name, hostent->h_name, MAXHOSTNAMELEN - 2);

    /* now save all the available ip addresses (limiting to the global MAXINETADDRS) */
    for (i = 0; hostent->h_addr_list[i] && (i < MAXINETADDRS); i++) {
      memcpy(&dst->iaddrs[i], hostent->h_addr_list[i], sizeof(dst->iaddrs[0]));
      strncpy(dst->addrs[i], netcat_inet_ntop(&dst->iaddrs[i]),
	      sizeof(dst->addrs[0]));
    }				/* for x -> addrs, part A */

    /* since the invalid dns warning is only shown with verbose level 1,
       we can skip them (which would speed up the thing) */
    if (opt_verbose < 1)
      return TRUE;

    /* do inverse lookups in separate loop based on our collected forward
       addresses. FIXME: handle the mismatch event */
    for (i = 0; dst->iaddrs[i].s_addr && (i < MAXINETADDRS); i++) {
      hostent = gethostbyaddr((char *)&dst->iaddrs[i], sizeof(dst->iaddrs[0]),
			      AF_INET);

      if (!hostent || !hostent->h_name) {
	ncprint(NCPRINT_WARNING, _("inverse host lookup failed for %s"),
		dst->addrs[i]);
	continue;
      }
      if (strcasecmp(dst->name, hostent->h_name)) {
	ncprint(NCPRINT_WARNING, _("this host mismatch! %s - %s"), dst->name,
		hostent->h_name);
      }
    }
  }
  else {			/* `name' is a numeric address, try reverse lookup */
    memcpy(&dst->iaddrs[0], &res_addr, sizeof(dst->iaddrs[0]));
    /* FIXME: the following is broken cause of dst->addrs */
    strncpy(dst->addrs[0], netcat_inet_ntop(&res_addr), sizeof(dst->addrs));

    /* if opt_numeric is set or we don't require verbosity, we are done */
    if (opt_numeric || !opt_verbose)
      return TRUE;

    /* numeric or not, failure to look up a PTR is *not* considered fatal */
    hostent = gethostbyaddr((char *)&res_addr, sizeof(res_addr), AF_INET);
    if (!hostent)
      ncprint(NCPRINT_ERROR, _("Inverse name lookup failed for `%s'"), name);
    else {
      strncpy(dst->name, hostent->h_name, MAXHOSTNAMELEN - 2);
      /* now do the direct lookup to see if the IP was auth */
      hostent = gethostbyname(dst->name);
      if (!hostent || !hostent->h_addr_list[0]) {
	ncprint(NCPRINT_WARNING, _("direct host lookup failed for %s"), dst->name);
      }
      else if (strcasecmp(dst->name, hostent->h_name)) {
	ncprint(NCPRINT_WARNING, _("this host mismatch! %s - %s"), dst->name,
		hostent->h_name);
      }
      /* FIXME: I should erase the dst->name field, since the answer wasn't auth */
    }				/* if hostent */
  }				/* INADDR_NONE Great Split */

  return TRUE;
}

/* Identifies a port and fills in the netcat_port structure pointed to by
   `dst'.  If `port_string' is not NULL, it is used to identify the port
   (either by port name, listed in /etc/services, or by a string number).
   In this case `port_num' is discarded.
   If `port_string' is NULL then `port_num' is used to identify the port
   and the port name is looked up reversely. */

bool netcat_getport(netcat_port *dst, const char *port_string,
		    unsigned short port_num)
{
  const char *get_proto = (opt_udpmode ? "udp" : "tcp");
  struct servent *servent;

  debug_v("netcat_getport(dst=%p, port_string=\"%s\", port_num=%hu)",
		(void *) dst, port_string, port_num);

/* Obligatory netdb.h-inspired rant: servent.s_port is supposed to be an int.
   Despite this, we still have to treat it as a short when copying it around.
   Not only that, but we have to convert it *back* into net order for
   getservbyport to work.  Manpages generally aren't clear on all this, but
   there are plenty of examples in which it is just quietly done. -hobbit */

  /* reset the dst struct for debugging cleanup purposes */
  memset(dst, 0, sizeof(*dst));
  strcpy(dst->name, "(unknown)");

  if (!port_string) {
    if (port_num == 0)
      return FALSE;
    servent = getservbyport((int) htons(port_num), get_proto);
    if (servent) {
      assert(port_num == ntohs(servent->s_port));
      strncpy(dst->name, servent->s_name, sizeof(dst->name));
    }
    /* always load any numeric specs! (what?) */
    dst->num = port_num;
    goto end;
  }
  else {
    long port;
    char *endptr;

    /* empty string? refuse it */
    if (!port_string[0])
      return FALSE;

    /* try to convert the string into a valid port number.  If an error occurs
       but it doesn't occur at the first char, throw an error */
    port = strtol(port_string, &endptr, 10);
    if (!endptr[0]) {
      /* pure numeric value, check it out */
      if ((port > 0) && (port < 65536))
        return netcat_getport(dst, NULL, (unsigned short) port);
      else
        return FALSE;
    }
    else if (endptr != port_string)	/* mixed numeric and string value */
      return FALSE;

    /* this is a port name, try to lookup it */
    servent = getservbyname(port_string, get_proto);
    if (servent) {
      strncpy(dst->name, servent->s_name, sizeof(dst->name));
      dst->num = ntohs(servent->s_port);
      goto end;
    }
    return FALSE;
  }

 end:
  snprintf(dst->ascnum, sizeof(dst->ascnum), "%hu", dst->num);
  return TRUE;
}			/* end of netcat_getport() */

/* ... */

int netcat_inet_pton(const char *src, void *dst)
{
  int ret;

#ifdef HAVE_INET_PTON
  ret = inet_pton(AF_INET, src, dst);
#else
# warning Using broken network address conversion function for pton
  ret = inet_aton(src, (struct in_addr *)dst);
#endif

  return ret;
}			/* end of netcat_inet_pton() */

/* ... */

const char *netcat_inet_ntop(const void *src)
{
#ifdef HAVE_INET_NTOP
  static char my_buf[127];
#endif
  const char *ret;

  debug_v("netcat_inet_ntop(src=%p)", src);

#ifdef HAVE_INET_NTOP
  /* FIXME: Since inet_ntop breaks on IPV6-mapped IPv4 addresses i'll need to
   * sort it out by myself. */
  ret = inet_ntop(AF_INET, src, my_buf, sizeof(my_buf));
#else
# warning Using broken network address conversion function for ntop
  ret = inet_ntoa(*(struct in_addr *)src);
#endif

  return ret;
}			/* end of netcat_inet_ntop() */

/* Backend for the socket(2) system call.  This function wraps the creation of
   new sockets and sets the common SO_REUSEADDR SOL_SOCKET option, handling
   eventual errors.
   Returns -1 if the socket(2) call failed, -2 if the setsockopt() call failed;
   otherwise the return value is a descriptor referencing the new socket. */

int netcat_socket_new(int domain, int type)
{
  int sock, ret, sockopt = 0;

  sock = socket(domain, type, 0);
  if (sock < 0)
    return -1;

  /* fix the socket options */
  ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
  if (ret < 0) {
    close(sock);		/* anyway the socket was created */
    return -2;
  }

  return sock;
}

/* ... */

int netcat_socket_new_connect(int domain, int type, const struct in_addr *addr,
		unsigned short port, const struct in_addr *local_addr,
		unsigned short local_port)
{
  int sock, ret;
  struct sockaddr_in rem_addr;

  debug_dv("netcat_socket_new_connect(addr=%p, port=%hu, local_addr=%p, local"
	   "_port=%hu)", (void *)addr, port, (void *)local_addr, local_port);

  rem_addr.sin_family = AF_INET;
  rem_addr.sin_port = htons(port);
  memcpy(&rem_addr.sin_addr, addr, sizeof(rem_addr.sin_addr));

  /* create the socket and fix the options */
  sock = netcat_socket_new(domain, type);
  if (sock < 0)
    return sock;		/* just forward the error code */

  /* only if needed, bind it to a local address */
  if (local_addr || local_port) {
    struct sockaddr_in my_addr;

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(local_port);
    /* local_addr may not be specified because the user may want to only enforce
       the local source port */
    if (local_addr)
      memcpy(&my_addr.sin_addr, local_addr, sizeof(my_addr.sin_addr));
    else
      memset(&my_addr.sin_addr, 0, sizeof(my_addr.sin_addr));
    ret = bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
      ret = -3;
      goto err;
    }
  }

  /* add the non-blocking flag to this socket */
  ret = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
  if (ret < 0) {
    ret = -4;
    goto err;
  }

  /* now launch the real connection. Since we are in non-blocking mode, this
     call will return -1 in MOST cases (on some systems, a connect() to a local
     address may immediately return successfully) */
  ret = connect(sock, (struct sockaddr *)&rem_addr, sizeof(rem_addr));
  if ((ret < 0) && (errno != EINPROGRESS)) {
    ret = -5;
    goto err;
  }

  /* everything went fine, return the (maybe connecting) socket */
  return sock;

 err:
  if (ret < 0) {
    int tmpret, saved_errno = errno;

    /* the close() call MUST NOT fail */
    tmpret = close(sock);
    assert(tmpret >= 0);

    /* restore the original errno */
    errno = saved_errno;
  }
  return ret;
}

/* ... */

int netcat_socket_new_listen(const struct in_addr *addr, unsigned short port)
{
  int sock, ret;
  struct sockaddr_in my_addr;

  debug_dv("netcat_socket_new_listen(addr=%p, port=%hu)", (void *)addr, port);

  /* Reset the sockaddr structure */
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(port);
  memcpy(&my_addr.sin_addr, addr, sizeof(my_addr.sin_addr));

  /* create the socket and fix the options */
  sock = netcat_socket_new(PF_INET, SOCK_STREAM);
  if (sock < 0)
    return sock;		/* just forward the error code */

  /* bind it to the specified address (could be INADDY_ANY as well) */
  ret = bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr));
  if (ret < 0) {
    ret = -3;
    goto err;
  }

  /* actually make it listening, with a reasonable backlog value */
  ret = listen(sock, 4);
  if (ret < 0) {
    ret = -4;
    goto err;
  }

  return sock;

 err:
  if (ret < 0) {
    int tmpret, saved_errno = errno;

    /* the close() call MUST NOT fail */
    tmpret = close(sock);
    assert(tmpret >= 0);

    /* restore the original errno */
    errno = saved_errno;
  }
  return ret;
}

/* This function is much like the accept(2) call, but implements also the
   parameter `timeout', which specifies the time (in seconds) after which the
   function returns.  If `timeout' is negative, the remaining of the last
   valid timeout specified is used.  If it reached zero, or if the timeout
   haven't been initialized already, this function will wait forever.
   Returns -1 on error, setting the errno variable.  If it succeeds, it
   returns a non-negative integer that is the descriptor for the accepted
   socket. */

int netcat_socket_accept(int s, int timeout)
{
  fd_set in;
  static bool timeout_init = FALSE;
  static struct timeval timest;

  debug_v("netcat_socket_accept(s=%d, timeout=%d)", s, timeout);

  /* initialize the select() variables */
  FD_ZERO(&in);
  FD_SET(s, &in);
  if (timeout > 0) {
    timest.tv_sec = timeout;
    timest.tv_usec = 0;
    timeout_init = TRUE;
  }
  else if (timeout && !timeout_init) {
    /* means that timeout is < 0 and timest hasn't been initialized */
    timeout = 0;
  }

  /* now go into select. use timest only if we don't wait forever */
  select(s + 1, &in, NULL, NULL, (timeout ? &timest : NULL));

  /* have we got this connection? */
  if (FD_ISSET(s, &in)) {
    int new_sock;

    new_sock = accept(s, NULL, NULL);
    debug_v("Connection received (new fd=%d)", new_sock);

    /* note: as accept() could fail, new_sock might also be a negative value.
       It's application's work to handle the right errno. */
    return new_sock;
  }

  /* since we've got a timeout, the timest is now zero and thus it is like
     uninitialized.  Next time assume wait forever. */
  timeout_init = FALSE;

  /* no connections arrived during the given time. nothing happens */
  errno = ETIMEDOUT;
  return -1;
}
