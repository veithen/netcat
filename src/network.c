/*
 * network.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: network.c,v 1.5 2002-04-30 17:52:50 themnemonic Exp $
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

/* ========================== netcat_resolvehost =========================== */
/* Fills the structure pointed to by `dst' with the resolved host `name'.
 * `name' can be either a valid IP string in dotted notation or a FQDN.
 * ... */
bool netcat_resolvehost(netcat_host *dst, char *name)
{
  struct hostent *hostent;
  struct in_addr res_addr;
  int i, ret;

  assert(name);
  debug_v("netcat_resolvehost(dst=%p, name=\"%s\")", (void *)dst, name);

  /* reset the dst struct for debugging cleanup purposes */
  memset(dst, 0, sizeof(*dst));
  strcpy(dst->name, "(unknown)");

  ret = inet_pton(AF_INET, name, &res_addr);
  if (!ret) {			/* couldn't translate: it must be a name! */
    if (opt_numeric) {
      fprintf(stderr, "Can't parse %s as an IP address", name);
      exit(EXIT_FAILURE); /* FIXME: i should return FALSE here */
    }
    hostent = gethostbyname(name);
    /* failure to look up a name is fatal, since we can't do anything with it */
    if (!hostent) {
      fprintf(stderr, "Error: Host lookup failed for `%s'\n", name);
      exit(EXIT_FAILURE);
    }
    strncpy(dst->name, hostent->h_name, MAXHOSTNAMELEN - 2);
    /* FIXME: what do I do with other hosts? */
    for (i = 0; hostent->h_addr_list[i] && (i < 8); i++) {
      memcpy(&dst->iaddrs[i], hostent->h_addr_list[i], sizeof(struct in_addr));
      strncpy(dst->addrs[i], inet_ntoa(dst->iaddrs[i]), sizeof(dst->addrs[0]));
    }				/* for x -> addrs, part A */
    if (!opt_verbose)		/* if we didn't want to see the */
      return TRUE;		/* inverse stuff, we're done. */

    /* do inverse lookups in separate loop based on our collected forward addrs,
       since gethostby* tends to crap into the same buffer over and over */
    for (i = 0; dst->iaddrs[i].s_addr && (i < 8); i++) {
      hostent = gethostbyaddr((char *) &dst->iaddrs[i], sizeof(struct in_addr), AF_INET);

      if (!hostent || !hostent->h_name) {
	fprintf(stderr, "Warning: inverse host lookup failed for %s: ", dst->addrs[i]);
	continue;
      }
      if (strcasecmp(dst->name, hostent->h_name)) {
	fprintf(stderr, "Warning, this host mismatch! %s - %s\n", dst->name, hostent->h_name);
      }
    }				/* for x -> addrs, part B */
  }
  else {			/* `name' is a numeric address */
    memcpy(dst->iaddrs, &res_addr, sizeof(struct in_addr));
    strncpy(dst->addrs[0], inet_ntoa(res_addr), sizeof(dst->addrs));
    if (opt_numeric)		/* if numeric-only, we're done */
      return TRUE;
    if (!opt_verbose)		/* likewise if we don't want */
      return TRUE;		/* the full DNS hair (FIXME?) */
    hostent = gethostbyaddr((char *) &res_addr, sizeof(struct in_addr), AF_INET);
    /* numeric or not, failure to look up a PTR is *not* considered fatal */
    if (!hostent)
      fprintf(stderr, "Error: Inverse name lookup failed for `%s'\n", name);
    else {
      strncpy(dst->name, hostent->h_name, MAXHOSTNAMELEN - 2);
      /* now do the direct lookup to see if the IP was auth */
      hostent = gethostbyname(dst->name);
      if (!hostent || !hostent->h_addr_list[0]) {
	fprintf(stderr, "Warning: forward host lookup failed for %s: ", dst->name);
      }
      else if (strcasecmp(dst->name, hostent->h_name)) {
	fprintf(stderr, "Warning, this host mismatch! %s - %s\n", dst->name, hostent->h_name);
      }
      /* FIXME: I should erase the dst->name field, since the answer wasn't auth */
    }				/* if hostent */
  }				/* INADDR_NONE Great Split */

  return TRUE;
}

/* =========================== netcat_getport ============================== */
/* Identifies a port and fills in the netcat_port structure pointed to by
 * `dst'.  If `port_string' is not NULL, it is used to identify the port
 * (either by port name, listed in /etc/services, or by a string number).
 * In this case `port_num' is discarded.
 * If `port_string' is NULL then `port_num' is used to identify the port
 * and the port name is looked up reversely. */

/* Obligatory netdb.h-inspired rant: servent.s_port is supposed to be an int.
   Despite this, we still have to treat it as a short when copying it around.
   Not only that, but we have to convert it *back* into net order for
   getservbyport to work.  Manpages generally aren't clear on all this, but
   there are plenty of examples in which it is just quietly done. -hobbit */

bool netcat_getport(netcat_port *dst, const char *port_string,
		    unsigned short port_num)
{
  const char *get_proto = (opt_udpmode ? "udp" : "tcp");
  struct servent *servent;

  debug_v("netcat_getport(dst=%p, port_string=\"%s\", port_num=%hu)",
		(void *) dst, port_string, port_num);

  /* reset the dst struct for debugging cleanup purposes */
  memset(dst, 0, sizeof(*dst));
  strcpy(dst->name, "(unknown)");

  /* case 1: reverse-lookup of a number; placed first since this case is
     much more frequent if we're scanning */
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
    int x;
    /* case 2: resolve a string, but we still give preference to numbers
       instead of trying to resolve conflicts.  None of the entries in
       *my* extensive /etc/services begins with a digit, so this should
       "always work" unless you're at 3com and have some company-internal
       services defined... -hobbit */
    x = atoi(port_string);
    if ((x = atoi(port_string)))
      return netcat_getport(dst, NULL, x);	/* recurse for numeric-string-arg */

    servent = getservbyname(port_string, get_proto);
    if (servent) {
      strncpy(dst->name, servent->s_name, sizeof(dst->name));
      dst->num = ntohs(servent->s_port);
      goto end;
    }
    dst->num = 0;
    dst->ascnum[0] = 0;
    return FALSE;
  }

 end:
  snprintf(dst->ascnum, sizeof(dst->ascnum), "%hu", dst->num);
  return TRUE;
}
