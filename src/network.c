/*
 * network.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: network.c,v 1.4 2002-04-29 23:41:00 themnemonic Exp $
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

/* netcat_resolvehost :
   resolve a host 8 ways from sunday; return a new host_poop struct with its
   info.  The argument can be a name or [ascii] IP address; it will try its
   damndest to deal with it.  "opt_numeric" governs whether we do any DNS at all,
   and we also check opt_verbose for what's appropriate work to do. */
netcat_host *netcat_resolvehost(char *name)
{
  struct hostent *hostent;
  struct in_addr res_addr;
  register netcat_host *poop = NULL;
  register int x;
  int ret;

/* I really want to strangle the twit who dreamed up all these sockaddr and
   hostent abstractions, and then forced them all to be incompatible with
   each other so you *HAVE* to do all this ridiculous casting back and forth.
   If that wasn't bad enough, all the doc insists on referring to local ports
   and addresses as "names", which makes NO sense down at the bare metal.

   What an absolutely horrid paradigm, and to think of all the people who
   have been wasting significant amounts of time fighting with this stupid
   deliberate obfuscation over the last 10 years... then again, I like
   languages wherein a pointer is a pointer, what you put there is your own
   business, the compiler stays out of your face, and sheep are nervous.
   Maybe that's why my C code reads like assembler half the time... */

/* If we want to see all the DNS stuff, do the following hair --
   if inet_addr, do reverse and forward with any warnings; otherwise try
   to do forward and reverse with any warnings.  In other words, as long
   as we're here, do a complete DNS check on these clowns.  Yes, it slows
   things down a bit for a first run, but once it's cached, who cares? */

  assert(name);
  debug_v("netcat_resolvehost(name=\"%s\")", name);

  poop = malloc(sizeof(netcat_host));
  strcpy(poop->name, unknown);	/* preload it */

  ret = inet_pton(AF_INET, name, &res_addr);
  if (!ret) {			/* couldn't translate: it must be a name! */
    if (opt_numeric) { /* FIXME: it doesn't have much sense this */
      fprintf(stderr, "Can't parse %s as an IP address", name);
      exit(EXIT_FAILURE);
    }
    hostent = gethostbyname(name);
    /* failure to look up a name is fatal, since we can't do anything with it */
    if (!hostent) {
      fprintf(stderr, "%s: forward host lookup failed: ", name);
      exit(EXIT_FAILURE);
    }
    strncpy(poop->name, hostent->h_name, MAXHOSTNAMELEN - 2);
    /* FIXME: what do I do with other hosts? */
    for (x = 0; hostent->h_addr_list[x] && (x < 8); x++) {
      memcpy(&poop->iaddrs[x], hostent->h_addr_list[x], sizeof(struct in_addr));
      strncpy(poop->addrs[x], inet_ntoa(poop->iaddrs[x]), sizeof(poop->addrs[0]));
    }				/* for x -> addrs, part A */
    if (!opt_verbose)		/* if we didn't want to see the */
      return poop;		/* inverse stuff, we're done. */

    /* do inverse lookups in separate loop based on our collected forward addrs,
       since gethostby* tends to crap into the same buffer over and over */
    for (x = 0; poop->iaddrs[x].s_addr && (x < 8); x++) {
      hostent = gethostbyaddr((char *) &poop->iaddrs[x], sizeof(struct in_addr), AF_INET);

      if (!hostent || !hostent->h_name) {
	fprintf(stderr, "Warning: inverse host lookup failed for %s: ", poop->addrs[x]);
	continue;
      }
      if (strcasecmp(poop->name, hostent->h_name)) {
	fprintf(stderr, "Warning, this host mismatch! %s - %s\n", poop->name, hostent->h_name);
      }
    }				/* for x -> addrs, part B */

  }
  else {			/* `name' is a numeric address */
    memcpy(poop->iaddrs, &res_addr, sizeof(struct in_addr));
    strncpy(poop->addrs[0], inet_ntoa(res_addr), sizeof(poop->addrs));
    if (opt_numeric)		/* if numeric-only, we're done */
      return poop;
    if (!opt_verbose)		/* likewise if we don't want */
      return poop;		/* the full DNS hair */
    hostent = gethostbyaddr((char *) &res_addr, sizeof(struct in_addr), AF_INET);
    /* numeric or not, failure to look up a PTR is *not* considered fatal */
    if (!hostent)
      fprintf(stderr, "%s: inverse host lookup failed: ", name);
    else {
      strncpy(poop->name, hostent->h_name, MAXHOSTNAMELEN - 2);
      hostent = gethostbyname(poop->name);
      if (!hostent || !hostent->h_addr_list[0]) {
	fprintf(stderr, "Warning: forward host lookup failed for %s: ", poop->name);
      } else
      if (strcasecmp(poop->name, hostent->h_name)) {
	fprintf(stderr, "Warning, this host mismatch! %s - %s\n", poop->name, hostent->h_name);
      }
    }				/* if hostent */
  }				/* INADDR_NONE Great Split */

  /* whatever-all went down previously, we should now have a host_poop struct
     with at least one IP address in it. */
  return poop;
}				/* gethostpoop */


/* getportpoop :
   Same general idea as netcat_resolvehost -- look up a port in /etc/services, fill
   in global port_poop, but return the actual port *number*.  Pass ONE of:
	pstring to resolve stuff like "23" or "exec";
	pnum to reverse-resolve something that's already a number.
   If opt_numeric is on, fill in what we can but skip the getservby??? stuff.
   Might as well have consistent behavior here, and it *is* faster. */

/* Obligatory netdb.h-inspired rant: servent.s_port is supposed to  be an int.
   Despite this, we still have to treat it as a short when copying it around.
   Not only that, but we have to convert it *back* into net order for
   getservbyport to work.  Manpages generally aren't clear on all this, but
   there are plenty of examples in which it is just quietly done. -Avian */

bool netcat_getport(netcat_port *dst, const char *port_string,
		    unsigned short port_num)
{
  const char *get_proto = (opt_udpmode ? "udp" : "tcp");
  struct servent *servent;

  debug_v("netcat_getport(dst=%p, port_string=\"%s\", port_num=%hu)",
		(void *) dst, port_string, port_num);

  /* preload some label */
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
       services defined... -Avian */
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
