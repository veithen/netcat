/*
 * network.c -- description
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: network.c,v 1.2 2002-04-29 10:32:28 themnemonic Exp $
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
int netcat_connect_tcp() {

  /* do nothing */
  return 0;
}

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
      memcpy(&poop->iaddrs[x], hostent->h_addr_list[x], sizeof(IA));
      strncpy(poop->addrs[x], inet_ntoa(poop->iaddrs[x]), sizeof(poop->addrs[0]));
    }				/* for x -> addrs, part A */
    if (!opt_verbose)		/* if we didn't want to see the */
      return poop;		/* inverse stuff, we're done. */

    /* do inverse lookups in separate loop based on our collected forward addrs,
       since gethostby* tends to crap into the same buffer over and over */
    for (x = 0; poop->iaddrs[x].s_addr && (x < 8); x++) {
      hostent = gethostbyaddr((char *) &poop->iaddrs[x], sizeof(IA), AF_INET);

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
    memcpy(poop->iaddrs, &res_addr, sizeof(IA));
    strncpy(poop->addrs[0], inet_ntoa(res_addr), sizeof(poop->addrs));
    if (opt_numeric)		/* if numeric-only, we're done */
      return poop;
    if (!opt_verbose)		/* likewise if we don't want */
      return poop;		/* the full DNS hair */
    hostent = gethostbyaddr((char *) &res_addr, sizeof(IA), AF_INET);
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
