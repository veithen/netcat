/*
 * netcat.c -- main project file
 * Part of the netcat project
 *
 * Author: Johnny Mnemonic <johnny@themnemonic.org>
 * Copyright (c) 2002 by Johnny Mnemonic
 *
 * $Id: netcat.c,v 1.15 2002-04-29 23:41:00 themnemonic Exp $
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
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/time.h>

#include <getopt.h>

/* globals: */
jmp_buf jbuf;			/* timer crud */
int jval = 0;			/* timer crud */
int netfd = -1;
char unknown[] = "(UNKNOWN)";

#ifdef HAVE_BIND
extern int h_errno;

/* stolen almost wholesale from bsd herror.c */
static char *h_errs[] = {
  "Error 0",			/* but we *don't* use this */
  "Unknown host",		/* 1 HOST_NOT_FOUND */
  "Host name lookup failure",	/* 2 TRY_AGAIN */
  "Unknown server error",	/* 3 NO_RECOVERY */
  "No address associated with name",	/* 4 NO_ADDRESS */
};
#else
int h_errno;			/* just so we *do* have it available */
#endif /* HAVE_BIND */
int gatesidx = 0;		/* LSRR hop count */
int gatesptr = 4;		/* initial LSRR pointer, settable */
USHORT Single = 1;		/* zero if scanning */
unsigned int insaved = 0;	/* stdin-buffer size for multi-mode */
unsigned int wrote_out = 0;	/* total stdout bytes */
unsigned int wrote_net = 0;	/* total net bytes */
static char wrote_txt[] = " sent %d, rcvd %d";
char hexnibs[20] = "0123456789abcdef  ";

/* will malloc up the following globals: */
struct timeval *timer1 = NULL;
struct timeval *timer2 = NULL;
struct sockaddr_in *lclend = NULL;		/* sockaddr_in structs */
struct sockaddr_in *remend = NULL;
netcat_host **gates = NULL;		/* LSRR hop hostpoop */
char *optbuf = NULL;		/* LSRR or sockopts */
char *bigbuf_in;		/* data buffers */
char *bigbuf_net;
fd_set *ding1;			/* for select loop */
fd_set *ding2;
/* FIXME: i don't want this thing global, everyone must use his own */
static netcat_port portpoop;		/* for netcat_getport */

/* global options flags */
unsigned int o_interval = 0;
bool opt_listen = FALSE;		/* listen mode */
bool opt_numeric = FALSE;	/* don't resolve hostnames */
bool opt_random = FALSE;		/* use random ports */
bool opt_udpmode = FALSE;	/* use udp protocol instead of tcp */
bool opt_telnet = FALSE;		/* answer in telnet mode */
bool opt_hexdump = FALSE;	/* hexdump traffic */
bool opt_zero = FALSE;		/* zero I/O mode (don't expect anything) */
int opt_verbose = 0;		/* be verbose (> 1 to be MORE verbose) */
int opt_wait = 0;		/* wait time (FIXME) */
char *opt_outputfile = NULL;	/* hexdump output file */

static FILE *output_fd = NULL;	/* output fd (FIXME: i don't like this) */

/* support routines -- the bulk of this thing.  Placed in such an order that
   we don't have to forward-declare anything: */

/* holler :
   fake varargs -- need to do this way because we wind up calling through
   more levels of indirection than vanilla varargs can handle, and not all
   machines have vfprintf/vsyslog/whatever!  6 params oughta be enough. */
void holler(str, p1, p2, p3, p4, p5, p6)
     char *str;
     char *p1, *p2, *p3, *p4, *p5, *p6;
{
  if (opt_verbose) {
    fprintf(stderr, str, p1, p2, p3, p4, p5, p6);
#ifdef HAVE_BIND
    if (h_errno) {		/* if host-lookup variety of error ... */
      if (h_errno > 4)		/* oh no you don't, either */
	fprintf(stderr, "preposterous h_errno: %d", h_errno);
      else
	fprintf(stderr, h_errs[h_errno]);	/* handle it here */
      h_errno = 0;		/* and reset for next call */
    }
#endif
    if (errno) {		/* this gives funny-looking messages, but */
      perror(" ");		/* it's more portable than sys_errlist[]... */
    }
    else			/* xxx: do something better?  */
      fprintf(stderr, "\n");
    fflush(stderr);
  }
}				/* holler */

/* bail :
   error-exit handler, callable from anywhere */
void bail(str, p1, p2, p3, p4, p5, p6)
     char *str;
     char *p1, *p2, *p3, *p4, *p5, *p6;
{
  opt_verbose = 1;
  holler(str, p1, p2, p3, p4, p5, p6);
  close(netfd);
  sleep(1);
  exit(1);
}				/* bail */

/* catch :
   no-brainer interrupt handler */
void catch()
{
  errno = 0;
  if (opt_verbose > 1)		/* normally we don't care */
    bail(wrote_txt, wrote_net, wrote_out);
  bail(" punt!");
}

/* timeout and other signal handling cruft */
void tmtravel()
{
  signal(SIGALRM, SIG_IGN);
  alarm(0);
  if (jval == 0)
    bail("spurious timer interrupt!");
  longjmp(jbuf, jval);
}

/* arm :
   set the timer.  Zero secs arg means unarm */
void arm(unsigned int num, unsigned int secs)
{
  if (secs == 0) {		/* reset */
    signal(SIGALRM, SIG_IGN);
    alarm(0);
    jval = 0;
  }
  else {			/* set */
    signal(SIGALRM, tmtravel);
    alarm(secs);
    jval = num;
  }				/* if secs */
}				/* arm */

/* Hmalloc :
   malloc up what I want, rounded up to *4, and pre-zeroed.  Either succeeds
   or bails out on its own, so that callers don't have to worry about it. */
char *Hmalloc(unsigned int size)
{
  unsigned int s = (size + 4) & 0xfffffffc;	/* 4GB?! */
  char *p = malloc(s);

  if (p != NULL)
    memset(p, 0, s);
  else
    bail("Hmalloc %d failed", s);
  return p;
}				/* Hmalloc */

/* findline :
   find the next newline in a buffer; return inclusive size of that "line",
   or the entire buffer size, so the caller knows how much to then write().
   Not distinguishing \n vs \r\n for the nonce; it just works as is... */
unsigned int findline(char *buf, unsigned int siz)
{
  register char *p;
  register int x;

  if (!buf)			/* various sanity checks... */
    return 0;
  if (siz > BIGSIZ)
    return 0;
  x = siz;
  for (p = buf; x > 0; x--) {
    if (*p == '\n') {
      x = (int) (p - buf);
      x++;			/* 'sokay if it points just past the end! */
      debug_d("findline returning %d\n", x);
      return x;
    }
    p++;
  }				/* for */
  debug_d("findline returning whole thing: %d\n", siz);
  return siz;
}				/* findline */

/* nextport :
   Come up with the next port to try, be it random or whatever.  "block" is
   a ptr to randports array, whose bytes [so far] carry these meanings:
	0	ignore
	1	to be tested
	2	tested [which is set as we find them here]
   returns a USHORT random port, or 0 if all the t-b-t ones are used up. */
USHORT nextport(char *block)
{
  unsigned int x = 0, y = 0;

  y = 70000;			/* high safety count for rnd-tries */
  while (y > 0) {
    x = (RAND() & 0xffff);
    if (block[x] == 1) {	/* try to find a not-done one... */
      block[x] = 2;
      break;
    }
    x = 0;			/* bummer. */
    y--;
  }				/* while y */
  if (x)
    return x;

  y = 65535;			/* no random one, try linear downsearch */
  while (y > 0) {		/* if they're all used, we *must* be sure! */
    if (block[y] == 1) {
      block[y] = 2;
      break;
    }
    y--;
  }				/* while y */
  if (y)
    return y;			/* at least one left */

  return 0;			/* no more left! */
}				/* nextport */

/* loadports :
   set "to be tested" indications in BLOCK, from LO to HI.  Almost too small
   to be a separate routine, but makes main() a little cleaner... */
void loadports(char *block, USHORT lo, USHORT hi)
{
  USHORT x;

  if (!block)
    bail("loadports: no block?!");
  if ((!lo) || (!hi))
    bail("loadports: bogus values %d, %d", lo, hi);
  x = hi;
  while (lo <= x) {
    block[x] = 1;
    x--;
  }
}				/* loadports */

#ifdef GAPING_SECURITY_HOLE
char *pr00gie = NULL;		/* global ptr to -e arg */

/* doexec :
   fiddle all the file descriptors around, and hand off to another prog.  Sort
   of like a one-off "poor man's inetd".  This is the only section of code
   that would be security-critical, which is why it's ifdefed out by default.
   Use at your own hairy risk; if you leave shells lying around behind open
   listening ports you deserve to lose!! */
doexec(int fd)
{
  register char *p;

  dup2(fd, 0);			/* the precise order of fiddlage */
  close(fd);			/* is apparently crucial; this is */
  dup2(0, 1);			/* swiped directly out of "inetd". */
  dup2(0, 2);
  p = strrchr(pr00gie, '/');	/* shorter argv[0] */
  if (p)
    p++;
  else
    p = pr00gie;
  debug_d("gonna exec %s as %s...\n", pr00gie, p);
  execl(pr00gie, p, NULL);
  bail("exec %s failed", pr00gie);	/* this gets sent out.  Hmm... */
}				/* doexec */
#endif /* GAPING_SECURITY_HOLE */

/* doconnect :
   do all the socket stuff, and return an fd for one of
	an open outbound TCP connection
	a UDP stub-socket thingie
   with appropriate socket options set up if we wanted source-routing, or
	an unconnected TCP or UDP socket to listen on.
   Examines various global o_blah flags to figure out what-all to do. */
int doconnect(struct in_addr *rad, USHORT rp, struct in_addr *lad, USHORT lp)
{
  register int nnetfd;
  register int rr;
  int x, y;

  errno = 0;

/* grab a socket; set opts */
newskt:
  if (opt_udpmode)
    nnetfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  else
    nnetfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (nnetfd < 0)
    bail("Can't get socket");
  if (nnetfd == 0)		/* if stdin was closed this might *be* 0, */
    goto newskt;		/* so grab another.  See text for why... */
  x = 1;
  rr = setsockopt(nnetfd, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x));
  if (rr == -1)
    holler("nnetfd reuseaddr failed");	/* ??? */
#ifdef SO_REUSEPORT		/* doesnt exist everywhere... */
  rr = setsockopt(nnetfd, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
  if (rr == -1)
    holler("nnetfd reuseport failed");	/* ??? */
#endif
#if 0
/* If you want to screw with RCVBUF/SNDBUF, do it here.  Liudvikas Bukys at
   Rochester sent this example, which would involve YET MORE options and is
   just archived here in case you want to mess with it.  o_xxxbuf are global
   integers set in main() getopt loop, and check for rr == 0 afterward. */
  rr = setsockopt(nnetfd, SOL_SOCKET, SO_RCVBUF, &o_rcvbuf, sizeof o_rcvbuf);
  rr = setsockopt(nnetfd, SOL_SOCKET, SO_SNDBUF, &o_sndbuf, sizeof o_sndbuf);
#endif

  /* fill in all the right sockaddr crud */
  lclend->sin_family = AF_INET;

/* fill in all the right sockaddr crud */
  lclend->sin_family = AF_INET;
  remend->sin_family = AF_INET;

/* if lad/lp, do appropriate binding */
  if (lad)
    memcpy(&lclend->sin_addr.s_addr, lad, sizeof(struct in_addr));
  if (lp)
    lclend->sin_port = htons(lp);
  rr = 0;
  if (lad || lp) {
    x = (int) lp;
/* try a few times for the local bind, a la ftp-data-port... */
    for (y = 4; y > 0; y--) {
      rr = bind(nnetfd, (SA *) lclend, sizeof(SA));
      if (rr == 0)
	break;
      if (errno != EADDRINUSE)
	break;
      else {
	holler("retrying local %s:%d", inet_ntoa(lclend->sin_addr), lp);
	sleep(2);
	errno = 0;		/* clear from sleep */
      }				/* if EADDRINUSE */
    }				/* for y counter */
  }				/* if lad or lp */
  if (rr)
    bail("Can't grab %s:%d with bind", inet_ntoa(lclend->sin_addr), lp);

  if (opt_listen)
    return nnetfd;		/* thanks, that's all for today */

  memcpy(&remend->sin_addr.s_addr, rad, sizeof(struct in_addr));
  remend->sin_port = htons(rp);

/* rough format of LSRR option and explanation of weirdness.
Option comes after IP-hdr dest addr in packet, padded to *4, and ihl > 5.
IHL is multiples of 4, i.e. real len = ip_hl << 2.
	type 131	1	; 0x83: copied, option class 0, number 3
	len		1	; of *whole* option!
	pointer		1	; nxt-hop-addr; 1-relative, not 0-relative
	addrlist...	var	; 4 bytes per hop-addr
	pad-to-32	var	; ones, i.e. "NOP"

If we want to route A -> B via hops C and D, we must add C, D, *and* B to the
options list.  Why?  Because when we hand the kernel A -> B with list C, D, B
the "send shuffle" inside the kernel changes it into A -> C with list D, B and
the outbound packet gets sent to C.  If B wasn't also in the hops list, the
final destination would have been lost at this point.

When C gets the packet, it changes it to A -> D with list C', B where C' is
the interface address that C used to forward the packet.  This "records" the
route hop from B's point of view, i.e. which address points "toward" B.  This
is to make B better able to return the packets.  The pointer gets bumped by 4,
so that D does the right thing instead of trying to forward back to C.

When B finally gets the packet, it sees that the pointer is at the end of the
LSRR list and is thus "completed".  B will then try to use the packet instead
of forwarding it, i.e. deliver it up to some application.

Note that by moving the pointer yourself, you could send the traffic directly
to B but have it return via your preconstructed source-route.  Playing with
this and watching "tcpdump -v" is the best way to understand what's going on.

Only works for TCP in BSD-flavor kernels.  UDP is a loss; udp_input calls
stripoptions() early on, and the code to save the srcrt is notdef'ed.
Linux is also still a loss at 1.3.x it looks like; the lsrr code is { }...
*/

/* if any -g arguments were given, set up source-routing.  We hit this after
   the gates are all looked up and ready to rock, any -G pointer is set,
   and gatesidx is now the *number* of hops */
  if (gatesidx) {		/* if we wanted any srcrt hops ... */
/* don't even bother compiling if we can't do IP options here! */
#ifdef IP_OPTIONS
    if (!optbuf) {		/* and don't already *have* a srcrt set */
      char *opp;		/* then do all this setup hair */

      optbuf = Hmalloc(48);
      opp = optbuf;
      *opp++ = IPOPT_LSRR;	/* option */
      *opp++ = (char) (((gatesidx + 1) * sizeof(struct in_addr)) + 3) & 0xff;	/* length */
      *opp++ = gatesptr;	/* pointer */
/* opp now points at first hop addr -- insert the intermediate gateways */
      for (x = 0; x < gatesidx; x++) {
	memcpy(opp, gates[x]->iaddrs, sizeof(struct in_addr));
	opp += sizeof(struct in_addr);
      }
/* and tack the final destination on the end [needed!] */
      memcpy(opp, rad, sizeof(struct in_addr));
      opp += sizeof(struct in_addr);
      *opp = IPOPT_NOP;		/* alignment filler */
    }				/* if empty optbuf */
/* calculate length of whole option mess, which is (3 + [hops] + [final] + 1),
   and apply it [have to do this every time through, of course] */
    x = ((gatesidx + 1) * sizeof(struct in_addr)) + 4;
    rr = setsockopt(nnetfd, IPPROTO_IP, IP_OPTIONS, optbuf, x);
    if (rr == -1)
      bail("srcrt setsockopt fuxored");
#else /* IP_OPTIONS */
    holler("Warning: source routing unavailable on this machine, ignoring");
#endif /* IP_OPTIONS */
  }				/* if gatesidx */

/* wrap connect inside a timer, and hit it */
  arm(1, opt_wait);
  if (setjmp(jbuf) == 0) {
    rr = connect(nnetfd, (SA *) remend, sizeof(SA));
  }
  else {			/* setjmp: connect failed... */
    rr = -1;
    errno = ETIMEDOUT;		/* fake it */
  }
  arm(0, 0);
  if (rr == 0)
    return nnetfd;
  close(nnetfd);		/* clean up junked socket FD!! */
  return -1;
}				/* doconnect */

/* dolisten :
   just like doconnect, and in fact calls a hunk of doconnect, but listens for
   incoming and returns an open connection *from* someplace.  If we were
   given host/port args, any connections from elsewhere are rejected.  This
   in conjunction with local-address binding should limit things nicely... */
int dolisten(struct in_addr *rad, USHORT rp, struct in_addr *lad, USHORT lp)
{
  register int nnetfd;
  register int rr;
  netcat_host *whozis = NULL;
  int x;
  char *cp;
  USHORT z;

  errno = 0;

/* Pass everything off to doconnect, who in opt_listen mode just gets a socket */
  nnetfd = doconnect(rad, rp, lad, lp);
  if (nnetfd <= 0)
    return -1;
  if (opt_udpmode) {		/* apparently UDP can listen ON */
    if (!lp)			/* "port 0",  but that's not useful */
      bail("UDP listen needs -p arg");
  }
  else {
    rr = listen(nnetfd, 1);	/* gotta listen() before we can get */
    if (rr < 0)			/* our local random port.  sheesh. */
      bail("local listen fuxored");
  }

/* Various things that follow temporarily trash bigbuf_net, which might contain
   a copy of any recvfrom()ed packet, but we'll read() another copy later. */

/* I can't believe I have to do all this to get my own goddamn bound address
   and port number.  It should just get filled in during bind() or something.
   All this is only useful if we didn't say -p for listening, since if we
   said -p we *know* what port we're listening on.  At any rate we won't bother
   with it all unless we wanted to see it, although listening quietly on a
   random unknown port is probably not very useful without "netstat". */
  if (opt_verbose) {
    x = sizeof(SA);		/* how 'bout getsockNUM instead, pinheads?! */
    rr = getsockname(nnetfd, (SA *) lclend, &x);
    if (rr < 0)
      holler("local getsockname failed");
    strcpy(bigbuf_net, "listening on [");	/* buffer reuse... */
    if (lclend->sin_addr.s_addr)
      strcat(bigbuf_net, inet_ntoa(lclend->sin_addr));
    else
      strcat(bigbuf_net, "any");
    strcat(bigbuf_net, "] %d ...");
    z = ntohs(lclend->sin_port);
    holler(bigbuf_net, z);
  }				/* verbose -- whew!! */

/* UDP is a speeeeecial case -- we have to do I/O *and* get the calling
   party's particulars all at once, listen() and accept() don't apply.
   At least in the BSD universe, however, recvfrom/PEEK is enough to tell
   us something came in, and we can set things up so straight read/write
   actually does work after all.  Yow.  YMMV on strange platforms!  */
  if (opt_udpmode) {
    x = sizeof(SA);		/* retval for recvfrom */
    arm(2, opt_wait);		/* might as well timeout this, too */
    if (setjmp(jbuf) == 0) {	/* do timeout for initial connect */
      rr = recvfrom		/* and here we block... */
	(nnetfd, bigbuf_net, BIGSIZ, MSG_PEEK, (SA *) remend, &x);
      debug_d("dolisten/recvfrom ding, rr = %d, netbuf %s\n", rr, bigbuf_net);
    }
    else
      goto dol_tmo;		/* timeout */
    arm(0, 0);
/* I'm not completely clear on how this works -- BSD seems to make UDP
   just magically work in a connect()ed context, but we'll undoubtedly run
   into systems this deal doesn't work on.  For now, we apparently have to
   issue a connect() on our just-tickled socket so we can write() back.
   Again, why the fuck doesn't it just get filled in and taken care of?!
   This hack is anything but optimal.  Basically, if you want your listener
   to also be able to send data back, you need this connect() line, which
   also has the side effect that now anything from a different source or even a
   different port on the other end won't show up and will cause ICMP errors.
   I guess that's what they meant by "connect".
   Let's try to remember what the "U" is *really* for, eh? */
    rr = connect(nnetfd, (SA *) remend, sizeof(SA));
    goto whoisit;
  }				/* opt_udpmode */

/* fall here for TCP */
  x = sizeof(SA);		/* retval for accept */
  arm(2, opt_wait);		/* wrap this in a timer, too; 0 = forever */
  if (setjmp(jbuf) == 0) {
    rr = accept(nnetfd, (SA *) remend, &x);
  }
  else
    goto dol_tmo;		/* timeout */
  arm(0, 0);
  close(nnetfd);		/* dump the old socket */
  nnetfd = rr;			/* here's our new one */

whoisit:
  if (rr < 0)
    goto dol_err;		/* bail out if any errors so far */

/* If we can, look for any IP options.  Useful for testing the receiving end of
   such things, and is a good exercise in dealing with it.  We do this before
   the connect message, to ensure that the connect msg is uniformly the LAST
   thing to emerge after all the intervening crud.  Doesn't work for UDP on
   any machines I've tested, but feel free to surprise me. */
#ifdef IP_OPTIONS
  if (!opt_verbose)		/* if we wont see it, we dont care */
    goto dol_noop;
  optbuf = Hmalloc(40);
  x = 40;
  rr = getsockopt(nnetfd, IPPROTO_IP, IP_OPTIONS, optbuf, &x);
  if (rr < 0)
    holler("getsockopt failed");
  debug_d("ipoptions ret len %d\n", x);
  if (x) {	/* we've got options, lessee em... */
    unsigned char *q = (unsigned char *) optbuf;
    char *p = bigbuf_net;	/* local variables, yuk! */
    char *pp = &bigbuf_net[128];	/* get random space farther out... */

    memset(bigbuf_net, 0, 256);	/* clear it all first */
    while (x > 0) {
      sprintf(pp, "%2.2x ", *q);	/* clumsy, but works: turn into hex */
      strcat(p, pp);		/* and build the final string */
      q++;
      p++;
      x--;
    }
    holler("IP options: %s", bigbuf_net);
  }				/* if x, i.e. any options */
dol_noop:
#endif /* IP_OPTIONS */

/* find out what address the connection was *to* on our end, in case we're
   doing a listen-on-any on a multihomed machine.  This allows one to
   offer different services via different alias addresses, such as the
   "virtual web site" hack. */
  memset(bigbuf_net, 0, 64);
  cp = &bigbuf_net[32];
  x = sizeof(SA);
  rr = getsockname(nnetfd, (SA *) lclend, &x);
  if (rr < 0)
    holler("post-rcv getsockname failed");
  strcpy(cp, inet_ntoa(lclend->sin_addr));

/* now check out who it is.  We don't care about mismatched DNS names here,
   but any ADDR and PORT we specified had better fucking well match the caller.
   Converting from addr to inet_ntoa and back again is a bit of a kludge, but
   netcat_resolvehost wants a string and there's much gnarlier code out there already,
   so I don't feel bad.
   The *real* question is why BFD sockets wasn't designed to allow listens for
   connections *from* specific hosts/ports, instead of requiring the caller to
   accept the connection and then reject undesireable ones by closing.  In
   other words, we need a TCP MSG_PEEK. */
  z = ntohs(remend->sin_port);
  strcpy(bigbuf_net, inet_ntoa(remend->sin_addr));
  whozis = netcat_resolvehost(bigbuf_net);
  errno = 0;
  x = 0;			/* use as a flag... */
  if (rad)			/* xxx: fix to go down the *list* if we have one? */
    if (memcmp(rad, whozis->iaddrs, sizeof(SA)))
      x = 1;
  if (rp)
    if (z != rp)
      x = 1;
  if (x)			/* guilty! */
    bail("invalid connection to [%s] from %s [%s] %d",
	 cp, whozis->name, whozis->addrs[0], z);
  holler("connect to [%s] from %s [%s] %d",	/* oh, you're okay.. */
	 cp, whozis->name, whozis->addrs[0], z);
  return nnetfd;		/* open! */

dol_tmo:
  errno = ETIMEDOUT;		/* fake it */
dol_err:
  close(nnetfd);
  return -1;
}				/* dolisten */

/* udptest :
   fire a couple of packets at a UDP target port, just to see if it's really
   there.  On BSD kernels, ICMP host/port-unreachable errors get delivered to
   our socket as ECONNREFUSED write errors.  On SV kernels, we lose; we'll have
   to collect and analyze raw ICMP ourselves a la satan's probe_udp_ports
   backend.  Guess where one could swipe the appropriate code from...

   Use the time delay between writes if given, otherwise use the "tcp ping"
   trick for getting the RTT.  [I got that idea from pluvius, and warped it.]
   Return either the original fd, or clean up and return -1. */
int udptest(int fd, struct in_addr *where)
{
  int rr;

  rr = write(fd, bigbuf_in, 1);
  if (rr != 1)
    holler("udptest first write failed?! errno %d", errno);
  if (opt_wait)
    sleep((unsigned int) opt_wait);
  else {
/* use the tcp-ping trick: try connecting to a normally refused port, which
   causes us to block for the time that SYN gets there and RST gets back.
   Not completely reliable, but it *does* mostly work. */
    opt_udpmode = FALSE;		/* so doconnect does TCP this time */
/* Set a temporary connect timeout, so packet filtration doesnt cause
   us to hang forever, and hit it */
    opt_wait = 5;			/* enough that we'll notice?? */
    rr = doconnect(where, SLEAZE_PORT, 0, 0);
    if (rr > 0)
      close(rr);		/* in case it *did* open */
    opt_wait = 0;		/* reset it */
    opt_udpmode = TRUE;		/* we *are* still doing UDP, right? */
  }				/* if opt_wait */
  errno = 0;			/* clear from sleep */
  rr = write(fd, bigbuf_in, 1);
  if (rr == 1)			/* if write error, no UDP listener */
    return fd;
  close(fd);			/* use it or lose it! */
  return -1;
}				/* udptest */

/* readwrite :
   handle stdin/stdout/network I/O.  Bwahaha!! -- the select loop from hell.
   In this instance, return what might become our exit status. */
int readwrite(int fd)
{
  register int rr;
  register char *zp;		/* stdin buf ptr */
  register char *np;		/* net-in buf ptr */
  unsigned int rzleft;
  unsigned int rnleft;
  USHORT netretry;		/* net-read retry counter */
  USHORT wretry;		/* net-write sanity counter */
  USHORT wfirst;		/* one-shot flag to skip first net read */

/* if you don't have all this FD_* macro hair in sys/types.h, you'll have to
   either find it or do your own bit-bashing: *ding1 |= (1 << fd), etc... */
  if (fd > FD_SETSIZE) {
    holler("Preposterous fd value %d", fd);
    return 1;
  }
  FD_SET(fd, ding1);		/* global: the net is open */
  netretry = 2;
  wfirst = 0;
  rzleft = rnleft = 0;
  if (insaved) {
    rzleft = insaved;		/* preload multi-mode fakeouts */
    zp = bigbuf_in;
    wfirst = 1;
    if (Single)			/* if not scanning, this is a one-off first */
      insaved = 0;		/* buffer left over from argv construction, */
    else {
      FD_CLR(0, ding1);		/* OR we've already got our repeat chunk, */
      close(0);			/* so we won't need any more stdin */
    }				/* Single */
  }				/* insaved */
  if (o_interval)
    sleep(o_interval);		/* pause *before* sending stuff, too */
  errno = 0;			/* clear from sleep, close, whatever */

/* and now the big ol' select shoveling loop ... */
  while (FD_ISSET(fd, ding1)) {	/* i.e. till the *net* closes! */
    wretry = 8200;		/* more than we'll ever hafta write */
    if (wfirst) {		/* any saved stdin buffer? */
      wfirst = 0;		/* clear flag for the duration */
      goto shovel;		/* and go handle it first */
    }
    *ding2 = *ding1;		/* FD_COPY ain't portable... */
/* some systems, notably linux, crap into their select timers on return, so
   we create a expendable copy and give *that* to select.  *Fuck* me ... */
    if (timer1)
      memcpy(timer2, timer1, sizeof(struct timeval));
    rr = select(16, ding2, 0, 0, timer2);	/* here it is, kiddies */
    if (rr < 0) {
      if (errno != EINTR) {	/* might have gotten ^Zed, etc ? */
	holler("select fuxored");
	close(fd);
	return 1;
      }
    }				/* select fuckup */
/* if we have a timeout AND stdin is closed AND we haven't heard anything
   from the net during that time, assume it's dead and close it too. */
    if (rr == 0) {
      if (!FD_ISSET(0, ding1))
	netretry--;		/* we actually try a coupla times. */
      if (!netretry) {
	if (opt_verbose > 1)	/* normally we don't care */
	  holler("net timeout");
	close(fd);
	return 0;		/* not an error! */
      }
    }				/* select timeout */
/* xxx: should we check the exception fds too?  The read fds seem to give
   us the right info, and none of the examples I found bothered. */

/* Ding!!  Something arrived, go check all the incoming hoppers, net first */
    if (FD_ISSET(fd, ding2)) {	/* net: ding! */
      rr = read(fd, bigbuf_net, BIGSIZ);
      if (rr <= 0) {
	FD_CLR(fd, ding1);	/* net closed, we'll finish up... */
	rzleft = 0;		/* can't write anymore: broken pipe */
      }
      else {
	rnleft = rr;
	np = bigbuf_net;
	if (opt_telnet)
	  atelnet(np, rr);	/* fake out telnet stuff */
      }				/* if rr */
      debug_d("got %d from the net, errno %d\n", rr, errno);
    }	/* net:ding */

/* if we're in "slowly" mode there's probably still stuff in the stdin
   buffer, so don't read unless we really need MORE INPUT!  MORE INPUT! */
    if (rzleft)
      goto shovel;

/* okay, suck more stdin */
    if (FD_ISSET(0, ding2)) {	/* stdin: ding! */
      rr = read(0, bigbuf_in, BIGSIZ);
/* Considered making reads here smaller for UDP mode, but 8192-byte
   mobygrams are kinda fun and exercise the reassembler. */
      if (rr <= 0) {		/* at end, or fukt, or ... */
	FD_CLR(0, ding1);	/* disable and close stdin */
	close(0);
      }
      else {
	rzleft = rr;
	zp = bigbuf_in;
/* special case for multi-mode -- we'll want to send this one buffer to every
   open TCP port or every UDP attempt, so save its size and clean up stdin */
	if (!Single) {		/* we might be scanning... */
	  insaved = rr;		/* save len */
	  FD_CLR(0, ding1);	/* disable further junk from stdin */
	  close(0);		/* really, I mean it */
	}			/* Single */
      }				/* if rr/read */
    }				/* stdin:ding */

  shovel:
/* now that we've dingdonged all our thingdings, send off the results.
   Geez, why does this look an awful lot like the big loop in "rsh"? ...
   not sure if the order of this matters, but write net -> stdout first. */

/* sanity check.  Works because they're both unsigned... */
    if ((rzleft > 8200) || (rnleft > 8200)) {
      holler("Bogus buffers: %d, %d", rzleft, rnleft);
      rzleft = rnleft = 0;
    }
/* net write retries sometimes happen on UDP connections */
    if (!wretry) {		/* is something hung? */
      holler("too many output retries");
      return 1;
    }
    if (rnleft) {
      rr = write(1, np, rnleft);
      if (rr > 0) {
	if (opt_hexdump)
	  netcat_fhexdump(output_fd, np, rr);	/* log the stdout */
	np += rr;		/* fix up ptrs and whatnot */
	rnleft -= rr;		/* will get sanity-checked above */
	wrote_out += rr;	/* global count */
      }
      debug_d("wrote %d to stdout, errno %d\n", rr, errno);
    }	/* rnleft */
    if (rzleft) {
      if (o_interval)		/* in "slowly" mode ?? */
	rr = findline(zp, rzleft);
      else
	rr = rzleft;
      rr = write(fd, zp, rr);	/* one line, or the whole buffer */
      if (rr > 0) {
	if (opt_hexdump)
	  netcat_fhexdump(output_fd, zp, rr);	/* log what got sent */
	zp += rr;
	rzleft -= rr;
	wrote_net += rr;	/* global count */
      }
      debug_d("wrote %d to net, errno %d\n", rr, errno);
    }	/* rzleft */
    if (o_interval) {		/* cycle between slow lines, or ... */
      sleep(o_interval);
      errno = 0;		/* clear from sleep */
      continue;			/* ...with hairy select loop... */
    }
    if ((rzleft) || (rnleft)) {	/* shovel that shit till they ain't */
      wretry--;			/* none left, and get another load */
      goto shovel;
    }
  }				/* while ding1:netfd is open */

/* XXX: maybe want a more graceful shutdown() here, or screw around with
   linger times??  I suspect that I don't need to since I'm always doing
   blocking reads and writes and my own manual "last ditch" efforts to read
   the net again after a timeout.  I haven't seen any screwups yet, but it's
   not like my test network is particularly busy... */
  close(fd);
  return 0;
}				/* readwrite */

/* main :
   now we pull it all together... */
int main(int argc, char *argv[])
{
  register int x;
  register char *cp;
  netcat_host *gp;
  netcat_host *whereto = NULL;
  netcat_host *wherefrom = NULL;
  struct in_addr *ouraddr = NULL;
  struct in_addr *themaddr = NULL;
  USHORT o_lport = 0;
  USHORT ourport = 0;
  USHORT loport = 0;		/* for scanning stuff */
  USHORT hiport = 0;
  USHORT curport = 0;
  char *randports = NULL;

  int c;

#ifdef HAVE_BIND
/* can *you* say "cc -yaddayadda netcat.c -lresolv -l44bsd" on SunLOSs? */
  res_init();
#endif
/* I was in this barbershop quartet in Skokie IL ... */
/* round up the usual suspects, i.e. malloc up all the stuff we need */
  lclend = (struct sockaddr_in *) Hmalloc(sizeof(SA));
  remend = (struct sockaddr_in *) Hmalloc(sizeof(SA));
  bigbuf_in = Hmalloc(BIGSIZ);
  bigbuf_net = Hmalloc(BIGSIZ);
  ding1 = (fd_set *) Hmalloc(sizeof(fd_set));
  ding2 = (fd_set *) Hmalloc(sizeof(fd_set));

  errno = 0;
  gatesptr = 4;
  h_errno = 0;

/* catch a signal or two for cleanup */
  signal(SIGINT, catch);
  signal(SIGQUIT, catch);
  signal(SIGTERM, catch);
/* and suppress others... */
#ifdef SIGURG
  signal(SIGURG, SIG_IGN);
#endif
#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);	/* important! */
#endif

  /* if no args given at all, get them from stdin */
  if (argc == 1)
    netcat_commandline(&argc, &argv);

  while (TRUE) {
    int option_index = 0;
    static const struct option long_options[] = {
	{ "gateway",	required_argument,	NULL, 'g' },
	{ "pointer",	required_argument,	NULL, 'G' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "listen",	no_argument,		NULL, 'l' },
	{ "dont-resolve", no_argument,		NULL, 'n' },
	{ "output",	required_argument,	NULL, 'o' },
	{ "local-port",	required_argument,	NULL, 'p' },
	{ "randomize",	no_argument,		NULL, 'r' },
	{ "telnet",	no_argument,		NULL, 't' },
	{ "udp",		no_argument,		NULL, 'u' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "hexdump",	no_argument,		NULL, 'x' },
	{ "wait",	required_argument,	NULL, 'w' },
	{ "zero",	no_argument,		NULL, 'z' },
	{ 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "g:G:hi:lno:p:rtuvxw:z", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
#ifdef GAPING_SECURITY_HOLE
    case 'e':			/* prog to exec */
      pr00gie = optarg;
      break;
#endif
    case 'G':			/* srcrt gateways pointer val */
      x = atoi(optarg);
      if ((x) && (x == (x & 0x1c)))	/* mask off bits of fukt values */
	gatesptr = x;
      else
	bail("invalid hop pointer %d, must be multiple of 4 <= 28", x);
      break;
    case 'g':			/* srcroute hop[s] */
      if (gatesidx > 8)
	bail("too many -g hops");
      if (gates == NULL)	/* eat this, Billy-boy */
	gates = (netcat_host **) Hmalloc(sizeof(netcat_host *) * 10);
      gp = netcat_resolvehost(optarg);
      if (gp)
	gates[gatesidx] = gp;
      gatesidx++;
      break;
    case 'h':
      netcat_printhelp(argv[0]);
      exit(EXIT_SUCCESS);
    case 'i':			/* line-interval time */
      o_interval = atoi(optarg) & 0xffff;
      if (!o_interval)
	bail("invalid interval time %s", optarg);
      break;
    case 'l':			/* listen mode */
      opt_listen = TRUE;
      break;
    case 'n':			/* numeric-only, no DNS lookups */
      opt_numeric++;
      break;
    case 'o':			/* hexdump log */
      opt_outputfile = strdup(optarg);
      opt_hexdump = TRUE;	/* implied */
      break;
    case 'p':			/* local source port */
      netcat_getport(&portpoop, optarg, 0);
      o_lport = portpoop.num;
      if (o_lport == 0)
	bail("invalid local port %s", optarg);
      break;
    case 'r':			/* randomize various things */
      opt_random = TRUE;
      break;
    case 's':			/* local source address */
/* do a full lookup [since everything else goes through the same mill],
   unless -n was previously specified.  In fact, careful placement of -n can
   be useful, so we'll still pass opt_numeric here instead of forcing numeric.  */
      wherefrom = netcat_resolvehost(optarg);
      ouraddr = &wherefrom->iaddrs[0];
      break;
    case 't':			/* do telnet fakeout */
      opt_telnet++;
      break;
    case 'u':			/* use UDP */
      opt_udpmode = TRUE;
      break;
    case 'v':			/* verbose */
      opt_verbose++;
      break;
    case 'V':			/* display version and exit */
      netcat_printversion();
      exit(EXIT_SUCCESS);
    case 'w':			/* wait time */
      opt_wait = atoi(optarg);
      if (opt_wait <= 0) {
	fprintf(stderr, "Error: invalid wait-time: %s\n", optarg);
	exit(EXIT_FAILURE);
      }
      timer1 = (struct timeval *) Hmalloc(sizeof(struct timeval));
      timer2 = (struct timeval *) Hmalloc(sizeof(struct timeval));
      timer1->tv_sec = opt_wait;	/* we need two.  see readwrite()... */
      break;
    case 'x':			/* hexdump traffic */
      opt_hexdump = TRUE;
      break;
    case 'z':			/* little or no data xfer */
      opt_zero++;
      break;
    default:
      fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
      exit(EXIT_FAILURE);
    }				/* switch c */
  }				/* while getopt */

/* other misc initialization */
  debug_d("fd_set size %d\n", sizeof(*ding1));	/* how big *is* it? */
  FD_SET(0, ding1);		/* stdin *is* initially open */
  if (opt_random) {
    SRAND(time(0));
    randports = Hmalloc(65536);	/* big flag array for ports */
  }
#ifdef GAPING_SECURITY_HOLE
  if (pr00gie) {
    close(0);			/* won't need stdin */
    opt_hexdump = FALSE;		/* -o with -e is meaningless! */
    output_fd = NULL;
  }
#endif /* G_S_H */

  if (opt_outputfile) {
    output_fd = fopen(opt_outputfile, "w");
    if (!output_fd) {
      perror("Failed to open output file: ");
      exit(EXIT_FAILURE);
    }
  }
  else
    output_fd = stdout;


/* optind is now index of first non -x arg */
  debug_d("after go: x now %c, optarg %x optind %d\n", x, (int)optarg, optind);
/* Debug (("optind up to %d at host-arg %s", optind, argv[optind])) */
/* gonna only use first addr of host-list, like our IQ was normal; if you wanna
   get fancy with addresses, look up the list yourself and plug 'em in for now.
   unless we finally implement -a, that is. */
    if (argv[optind])
    whereto = netcat_resolvehost(argv[optind]);
  if (whereto && whereto->iaddrs)
    themaddr = &whereto->iaddrs[0];
  if (themaddr)
    optind++;			/* skip past valid host lookup */
  errno = 0;
  h_errno = 0;

/* Handle listen mode here, and exit afterward.  Only does one connect;
   this is arguably the right thing to do.  A "persistent listen-and-fork"
   mode a la inetd has been thought about, but not implemented.  A tiny
   wrapper script can handle such things... */
  if (opt_listen) {
    curport = 0;		/* rem port *can* be zero here... */
    if (argv[optind]) {		/* any rem-port-arg? */
      netcat_getport(&portpoop, argv[optind], 0);
      curport = portpoop.num;
      if (curport == 0)		/* if given, demand correctness */
	bail("invalid port %s", argv[optind]);
    }				/* if port-arg */
    netfd = dolisten(themaddr, curport, ouraddr, o_lport);
/* dolisten does its own connect reporting, so we don't holler anything here */
    if (netfd > 0) {
#ifdef GAPING_SECURITY_HOLE
      if (pr00gie)		/* -e given? */
	doexec(netfd);
#endif /* GAPING_SECURITY_HOLE */
      x = readwrite(netfd);	/* it even works with UDP! */
      if (opt_verbose > 1)	/* normally we don't care */
	holler(wrote_txt, wrote_net, wrote_out);
      exit(x);			/* "pack out yer trash" */
    }
    else			/* if no netfd */
      bail("no connection");
  }				/* opt_listen */

/* fall thru to outbound connects.  Now we're more picky about args... */
  if (!themaddr)
    bail("no destination");
  if (argv[optind] == NULL)
    bail("no port[s] to connect to");
  if (argv[optind + 1])		/* look ahead: any more port args given? */
    Single = 0;			/* multi-mode, case A */
  ourport = o_lport;		/* which can be 0 */

/* everything from here down is treated as as ports and/or ranges thereof, so
   it's all enclosed in this big ol' argv-parsin' loop.  Any randomization is
   done within each given *range*, but in separate chunks per each succeeding
   argument, so we can control the pattern somewhat. */
  while (argv[optind]) {
    hiport = loport = 0;
    cp = strchr(argv[optind], '-');	/* nn-mm range? */
    if (cp) {
      *cp = '\0';
      cp++;
      netcat_getport(&portpoop, cp, 0);
      hiport = portpoop.num;
      if (hiport == 0)
	bail("invalid port %s", cp);
    }				/* if found a dash */
    netcat_getport(&portpoop, argv[optind], 0);
    loport = portpoop.num;
    if (loport == 0)
      bail("invalid port %s", argv[optind]);
    if (hiport > loport) {	/* was it genuinely a range? */
      Single = 0;		/* multi-mode, case B */
      curport = hiport;		/* start high by default */
      if (opt_random) {		/* maybe populate the random array */
	loadports(randports, loport, hiport);
	curport = nextport(randports);
      }
    }
    else			/* not a range, including args like "25-25" */
      curport = loport;
    debug_d("Single %d, curport %d\n", Single, curport);
/* Now start connecting to these things.  curport is already preloaded. */
    while (loport <= curport) {
      if ((!o_lport) && (opt_random)) {	/* -p overrides random local-port */
	ourport = (RAND() & 0xffff);	/* random local-bind -- well above */
	if (ourport < 8192)	/* resv and any likely listeners??? */
	  ourport += 8192;	/* if it *still* conflicts, use -s. */
      }
      netcat_getport(&portpoop, NULL, curport);
      curport = portpoop.num;
      netfd = doconnect(themaddr, curport, ouraddr, ourport);
      debug_d("netfd %d from port %d to port %d\n", netfd, ourport,
	     curport);
      if (netfd > 0)
	if (opt_zero && opt_udpmode)	/* if UDP scanning... */
	  netfd = udptest(netfd, themaddr);
      if (netfd > 0) {		/* Yow, are we OPEN YET?! */
	x = 0;			/* pre-exit status */
	holler("%s [%s] %d (%s) open",
	       whereto->name, whereto->addrs[0], curport, portpoop.name);
#ifdef GAPING_SECURITY_HOLE
	if (pr00gie)		/* exec is valid for outbound, too */
	  doexec(netfd);
#endif /* GAPING_SECURITY_HOLE */
	if (!opt_zero)
	  x = readwrite(netfd);	/* go shovel shit */
      }
      else {			/* no netfd... */
	x = 1;			/* preload exit status for later */
/* if we're scanning at a "one -v" verbosity level, don't print refusals.
   Give it another -v if you want to see everything. */
	if ((Single || (opt_verbose > 1)) || (errno != ECONNREFUSED))
	  holler("%s [%s] %d (%s)",
		 whereto->name, whereto->addrs[0], curport, portpoop.name);
      }				/* if netfd */
      close(netfd);		/* just in case we didn't already */
      if (o_interval)
	sleep(o_interval);	/* if -i, delay between ports too */
      if (opt_random)
	curport = nextport(randports);
      else
	curport--;		/* just decrement... */
    }				/* while curport within current range */
    optind++;
  }				/* while remaining port-args -- end of big argv-ports loop */

  errno = 0;
  if (opt_verbose > 1)		/* normally we don't care */
    holler(wrote_txt, wrote_net, wrote_out);
  if (Single)
    exit(x);			/* give us status on one connection */
  exit(0);			/* otherwise, we're just done */
}				/* main */
