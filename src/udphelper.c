/*
 * udphelper.c -- advanced udp routines for portability
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: udphelper.c,v 1.2 2002-07-03 13:10:17 themnemonic Exp $
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

#ifndef USE_PKTINFO
#include <sys/ioctl.h>
#include <net/if.h>
#endif

#ifdef USE_PKTINFO

/* Reads the ancillary data buffer for the given msghdr and extracts the packet
   destination address which is copied to the `get_addr' struct.
   Returns 0 on success, a negative value otherwise. */

int udphelper_ancillary_read(struct msghdr *my_hdr,
			     struct sockaddr_in *get_addr)
{
  /* let's hope that there is some ancillary data! */
  if (my_hdr->msg_controllen > 0) {
    struct cmsghdr *get_cmsg;

    /* We don't know which is the order of the ancillary messages and we don't
       know how many are there.  So I simply parse all of them until we find
       the right one, checking the index type. */
    for (get_cmsg = CMSG_FIRSTHDR(my_hdr); get_cmsg;
	 get_cmsg = CMSG_NXTHDR(my_hdr, get_cmsg)) {
      debug_v("Analizing ancillary header (id=%d)", get_cmsg->cmsg_type);

      if (get_cmsg->cmsg_type == IP_PKTINFO) {
	struct in_pktinfo *get_pktinfo;

	/* fetch the data and run away, we don't need to parse everything */
	get_pktinfo = (struct in_pktinfo *) CMSG_DATA(get_cmsg);
	memcpy(&get_addr->sin_addr, &get_pktinfo->ipi_spec_dst, sizeof(get_addr->sin_addr));
	return 0;
      }
    }
  }

  return -1;
}

#else	/* USE_PKTINFO */

/* This function opens an array of sockets (stored in `sockbuf'), one for each
   different interface in the current machine.  The purpose of this is to allow
   the application to determine which interface received the packet that
   otherwise would be unknown.
   Return -1 if an error occurred; otherwise the return value is a file
   descriptor referencing the first socket in the array.
   On success, at least one socket is returned. */

int udphelper_sockets_open(int **sockbuf, in_port_t nport)
{
  int ret, i, alloc_size, *my_sockbuf, if_total = 0, sock_total = 0;
  unsigned int if_pos = 0;
  struct ifconf nc_ifconf;
  struct ifreq *nc_ifreq = NULL;

  /* initialize the sockbuf (assuming the function will be positive */
  my_sockbuf = malloc(sizeof(int));
  if (!my_sockbuf) {
    errno = ENOMEM;
    return -1;
  }

  /* this is a dummy socket needed for the ioctl(2) call (this just tells the
     kernel where to look for the needed API */
  my_sockbuf[0] = socket(PF_INET, SOCK_DGRAM, 0);
  if (my_sockbuf[0] < 0)
    goto err;

  /* find out how many interface we have around */
  do { /* FIXME: set max buffer size (what is max if num?) */
    /* try with bigger steps in order not to do too many ioctls on systems with
       many interfaces. */
    if_total += 5;
    alloc_size = if_total * sizeof(*nc_ifreq);

    /* like many other syscalls, ioctl() will adjust ifc_len to the REAL
       ifc_len, so try to allocate a larger buffer in order to determine
       the total interfaces number. */
    free(nc_ifreq);	/* don't use realloc here, this way it is faster. */
    nc_ifreq = malloc(alloc_size);
    nc_ifconf.ifc_len = alloc_size;
    nc_ifconf.ifc_req = nc_ifreq;

    ret = ioctl(my_sockbuf[0], SIOCGIFCONF, (char *)&nc_ifconf);
    if (ret < 0)
      goto err;

  } while (nc_ifconf.ifc_len >= (if_total * sizeof(*nc_ifreq)));

  /* Now loop */
  if_total = 0;
  while (if_pos < nc_ifconf.ifc_len) {
    int newsock;
    struct sockaddr_in *if_addr;

    nc_ifreq = (struct ifreq *)((char *)nc_ifconf.ifc_req + if_pos);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
    if (nc_ifreq->ifr_addr.sa_len > sizeof(struct sockaddr))
      if_pos += sizeof(nc_ifreq->ifr_name) + nc_ifreq->ifr_addr.sa_len;
    else
      if_pos += sizeof(*nc_ifreq);
#else
    if_pos += sizeof(*nc_ifreq);
#endif

    /* truncated? */
    assert(if_pos <= nc_ifconf.ifc_len);

    if_total++;

    /* discard any interface not devoted to IP */
    if (nc_ifreq->ifr_addr.sa_family != AF_INET)
      continue;
    if_addr = (struct sockaddr_in *)&nc_ifreq->ifr_addr;

    /* we need to sort out interesting interfaces, so fetch the interface
       flags */
    ret = ioctl(my_sockbuf[0], SIOCGIFFLAGS, (char *)nc_ifreq);
    if (ret < 0)
      goto err;

    /* check that this interface is up and running */
    if (!(nc_ifreq->ifr_flags & IFF_UP))
      continue;

    debug("(udphelper) Found interface %s (IP address: %s)\n",
	  nc_ifreq->ifr_name, netcat_inet_ntop(&if_addr->sin_addr));

    newsock = socket(PF_INET, SOCK_DGRAM, 0);
    if (newsock < 0)
      goto err;

    /* update immediately the sockets buffer so that any following error would
       close this one in the cleanup. */
    my_sockbuf = realloc(my_sockbuf, ++sock_total * sizeof(int));
    my_sockbuf[sock_total] = newsock;

    /* FIXME: WHY does SIOCGIFFLAGS mess with sin_family?? */
    if_addr->sin_family = AF_INET;
    if_addr->sin_port = nport;
    /* FIXME: nport could be INPORT_ANY, we need to use ONE random value */

    ret = bind(newsock, (struct sockaddr *)if_addr, sizeof(*if_addr));
    if (ret < 0)
      goto err;

  }

  /* ok we don't need anymore the interfaces list */
  free(nc_ifconf.ifc_req);
  nc_ifconf.ifc_req = NULL;

  /* close the "ioctl" socket and replace its value with the total sock num */
  close(my_sockbuf[0]);
  my_sockbuf[0] = sock_total;
  *sockbuf = my_sockbuf;

  debug("(udphelper) Successfully created %d socket(s)\n", sock_total);

  /* On success, return the first socket for the application use, while if no
     valid interefaces were found step forward to the error handling */
  if (my_sockbuf[0] > 0)
    return my_sockbuf[1];

  errno = EAFNOSUPPORT;

 err:
  /* destroy the ifconf struct and buffers */
  free(nc_ifconf.ifc_req);

  /* FIXME: save the errno! */

  /* close all the sockets and free the sockets buffer */
  for (i = 0; i < sock_total; i++)
    close(my_sockbuf[i]);
  free(my_sockbuf);
  *sockbuf = NULL;

  return -1;
}

#endif	/* USE_PKTINFO */

/* ... */

void udphelper_sockets_close(int *sockbuf)
{
  int i;

  if (!sockbuf)
    return;

  for (i = 1; i <= sockbuf[0]; i++)
    if (sockbuf[i] >= 0)
      close(sockbuf[i]);

  free(sockbuf);
}

