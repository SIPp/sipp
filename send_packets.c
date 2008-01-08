/*
 * send_packets.c: from tcpreplay tools by Aaron Turner 
 * http://tcpreplay.sourceforge.net/
 * send_packets.c is under BSD license (see below)
 * SIPp is under GPL license
 *
 *
 * Copyright (c) 2001-2004 Aaron Turner.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*Map linux structure fields to BSD ones*/
#ifdef __LINUX
#define __BSD_SOURCE
#define _BSD_SOURCE
#define __FAVOR_BSD
#endif /*__LINUX*/

#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/udp.h>
#if defined(__DARWIN) || defined(__CYGWIN) || defined(__FreeBSD__)
#include <netinet/in.h>
#endif
#ifndef __CYGWIN
#include <netinet/ip6.h>
#endif
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "send_packets.h"
#include "prepare_pcap.h"
#include "screen.hpp"

extern volatile unsigned long rtp_pckts_pcap;
extern volatile unsigned long rtp_bytes_pcap;
extern int media_ip_is_ipv6;

inline void
timerdiv (struct timeval *tvp, float div)
{
  double interval;

  if (div == 0 || div == 1)
    return;

  interval = ((double) tvp->tv_sec * 1000000 + tvp->tv_usec) / (double) div;
  tvp->tv_sec = interval / (int) 1000000;
  tvp->tv_usec = interval - (tvp->tv_sec * 1000000);
}

/*
 * converts a float to a timeval structure
 */
inline void
float2timer (float time, struct timeval *tvp)
{
  float n;

  n = time;

  tvp->tv_sec = n;

  n -= tvp->tv_sec;
  tvp->tv_usec = n * 100000;
}

/* buffer should be "file_name" */
int
parse_play_args (char *buffer, pcap_pkts *pkts)
{
  pkts->file = strdup (buffer);
  prepare_pkts(pkts->file, pkts);
  return 1;
}

void hexdump(char *p, int s) {
	int i;
	for (i = 0; i < s; i++) {
		fprintf(stderr, "%02x ", *(char *)(p+i));
	}
	fprintf(stderr, "\n");
}

/*Safe threaded version*/
void do_sleep (struct timeval *, struct timeval *,
               struct timeval *, struct timeval *);

int
send_packets (play_args_t * play_args)
{
  int ret, sock, port_diff;
  pcap_pkt *pkt_index, *pkt_max;
  uint16_t *from_port, *to_port;
  struct timeval didsleep = { 0, 0 };
  struct timeval start = { 0, 0 };
  struct timeval last = { 0, 0 };
  pcap_pkts *pkts = play_args->pcap;
	/* to and from are pointers in case play_args (call sticky) gets modified! */
  struct sockaddr_storage *to = &(play_args->to);
  struct sockaddr_storage *from = &(play_args->from);
  struct udphdr *udp;
  struct sockaddr_in6 to6, from6;
  char buffer[PCAP_MAXPACKET];
  int temp_sum;

#ifndef MSG_DONTWAIT
  int fd_flags;
#endif

  if (media_ip_is_ipv6) {
    sock = socket(PF_INET6, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
      ERROR("Can't create raw socket (need to run as root?)");
    }
    from_port = &(((struct sockaddr_in6 *)(void *) from )->sin6_port);
    to_port = &(((struct sockaddr_in6 *)(void *) to )->sin6_port);
  }
  else {
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
      ERROR("Can't create raw socket (need to run as root?)");
    }
    from_port = &(((struct sockaddr_in *)(void *) from )->sin_port);
    to_port = &(((struct sockaddr_in *)(void *) to )->sin_port);
  }
	
#ifndef MSG_DONTWAIT
  fd_flags = fcntl(sock, F_GETFL , NULL);
  fd_flags |= O_NONBLOCK;
  fcntl(sock, F_SETFL , fd_flags);
#endif
  udp = (struct udphdr *)buffer;

  pkt_index = pkts->pkts;
  pkt_max = pkts->max;
	
  if (media_ip_is_ipv6) {
    memset(&to6, 0, sizeof(to6));
    memset(&from6, 0, sizeof(from6));
    to6.sin6_family = AF_INET6;
    from6.sin6_family = AF_INET6;
    memcpy(&(to6.sin6_addr.s6_addr), &(((struct sockaddr_in6 *)(void *) to)->sin6_addr.s6_addr), sizeof(to6.sin6_addr.s6_addr));
    memcpy(&(from6.sin6_addr.s6_addr), &(((struct sockaddr_in6 *)(void *) from)->sin6_addr.s6_addr), sizeof(from6.sin6_addr.s6_addr));
  }
	
  while (pkt_index < pkt_max) {
    memcpy(udp, pkt_index->data, pkt_index->pktlen);
    port_diff = ntohs (udp->uh_dport) - pkts->base;
    // modify UDP ports
    udp->uh_sport = htons(port_diff + *from_port);
    udp->uh_dport = htons(port_diff + *to_port);

    if (!media_ip_is_ipv6) {
      temp_sum = checksum_carry(pkt_index->partial_check + check((u_int16_t *) &(((struct sockaddr_in *)(void *) from)->sin_addr.s_addr), 4) + check((u_int16_t *) &(((struct sockaddr_in *)(void *) to)->sin_addr.s_addr), 4) + check((u_int16_t *) &udp->uh_sport, 4));
    }
    else {
      temp_sum = checksum_carry(pkt_index->partial_check + check((u_int16_t *) &(from6.sin6_addr.s6_addr), 16) + check((u_int16_t *) &(to6.sin6_addr.s6_addr), 16) + check((u_int16_t *) &udp->uh_sport, 4));
    }

#ifndef _HPUX_LI
#ifdef __HPUX
    udp->uh_sum = (temp_sum>>16)+((temp_sum & 0xffff)<<16);
#else
    udp->uh_sum = temp_sum;
#endif
#else
    udp->uh_sum = temp_sum;
#endif

    do_sleep ((struct timeval *) &pkt_index->ts, &last, &didsleep,
		&start);
#ifdef MSG_DONTWAIT
    if (!media_ip_is_ipv6) {
      ret = sendto(sock, buffer, pkt_index->pktlen, MSG_DONTWAIT,
                   (struct sockaddr *)(void *) to, sizeof(struct sockaddr_in));
    }
    else {
      ret = sendto(sock, buffer, pkt_index->pktlen, MSG_DONTWAIT,
                   (struct sockaddr *)(void *) &to6, sizeof(struct sockaddr_in6));
    }
#else
    if (!media_ip_is_ipv6) {
      ret = sendto(sock, buffer, pkt_index->pktlen, 0,
                   (struct sockaddr *)(void *) to, sizeof(struct sockaddr_in));
    }
    else {
      ret = sendto(sock, buffer, pkt_index->pktlen, 0,
                   (struct sockaddr *)(void *) &to6, sizeof(struct sockaddr_in6));
    }
#endif
    if (ret < 0) {
      close(sock);
      WARNING("send_packets.c: sendto failed with error: %s", strerror(errno));
      return( -1);
    }

	  rtp_pckts_pcap++;
    rtp_bytes_pcap += pkt_index->pktlen - sizeof(*udp);
    memcpy (&last, &(pkt_index->ts), sizeof (struct timeval));
    pkt_index++;
	}

  close(sock);
  return 0;
}

/*
 * Given the timestamp on the current packet and the last packet sent,
 * calculate the appropriate amount of time to sleep and do so.
 */
void do_sleep (struct timeval *time, struct timeval *last,
	  struct timeval *didsleep, struct timeval *start)
{
  struct timeval nap, now, delta;
  struct timespec sleep;

  if (gettimeofday (&now, NULL) < 0)
    {
      fprintf (stderr, "Error gettimeofday: %s\n", strerror (errno));
    }

  /* First time through for this file */
  if (!timerisset (last))
    {
      *start = now;
      timerclear (&delta);
      timerclear (didsleep);
    }
  else
    {
      timersub (&now, start, &delta);
    }

  if (timerisset (last) && timercmp (time, last, >))
    {
      timersub (time, last, &nap);
    }
  else
    {
      /* 
       * Don't sleep if this is our first packet, or if the
       * this packet appears to have been sent before the 
       * last packet.
       */
      timerclear (&nap);
    }

  timeradd (didsleep, &nap, didsleep);

  if (timercmp (didsleep, &delta, >))
    {
      timersub (didsleep, &delta, &nap);

      sleep.tv_sec = nap.tv_sec;
      sleep.tv_nsec = nap.tv_usec * 1000;	/* convert ms to ns */

      while ((nanosleep (&sleep, &sleep) == -1) && (errno == -EINTR));
    }
}


