/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Author : Guillaume TEISSIER from FTR&D 02/02/2006
 */
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#if defined(__HPUX) || defined(__CYGWIN) || defined(__FreeBSD__)
#include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#ifndef __CYGWIN
#include <netinet/ip6.h>
#endif
#include <string.h>

#include "prepare_pcap.h"
#include "screen.hpp"

/* We define our own structures for Ethernet Header and IPv6 Header as they are not available on CYGWIN.
 * We only need the fields, which are necessary to determine the type of the next header.
 * we could also define our own structures for UDP and IPv4. We currently use the structures
 * made available by the platform, as we had no problems to get them on all supported platforms.
 */

typedef struct _ether_hdr {
    char ether_dst[6];
    char ether_src[6];
    u_int16_t ether_type; /* we only need the type, so we can determine, if the next header is IPv4 or IPv6 */
} ether_hdr;

typedef struct _ipv6_hdr {
    char dontcare[6];
    u_int8_t nxt_header; /* we only need the next header, so we can determine, if the next header is UDP or not */
    char dontcare2[33];
} ipv6_hdr;


#ifdef __HPUX
int check(u_int16_t *buffer, int len)
{
#else
inline int check(u_int16_t *buffer, int len)
{
#endif
    int sum;
    int i;
    sum = 0;

    for (i=0; i<(len&~1); i+= 2)
        sum += *buffer++;

    if (len & 1) {
        sum += htons( (*(const u_int8_t *)buffer) << 8);
    }
    return sum;
}

#ifdef __HPUX
u_int16_t checksum_carry(int s)
{
#else
inline u_int16_t checksum_carry(int s)
{
#endif
    int s_c = (s >> 16) + (s & 0xffff);
    return (~(s_c + (s_c >> 16)) & 0xffff);
}

char errbuf[PCAP_ERRBUF_SIZE];

/* prepare a pcap file
 */
int prepare_pkts(char *file, pcap_pkts *pkts)
{
    pcap_t *pcap;
    struct pcap_pkthdr *pkthdr = NULL;
    u_char *pktdata = NULL;
    int n_pkts = 0;
    u_long max_length = 0;
    u_int16_t base = 0xffff;
    u_long pktlen;
    pcap_pkt *pkt_index;
    ether_hdr *ethhdr;
    struct iphdr *iphdr;
    ipv6_hdr *ip6hdr;
    struct udphdr *udphdr;

    pkts->pkts = NULL;

    pcap = pcap_open_offline(file, errbuf);
    if (!pcap)
        ERROR("Can't open PCAP file '%s'", file);

#if HAVE_PCAP_NEXT_EX
    while (pcap_next_ex (pcap, &pkthdr, (const u_char **) &pktdata) == 1) {
#else
#ifdef __HPUX
    pkthdr = (pcap_pkthdr *) malloc (sizeof (*pkthdr));
#else
    pkthdr = malloc (sizeof (*pkthdr));
#endif
    if (!pkthdr)
        ERROR("Can't allocate memory for pcap pkthdr");
    while ((pktdata = (u_char *) pcap_next (pcap, pkthdr)) != NULL) {
#endif
        ethhdr = (ether_hdr *)pktdata;
        if (ntohs(ethhdr->ether_type) != 0x0800 /* IPv4 */
                && ntohs(ethhdr->ether_type) != 0x86dd) { /* IPv6 */
            fprintf(stderr, "Ignoring non IP{4,6} packet!\n");
            continue;
        }
        iphdr = (struct iphdr *)((char *)ethhdr + sizeof(*ethhdr));
        if (iphdr && iphdr->version == 6) {
            //ipv6
            pktlen = (u_long) pkthdr->len - sizeof(*ethhdr) - sizeof(*ip6hdr);
            ip6hdr = (ipv6_hdr *)(void *) iphdr;
            if (ip6hdr->nxt_header != IPPROTO_UDP) {
                fprintf(stderr, "prepare_pcap.c: Ignoring non UDP packet!\n");
                continue;
            }
            udphdr = (struct udphdr *)((char *)ip6hdr + sizeof(*ip6hdr));
        } else {
            //ipv4
            if (iphdr->protocol != IPPROTO_UDP) {
                fprintf(stderr, "prepare_pcap.c: Ignoring non UDP packet!\n");
                continue;
            }
#if defined(__DARWIN) || defined(__CYGWIN) || defined(__FreeBSD__)
            udphdr = (struct udphdr *)((char *)iphdr + (iphdr->ihl << 2) + 4);
            pktlen = (u_long)(ntohs(udphdr->uh_ulen));
#elif defined ( __HPUX)
            udphdr = (struct udphdr *)((char *)iphdr + (iphdr->ihl << 2));
            pktlen = (u_long) pkthdr->len - sizeof(*ethhdr) - sizeof(*iphdr);
#else
            udphdr = (struct udphdr *)((char *)iphdr + (iphdr->ihl << 2));
            pktlen = (u_long)(ntohs(udphdr->len));
#endif
        }
        if (pktlen > PCAP_MAXPACKET) {
            ERROR("Packet size is too big! Recompile with bigger PCAP_MAXPACKET in prepare_pcap.h");
        }
        pkts->pkts = (pcap_pkt *) realloc(pkts->pkts, sizeof(*(pkts->pkts)) * (n_pkts + 1));
        if (!pkts->pkts)
            ERROR("Can't re-allocate memory for pcap pkt");
        pkt_index = pkts->pkts + n_pkts;
        pkt_index->pktlen = pktlen;
        pkt_index->ts = pkthdr->ts;
        pkt_index->data = (unsigned char *) malloc(pktlen);
        if (!pkt_index->data)
            ERROR("Can't allocate memory for pcap pkt data");
        memcpy(pkt_index->data, udphdr, pktlen);

#if defined(__HPUX) || defined(__DARWIN) || (defined __CYGWIN) || defined(__FreeBSD__)
        udphdr->uh_sum = 0 ;
#else
        udphdr->check = 0;
#endif

        // compute a partial udp checksum
        // not including port that will be changed
        // when sending RTP
#if defined(__HPUX) || defined(__DARWIN) || (defined __CYGWIN) || defined(__FreeBSD__)
        pkt_index->partial_check = check((u_int16_t *) &udphdr->uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
#else
        pkt_index->partial_check = check((u_int16_t *) &udphdr->len, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
#endif
        if (max_length < pktlen)
            max_length = pktlen;
#if defined(__HPUX) || defined(__DARWIN) || (defined __CYGWIN) || defined(__FreeBSD__)
        if (base > ntohs(udphdr->uh_dport))
            base = ntohs(udphdr->uh_dport);
#else
        if (base > ntohs(udphdr->dest))
            base = ntohs(udphdr->dest);
#endif
        n_pkts++;
    }
    pkts->max = pkts->pkts + n_pkts;
    pkts->max_length = max_length;
    pkts->base = base;
    fprintf(stderr, "In pcap %s, npkts %d\nmax pkt length %ld\nbase port %d\n", file, n_pkts, max_length, base);
    pcap_close(pcap);

    return 0;
}
struct rtphdr {
  unsigned char csicnt:4;
  unsigned int extension:1;
  unsigned int  padding:1;
  unsigned char version:2;

  unsigned char payload_type:7;
  unsigned int marker:1;

  u_int16_t seqno;
  u_int32_t timestamp;
  u_int32_t ssrcid;
};

struct rtpevent {
  unsigned char event_id;

  unsigned char volume:6;
  unsigned int reserved:1;
  unsigned int end_of_event:1;

  u_int16_t duration;
};

struct dtmfpacket {
  struct udphdr udp;
  struct rtphdr rtp;
  struct rtpevent dtmf;
};

static u_long dtmf_ssrcid = 0x01020304;

void fill_default_dtmf(struct dtmfpacket * dtmfpacket, int marker, int seqno, int ts, char digit, int eoe, int duration) {
  u_long pktlen = sizeof(struct dtmfpacket);

#if defined(__HPUX) || defined(__DARWIN) || (defined __CYGWIN) || defined(__FreeBSD__)
  dtmfpacket->udp.uh_ulen = htons(pktlen);
  dtmfpacket->udp.uh_sum = 0 ;
  dtmfpacket->udp.uh_sport = 0;
  dtmfpacket->udp.uh_dport = 0;
#else
  dtmfpacket->udp.len = htons(pktlen);
  dtmfpacket->udp.check = 0;
  dtmfpacket->udp.source = 0;
  dtmfpacket->udp.dest = 0;
#endif
  dtmfpacket->rtp.version = 2;
  dtmfpacket->rtp.padding = 0;
  dtmfpacket->rtp.extension = 0;
  dtmfpacket->rtp.csicnt = 0;
  dtmfpacket->rtp.marker = marker;
  dtmfpacket->rtp.payload_type = 0x60;
  dtmfpacket->rtp.seqno = htons(seqno);
  dtmfpacket->rtp.timestamp = htonl(ts);
  dtmfpacket->rtp.ssrcid = dtmf_ssrcid;

  dtmfpacket->dtmf.event_id = digit;
  dtmfpacket->dtmf.end_of_event = eoe;
  dtmfpacket->dtmf.volume = 10;
  dtmfpacket->dtmf.duration = htons(duration * 8);
}

/* prepare a dtmf pcap 
 */
int prepare_dtmf(char *digits, pcap_pkts *pkts, u_int16_t start_seq_no) {
  int n_pkts = 0;
  int n_digits = 0;
  u_long pktlen = sizeof(struct dtmfpacket);
  pcap_pkt *pkt_index;
  char * digit;
  int i;
  char * comma;
  unsigned long tone_len = 200;
  
  dtmf_ssrcid++;

  pkts->pkts = NULL;

  if (comma = strchr(digits,',')) {
    tone_len = atol(comma+1);
    if (tone_len < 50 || tone_len > 2000) tone_len = 200;
    *comma = '\0';
  }

  for(digit = digits; *digit; digit++) {
    unsigned char uc_digit;
    struct dtmfpacket * dtmfpacket;
    unsigned long cur_tone_len = 0;
    unsigned long ts;
    
    if (*digit >= '0' && *digit <= '9') {
      uc_digit = *digit - '0';
    } else if (*digit == '*') {
      uc_digit = 10;
    } else if (*digit == '#') {
      uc_digit = 11;
    } else {
      continue;
    }
      
    while (cur_tone_len < tone_len) {
      ts = (n_digits + 1) * tone_len * 2 + cur_tone_len;

      pkts->pkts = (pcap_pkt *) realloc(pkts->pkts, sizeof(*(pkts->pkts)) * (n_pkts + 1));
      if (!pkts->pkts) {
        ERROR("Can't re-allocate memory for dtmf pcap pkt");
      }

      pkt_index = pkts->pkts + n_pkts;
      pkt_index->pktlen = pktlen;
      pkt_index->ts.tv_sec = ts / 1000;
      pkt_index->ts.tv_usec = (ts % 1000) * 1000;
      pkt_index->data = (unsigned char *) malloc(pktlen);
      if (!pkt_index->data) {
        ERROR("Can't allocate memory for pcap pkt data");
      }

      dtmfpacket = (struct dtmfpacket*)pkt_index->data;

      fill_default_dtmf(dtmfpacket, n_pkts == 0, n_pkts + start_seq_no, n_digits * tone_len * 2 + 24000, uc_digit, 0, cur_tone_len);

#if defined(__HPUX) || defined(__DARWIN) || (defined __CYGWIN) || defined(__FreeBSD__)
      pkt_index->partial_check = check((u_int16_t *) &dtmfpacket->udp.uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
#else
      pkt_index->partial_check = check((u_int16_t *) &dtmfpacket->udp.len, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
#endif
      n_pkts++;
      cur_tone_len += 20;
    }
    
    for(i = 0; i < 3; i++) {
      ts = (n_digits + 1) * tone_len * 2 + tone_len + i + 1;
      pkts->pkts = (pcap_pkt *) realloc(pkts->pkts, sizeof(*(pkts->pkts)) * (n_pkts + 1));
      if (!pkts->pkts) {
        ERROR("Can't re-allocate memory for dtmf pcap pkt");
      }

      pkt_index = pkts->pkts + n_pkts;
      pkt_index->pktlen = pktlen;
      pkt_index->ts.tv_sec = ts / 1000;
      pkt_index->ts.tv_usec = (ts % 1000) * 1000;
      pkt_index->data = (unsigned char *) malloc(pktlen);
      if (!pkt_index->data) {
        ERROR("Can't allocate memory for pcap pkt data");
      }

      dtmfpacket = (struct dtmfpacket*)pkt_index->data;

      fill_default_dtmf(dtmfpacket, 0, n_pkts + start_seq_no, n_digits * tone_len * 2 + 24000, uc_digit, 1, tone_len);

#if defined(__HPUX) || defined(__DARWIN) || (defined __CYGWIN) || defined(__FreeBSD__)
      pkt_index->partial_check = check((u_int16_t *) &dtmfpacket->udp.uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
#else
      pkt_index->partial_check = check((u_int16_t *) &dtmfpacket->udp.len, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
#endif
      n_pkts++;
    }

    n_digits++;
  }

  pkts->max = pkts->pkts + n_pkts;
  pkts->max_length = pktlen;
  pkts->base = 0;

  return n_pkts;
}
