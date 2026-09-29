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

#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

/* On Linux, the plays send their IP headers on an IPPROTO_RAW socket.
 * A raw UDP socket gets a copy of each UDP packet to its address, and
 * it holds its lock while the kernel delivers what it sends: with a
 * socket per playback thread, the copies grow with the calls times the
 * packets, and with one for all, the threads wait on its lock. An
 * IPPROTO_RAW socket gets no packets and takes no lock to send. */
#ifdef __linux__
#define SEND_IP_HEADER 1
#define RAW_PROTOCOL IPPROTO_RAW
#else
#define RAW_PROTOCOL IPPROTO_UDP
#endif

#include "defines.h"
#include "fileutil.h"
#include "send_packets.h"
#include "prepare_pcap.h"
#include "config.h"

#ifndef HAVE_UDP_UH_PREFIX
#define uh_ulen len
#define uh_sum check
#define uh_sport source
#define uh_dport dest
#endif

extern bool media_ip_is_ipv6;

inline void
timerdiv(struct timeval* tvp, float div)
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
float2timer(float time, struct timeval *tvp)
{
    float n;

    n = time;

    tvp->tv_sec = n;

    n -= tvp->tv_sec;
    tvp->tv_usec = n * 100000;
}

int parse_play_args(const char* filename, const char *basepath, pcap_pkts* pkts)
{
    pkts->file = find_file(filename, basepath);
    prepare_pkts(pkts->file, pkts);
    return 1;
}

void free_pcaps(pcap_pkts* pkts)
{
    pcap_pkt *it;
    for (it = pkts->pkts; it != pkts->max; ++it) {
        free(it->data);
    }

    free(pkts->pkts);
    free(pkts->file);
    free(pkts);
}

int parse_dtmf_play_args(const char* buffer, pcap_pkts* pkts, uint16_t start_seq_no)
{
    unsigned long tone_len;
    uint8_t payload_type;
    const char* error;

    pkts->file = strdup(buffer);
    error = parse_dtmf(pkts->file, &tone_len, &payload_type);
    if (error) {
        WARNING("Invalid play_dtmf \"%s\": %s", buffer, error);
    }
    return prepare_dtmf(pkts->file, tone_len, payload_type, pkts, start_seq_no);
}

int send_packets_socket(const struct sockaddr_storage* from)
{
    int sock;
    struct sockaddr_storage bind_addr = {0};
    socklen_t len;
#ifndef MSG_DONTWAIT
    int fd_flags;
#endif

    if (media_ip_is_ipv6) {
        sock = socket(PF_INET6, SOCK_RAW, RAW_PROTOCOL);
        if (sock < 0) {
            ERROR("Can't create raw IPv6 socket (need to run as root?): %s", strerror(errno));
        }
        len = sizeof(struct sockaddr_in6);
    } else {
        sock = socket(PF_INET, SOCK_RAW, RAW_PROTOCOL);
        if (sock < 0) {
            ERROR("Can't create raw IPv4 socket (need to run as root?): %s", strerror(errno));
        }
        len = sizeof(struct sockaddr_in);
    }

    // When binding a raw socket, it doesn't make sense to bind to a particular
    // port, as that's a UDP/TCP concept but the point of a raw socket is that
    // we're writing the headers ourselves. Some systems (like FreeBSD) are
    // strict about this and return EADDRNOTAVAIL if we specify a port, so bind
    // to a sockaddr structure copied from our sending address but with the
    // port set to 0.
    memcpy(&bind_addr, from, len);
    if (media_ip_is_ipv6) {
        ((struct sockaddr_in6 *)&bind_addr)->sin6_port = 0;
    } else {
        ((struct sockaddr_in *)&bind_addr)->sin_port = 0;
    }

    if (bind(sock, (struct sockaddr *)&bind_addr, len)) {
        ERROR("Can't bind media raw socket: %s", strerror(errno));
    }

#ifndef MSG_DONTWAIT
    fd_flags = fcntl(sock, F_GETFL , NULL);
    fd_flags |= O_NONBLOCK;
    fcntl(sock, F_SETFL , fd_flags);
#endif
    return sock;
}

/* Send a packet of a play, with the ports and addresses of the play;
 * 1 if the socket cannot take it now, -1 if it fails */
static int send_packet(int sock, const play_args_t* play, const pcap_pkt* pkt_index)
{
    int ret, port_diff;
    const uint16_t *from_port, *to_port;
    const struct sockaddr_storage *to = &(play->to);
    const struct sockaddr_storage *from = &(play->from);
    struct udphdr *udp;
    struct sockaddr_in6 to6, from6;
    char buffer[sizeof(struct ip6_hdr) + PCAP_MAXPACKET];
    size_t header_len = 0;
    int temp_sum;

#ifdef SEND_IP_HEADER
    header_len = media_ip_is_ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip);
#endif

    if (media_ip_is_ipv6) {
        from_port = &(((const struct sockaddr_in6 *)from)->sin6_port);
        to_port = &(((const struct sockaddr_in6 *)to)->sin6_port);
        memset(&to6, 0, sizeof(to6));
        memset(&from6, 0, sizeof(from6));
        to6.sin6_family = AF_INET6;
        from6.sin6_family = AF_INET6;
        memcpy(&(to6.sin6_addr.s6_addr), &(((const struct sockaddr_in6 *)(const void *) to)->sin6_addr.s6_addr), sizeof(to6.sin6_addr.s6_addr));
        memcpy(&(from6.sin6_addr.s6_addr), &(((const struct sockaddr_in6 *)(const void *) from)->sin6_addr.s6_addr), sizeof(from6.sin6_addr.s6_addr));
    } else {
        from_port = &(((const struct sockaddr_in *)from)->sin_port);
        to_port = &(((const struct sockaddr_in *)to)->sin_port);
    }

    udp = (struct udphdr *)(buffer + header_len);
    memcpy(udp, pkt_index->data, pkt_index->pktlen);
    port_diff = ntohs(udp->uh_dport) - play->pcap->base;
    /* modify UDP ports */
    udp->uh_sport = htons(port_diff + ntohs(*from_port));
    udp->uh_dport = htons(port_diff + ntohs(*to_port));

    if (!media_ip_is_ipv6) {
        temp_sum = checksum_carry(
                pkt_index->partial_check +
                check((uint16_t *) &(((const struct sockaddr_in *)(const void *) from)->sin_addr.s_addr), 4) +
                check((uint16_t *) &(((const struct sockaddr_in *)(const void *) to)->sin_addr.s_addr), 4) +
                check((uint16_t *) &udp->uh_sport, 4));
    } else {
        temp_sum = checksum_carry(
                pkt_index->partial_check +
                check((uint16_t *) &(from6.sin6_addr.s6_addr), 16) +
                check((uint16_t *) &(to6.sin6_addr.s6_addr), 16) +
                check((uint16_t *) &udp->uh_sport, 4));
    }
#if !defined(_HPUX_LI) && defined(__HPUX)
    udp->uh_sum = (temp_sum>>16)+((temp_sum & 0xffff)<<16);
#else
    udp->uh_sum = temp_sum;
#endif

#ifdef SEND_IP_HEADER
    /* the kernel fills in the IPv4 checksum and ID */
    if (media_ip_is_ipv6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)buffer;

        memset(ip6, 0, sizeof(*ip6));
        ip6->ip6_flow = htonl(6 << 28);
        ip6->ip6_plen = htons(pkt_index->pktlen);
        ip6->ip6_nxt = IPPROTO_UDP;
        ip6->ip6_hlim = 64;
        ip6->ip6_src = from6.sin6_addr;
        ip6->ip6_dst = to6.sin6_addr;
    } else {
        struct ip *ip = (struct ip *)buffer;

        memset(ip, 0, sizeof(*ip));
        ip->ip_v = 4;
        ip->ip_hl = sizeof(*ip) / 4;
        ip->ip_len = htons(header_len + pkt_index->pktlen);
        ip->ip_ttl = 64;
        ip->ip_p = IPPROTO_UDP;
        ip->ip_src = ((const struct sockaddr_in *)(const void *) from)->sin_addr;
        ip->ip_dst = ((const struct sockaddr_in *)(const void *) to)->sin_addr;
    }
#endif

#ifdef MSG_DONTWAIT
    if (!media_ip_is_ipv6) {
        ret = sendto(sock, buffer, header_len + pkt_index->pktlen, MSG_DONTWAIT,
                     (const struct sockaddr *)to, sizeof(struct sockaddr_in));
    } else {
        ret = sendto(sock, buffer, header_len + pkt_index->pktlen, MSG_DONTWAIT,
                     (struct sockaddr *)&to6, sizeof(struct sockaddr_in6));
    }
#else
    if (!media_ip_is_ipv6) {
        ret = sendto(sock, buffer, header_len + pkt_index->pktlen, 0,
                     (const struct sockaddr *)to, sizeof(struct sockaddr_in));
    } else {
        ret = sendto(sock, buffer, header_len + pkt_index->pktlen, 0,
                     (struct sockaddr *)&to6, sizeof(struct sockaddr_in6));
    }
#endif
    if (ret < 0) {
        /* the socket cannot take it now, as its send buffer, which all
         * the plays of the socket share, is full: try again */
        if (errno == EAGAIN || errno == ENOBUFS || errno == EINTR) {
            return 1;
        }
        WARNING("send_packets.c: sendto failed with error: %s", strerror(errno));
        return -1;
    }

    rtp_pcap_count(pkt_index->pktlen - sizeof(*udp));
    return 0;
}

/* The plays start on multiples of 20 ms, the usual packet time of RTP:
 * the plays of a capture with a packet time that divides it go at the
 * same phase. */
#define PLAY_SLOT_US 20000

/* The time from a packet of a capture to the next, in microseconds:
 * none if the next one appears to have been sent before it. */
static unsigned long long packet_gap_us(const pcap_pkt* pkt, const pcap_pkt* next)
{
    struct timeval nap;

    if (!timercmp(&next->ts, &pkt->ts, >)) {
        return 0;
    }
    timersub(&next->ts, &pkt->ts, &nap);
    return nap.tv_sec * 1000000ULL + nap.tv_usec;
}

int send_packets_due(int sock, play_args_t* play, unsigned long long now_us,
                     unsigned long long* due_us)
{
    const pcap_pkts *pkts = play->pcap;
    int ret;

    /* The play starts on the next multiple of PLAY_SLOT_US, so that the
     * plays of a thread go at the same phase and it wakes up for them at
     * once: each packet leaves as long after the start as the gaps of
     * the capture up to it add up to, in that millisecond. A packet that
     * appears before the one it follows leaves with it. */
    if (!play->next) {
        play->next = pkts->pkts;
        play->start_us = (now_us + PLAY_SLOT_US - 1) / PLAY_SLOT_US * PLAY_SLOT_US;
        play->next_us = 0;
    }

    while (play->next < pkts->max) {
        unsigned long long packet_us = play->start_us + play->next_us;

        if (packet_us / 1000 > now_us / 1000) {
            *due_us = packet_us - packet_us % 1000;
            return 1;
        }
        ret = send_packet(sock, play, play->next);
        if (ret > 0) {
            /* the packet leaves as soon as the socket takes it */
            *due_us = now_us + 1000;
            return 1;
        } else if (ret < 0) {
            return 0;
        }
        play->next++;
        if (play->next < pkts->max) {
            play->next_us += packet_gap_us(play->next - 1, play->next);
        }
    }
    return 0;
}

void send_packets_end(play_args_t* play)
{
    if (play->free_pcap_when_done && play->pcap) {
        free_pcaps(play->pcap);
    }
    play->pcap = NULL;
    play->next = NULL;
}
