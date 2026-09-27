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
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#if defined(__linux__) && defined(__has_include)
#if __has_include(<linux/filter.h>)
#include <linux/filter.h>
#define HAVE_LINUX_FILTER 1
#endif
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
        sock = socket(PF_INET6, SOCK_RAW, IPPROTO_UDP);
        if (sock < 0) {
            ERROR("Can't create raw IPv6 socket (need to run as root?): %s", strerror(errno));
        }
        len = sizeof(struct sockaddr_in6);
    } else {
        sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
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

#if defined(HAVE_LINUX_FILTER) && defined(SO_ATTACH_FILTER)
    /* Linux gives a raw UDP socket a copy of each UDP packet to its
     * address, which nothing reads: a filter that drops them all keeps
     * them from queueing up on it. */
    {
        struct sock_filter drop_all = BPF_STMT(BPF_RET | BPF_K, 0);
        struct sock_fprog filter = {1, &drop_all};
        setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
    }
#endif

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
    char buffer[PCAP_MAXPACKET];
    int temp_sum;

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

    udp = (struct udphdr *)buffer;
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

#ifdef MSG_DONTWAIT
    if (!media_ip_is_ipv6) {
        ret = sendto(sock, buffer, pkt_index->pktlen, MSG_DONTWAIT,
                     (const struct sockaddr *)to, sizeof(struct sockaddr_in));
    } else {
        ret = sendto(sock, buffer, pkt_index->pktlen, MSG_DONTWAIT,
                     (struct sockaddr *)&to6, sizeof(struct sockaddr_in6));
    }
#else
    if (!media_ip_is_ipv6) {
        ret = sendto(sock, buffer, pkt_index->pktlen, 0,
                     (const struct sockaddr *)to, sizeof(struct sockaddr_in));
    } else {
        ret = sendto(sock, buffer, pkt_index->pktlen, 0,
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

    /* The first packet leaves at once, and each next one as long after
     * it as the gaps of the capture up to it add up to: a packet that
     * appears before the one it follows leaves with it. */
    if (!play->next) {
        play->next = pkts->pkts;
        play->start_us = now_us;
        play->next_us = 0;
    }

    while (play->next < pkts->max) {
        if (play->start_us + play->next_us > now_us) {
            *due_us = play->start_us + play->next_us;
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
