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
#ifndef PREPARE_PCAP_H
#define PREPARE_PCAP_H 1
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <time.h>
#include <stdint.h>

#if defined(__HPUX) || defined(__DARWIN) || defined(__CYGWIN) || defined(__FreeBSD__)
struct iphdr {
#ifdef _HPUX_LI
    unsigned int ihl:4;
    unsigned int version:4;
#else
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};

#endif

typedef struct {
    uint8_t *data;
    uint64_t pktlen;
    struct timeval ts;
    int partial_check;
} pcap_pkt;

#define PCAP_MAXPACKET 1500
typedef struct {
    char *file;
    uint16_t base;
    uint64_t max_length;
    pcap_pkt *max;
    pcap_pkt *pkts;
} pcap_pkts;

#ifdef __cplusplus
extern "C" {
#endif
    int check(uint16_t *, int);
    uint16_t checksum_carry(int);
    int prepare_pkts(char *, pcap_pkts *);
#ifdef __cplusplus
}
#endif
#endif /* PREPARE_PCAP_H */
