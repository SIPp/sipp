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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#include "defines.h"
#include "endianshim.h"
#include "prepare_pcap.h"

/* We define our own structures for Ethernet Header and IPv6 Header as they are not available on CYGWIN.
 * We only need the fields, which are necessary to determine the type of the next header.
 * we could also define our own structures for UDP and IPv4. We currently use the structures
 * made available by the platform, as we had no problems to get them on all supported platforms.
 */

typedef struct _ether_type_hdr {
    uint16_t ether_type; /* we only need the type, so we can determine, if the next header is IPv4 or IPv6 */
} ether_type_hdr;

typedef struct _ipv6_hdr {
    char dontcare[6];
    uint8_t nxt_header; /* we only need the next header, so we can determine, if the next header is UDP or not */
    char dontcare2[33];
} ipv6_hdr;


#ifdef __HPUX
int check(uint16_t *buffer, int len)
{
#else
inline int check(uint16_t *buffer, int len)
{
#endif
    int sum;
    int i;
    sum = 0;

    for (i=0; i<(len&~1); i+= 2)
        sum += *buffer++;

    if (len & 1) {
        sum += htons((*(const uint8_t*)buffer) << 8);
    }
    return sum;
}

#ifdef __HPUX
uint16_t checksum_carry(int s)
{
#else
inline uint16_t checksum_carry(int s)
{
#endif
    int s_c = (s >> 16) + (s & 0xffff);
    return (~(s_c + (s_c >> 16)) & 0xffff);
}

char errbuf[PCAP_ERRBUF_SIZE];

/* get octet offset to EtherType block in 802.11 frame
 */
size_t get_802_11_ethertype_offset(int link, const uint8_t* pktdata)
{
    size_t offset = 0;
    uint8_t frame_type = 0;     /* 2 bits */
    uint8_t frame_sub_type = 0; /* 4 bits */
    uint16_t frame_ctl_fld;     /* Frame Control Field */

    /* get RadioTap header length */
    if (link == DLT_IEEE802_11_RADIO) {
        uint16_t rdtap_hdr_len = 0;
        /* http://www.radiotap.org */
        /* rdtap_version[1], pad[1], rdtap_hdr_len[2], rdtap_flds[4] */
        memcpy(&rdtap_hdr_len, pktdata + 2, sizeof(rdtap_hdr_len));
        /* http://radiotap.org */
        /* all data fields in the radiotap header are to be specified
         * in little-endian order */
        rdtap_hdr_len = le16toh(rdtap_hdr_len);
        offset += rdtap_hdr_len;
    }

    memcpy(&frame_ctl_fld, pktdata + offset, sizeof(frame_ctl_fld));
    /* extract frame type and subtype from Frame Control Field */
    frame_type = frame_sub_type = frame_ctl_fld>>8;
    frame_type = frame_type>>2 & 0x03;
    frame_sub_type >>= 4;
    if (frame_type < 0x02) {
        /* Control or Management frame, so ignore it and try to get
         * EtherType from next one */
        offset = 0;
    } else if (frame_type == 0x02) {
        /* only Data frames carry the relevant payload and EtherType */
        if (frame_sub_type < 0x04
            || (frame_sub_type > 0x07 && frame_sub_type < 0x0c)) {
            /* MAC header of a Data frame is at least 24 and at most 36
             * octets long */
            size_t mac_hdr_len = 24;
            uint8_t llc_hdr[8] = { 0x00 };
            while (mac_hdr_len <= 36) {
                /* attempt to get Logical-Link Control header */
                /* dsap[1],ssap[1],ctrl_fld[1],org_code[3],ethertype[2] */
                memcpy(llc_hdr, pktdata + offset + mac_hdr_len, sizeof(llc_hdr));
                /* check if Logical-Link Control header */
                if (llc_hdr[0] == 0xaa && llc_hdr[1] == 0xaa && llc_hdr[2] == 0x03) {
                    /* get EtherType and convert to host byte-order.
                     * (reduce by sizeof(eth_type)) */
                    offset += mac_hdr_len + (sizeof(llc_hdr) - sizeof(uint16_t));
                    break;
                }
                mac_hdr_len++;
            }
        } else {
            /* could be Null Data frame, so ignore it and try to get
             * EtherType from next one */
            offset = 0;
        }
    } else {
        ERROR("Unsupported frame type %d", frame_type);
    }
    return offset;
}

/* get octet offset to EtherType block
 */
size_t get_ethertype_offset(int link, const uint8_t* pktdata)
{
    int is_le_encoded = 0; /* little endian */
    uint16_t eth_type = 0;
    size_t offset = 0;

    /* http://www.tcpdump.org/linktypes.html */
    if (link == DLT_EN10MB) {
        /* srcmac[6], dstmac[6], ethertype[2] */
        offset = 12;
    } else if (link == DLT_LINUX_SLL) {
        /* http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html */
        /* pkttype[2], arphrd_type[2], lladdrlen[2], lladdr[8], ethertype[2] */
        offset = 14;
    } else if (link == DLT_IEEE802_11
               || link == DLT_IEEE802_11_RADIO) {
        offset = get_802_11_ethertype_offset(link, pktdata);
        /* multi-octet fields in 802.11 frame are to be specified in
         * little-endian order */
        is_le_encoded = 1;
    } else {
        ERROR("Unsupported link-type %d", link);
    }

    if (offset) {
        /* get EtherType and convert to host byte order */
        memcpy(&eth_type, pktdata + offset, sizeof(eth_type));
        eth_type = (is_le_encoded) ? le16toh(eth_type) : ntohs(eth_type);
        if (eth_type != 0x0800 && eth_type != 0x86dd) {
            /* check if Ethernet 802.1Q VLAN */
            if (eth_type == 0x8100) {
                /* vlan_tag[4] */
                offset += 4;
            } else {
                ERROR("Unsupported ethernet type %d", eth_type);
            }
        }
    }
    return offset;
}

/* prepare a pcap file
 */
int prepare_pkts(char *file, pcap_pkts *pkts)
{
    pcap_t* pcap;
#ifdef HAVE_PCAP_NEXT_EX
    struct pcap_pkthdr* pkthdr = NULL;
#else
    struct pcap_pkthdr pkthdr_storage;
    struct pcap_pkthdr* pkthdr = &pkthdr_storage;
#endif
    const uint8_t* pktdata = NULL;
    int n_pkts = 0;
    uint64_t max_length = 0;
    size_t ether_type_offset = 0;
    uint16_t base = 0xffff;
    uint64_t pktlen;
    pcap_pkt* pkt_index;
    ether_type_hdr* ethhdr;

    struct iphdr* iphdr;
    ipv6_hdr* ip6hdr;
    struct udphdr* udphdr;

    pkts->pkts = NULL;

    pcap = pcap_open_offline(file, errbuf);
    if (!pcap)
        ERROR_NO("Can't open PCAP file '%s'", file);
#ifdef HAVE_PCAP_NEXT_EX
    while (pcap_next_ex(pcap, &pkthdr, &pktdata) == 1) {
#else
    while ((pktdata = pcap_next(pcap, pkthdr)) != NULL) {
#endif
        if (pkthdr->len != pkthdr->caplen) {
            ERROR("You got truncated packets. Please create a new dump with -s0");
        }

        /* Determine offset from packet to ether type only once. */
        if (!ether_type_offset) {
            int datalink = pcap_datalink(pcap);
            ether_type_offset = get_ethertype_offset(datalink, pktdata);
        }

        ethhdr = (ether_type_hdr *)(pktdata + ether_type_offset);
        if (ntohs(ethhdr->ether_type) != 0x0800 /* IPv4 */
                && ntohs(ethhdr->ether_type) != 0x86dd) { /* IPv6 */
            fprintf(stderr, "Ignoring non IP{4,6} packet, got ether_type %hu!\n",
                    ntohs(ethhdr->ether_type));
            continue;
        }
        iphdr = (struct iphdr*)((char*)ethhdr + sizeof(*ethhdr));
        if (iphdr && iphdr->version == 6) {
            /* ipv6 */
            pktlen = (uint64_t)pkthdr->len - sizeof(*ethhdr) - sizeof(*ip6hdr);
            ip6hdr = (ipv6_hdr*)(void*)iphdr;
            if (ip6hdr->nxt_header != IPPROTO_UDP) {
                fprintf(stderr, "prepare_pcap.c: Ignoring non UDP packet!\n");
                continue;
            }
            udphdr = (struct udphdr*)((char*)ip6hdr + sizeof(*ip6hdr));
        } else {
            /* ipv4 */
            if (iphdr->protocol != IPPROTO_UDP) {
                fprintf(stderr, "prepare_pcap.c: Ignoring non UDP packet!\n");
                continue;
            }
#if defined(__DARWIN) || defined(__CYGWIN) || defined(__FreeBSD__)
            udphdr = (struct udphdr*)((char*)iphdr + (iphdr->ihl << 2) + 4);
            pktlen = (uint64_t)(ntohs(udphdr->uh_ulen));
#elif defined ( __HPUX)
            udphdr = (struct udphdr*)((char*)iphdr + (iphdr->ihl << 2));
            pktlen = (uint64_t) pkthdr->len - sizeof(*ethhdr) - sizeof(*iphdr);
#else
            udphdr = (struct udphdr*)((char*)iphdr + (iphdr->ihl << 2));
            pktlen = (uint64_t)(ntohs(udphdr->len));
#endif
        }
        if (pktlen > PCAP_MAXPACKET) {
            ERROR("Packet size is too big! Recompile with bigger PCAP_MAXPACKET in prepare_pcap.h");
        }
        pkts->pkts = (pcap_pkt *)realloc(pkts->pkts, sizeof(*(pkts->pkts)) * (n_pkts + 1));
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

        /* compute a partial udp checksum */
        /* not including port that will be changed */
        /* when sending RTP */
#if defined(__HPUX) || defined(__DARWIN) || (defined __CYGWIN) || defined(__FreeBSD__)
        pkt_index->partial_check = check((uint16_t*)&udphdr->uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
#else
        pkt_index->partial_check = check((uint16_t*)&udphdr->len, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
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
