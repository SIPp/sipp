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

/* Helpful RFCs for DTMF generation.
 * https://tools.ietf.org/html/rfc4733
 * https://tools.ietf.org/html/rfc3550
 */

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
int prepare_pkts(const char* file, pcap_pkts* pkts)
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
            udphdr = (struct udphdr*)((char*)iphdr + (iphdr->ihl << 2));
        }

        pktlen = ntohs(udphdr->uh_ulen);
        if (pktlen > PCAP_MAXPACKET) {
            ERROR("Packet size is too big! Recompile with bigger PCAP_MAXPACKET in prepare_pcap.h");
        }

        /* BUG: inefficient */
        pkts->pkts = (pcap_pkt *)realloc(pkts->pkts, sizeof(*(pkts->pkts)) * (n_pkts + 1));
        if (!pkts->pkts)
            ERROR("Can't re-allocate memory for pcap pkt");
        pkt_index = pkts->pkts + n_pkts;
        pkt_index->pktlen = pktlen;
        pkt_index->ts = pkthdr->ts;
        pkt_index->data = (unsigned char *) malloc(pktlen); /* BUG: inefficient */
        if (!pkt_index->data)
            ERROR("Can't allocate memory for pcap pkt data");
        memcpy(pkt_index->data, udphdr, pktlen);

        udphdr->uh_sum = 0;

        /* compute a partial udp checksum */
        /* not including port that will be changed */
        /* when sending RTP */
        pkt_index->partial_check = check((uint16_t*)&udphdr->uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
        if (max_length < pktlen)
            max_length = pktlen;
        if (base > ntohs(udphdr->uh_dport))
            base = ntohs(udphdr->uh_dport);
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
    unsigned int csicnt:4;
    unsigned int extension:1;
    unsigned int padding:1;
    unsigned int version:2;

    unsigned int payload_type:7;
    unsigned int marker:1;

    u_int16_t seqno;
    u_int32_t timestamp;
    u_int32_t ssrcid;
};

struct rtpevent {
    unsigned int event_id;

    unsigned int volume:6;
    unsigned int reserved:1;
    unsigned int end_of_event:1;

    u_int16_t duration;
};

struct dtmfpacket {
    struct udphdr udp;
    struct rtphdr rtp;
    struct rtpevent dtmf;
};

struct rtpnoop {
    unsigned int request_rtcp:1;
    unsigned int reserved:31;
};

struct nooppacket {
    struct udphdr udp;
    struct rtphdr rtp;
    struct rtpnoop noop;
};

static u_long dtmf_ssrcid = 0x01020304; /* bug, should be random/unique */

static void fill_default_udphdr(struct udphdr* udp, u_long pktlen)
{
    udp->uh_ulen = htons(pktlen);
    udp->uh_sum = 0;
    udp->uh_sport = 0;
    udp->uh_dport = 0;
}

static void fill_default_rtphdr(struct rtphdr* rtp, int marker, int seqno, int ts)
{
    rtp->version = 2;
    rtp->padding = 0;
    rtp->extension = 0;
    rtp->csicnt = 0;
    rtp->marker = marker;
    rtp->payload_type = 0x60; /* 96 as in the SDP */
    rtp->seqno = htons(seqno);
    rtp->timestamp = htonl(ts);
    rtp->ssrcid = htonl(dtmf_ssrcid);
}

static void fill_default_dtmf(struct dtmfpacket* dtmfpacket, int marker, int seqno,
                              int ts, char digit, int eoe, int duration)
{
    const u_long pktlen = sizeof(*dtmfpacket);

    fill_default_udphdr(&dtmfpacket->udp, pktlen);
    fill_default_rtphdr(&dtmfpacket->rtp, marker, seqno, ts);

    dtmfpacket->dtmf.event_id = digit;
    dtmfpacket->dtmf.end_of_event = eoe;
    dtmfpacket->dtmf.volume = 10;
    dtmfpacket->dtmf.duration = htons(duration * 8);
}

static void fill_default_noop(struct nooppacket* nooppacket, int seqno, int ts)
{
    const u_long pktlen = sizeof(*nooppacket);

    fill_default_udphdr(&nooppacket->udp, pktlen);
    fill_default_rtphdr(&nooppacket->rtp, 0, seqno, ts);

    nooppacket->rtp.payload_type = 0x61; /* 97 for noop */
    nooppacket->noop.request_rtcp = 0;
    nooppacket->noop.reserved = 0;
}

static void prepare_dtmf_digit_start(
        pcap_pkts* pkts, int* n_pkts, u_int16_t start_seq_no, int n_digits,
        unsigned char uc_digit, int tone_len, unsigned long ts_offset, unsigned timestamp_start)
{
    const u_long pktlen = sizeof(struct dtmfpacket);
    unsigned long cur_tone_len = 0;
    int marked = 0;

    while (cur_tone_len < tone_len) {
        unsigned long ts = ts_offset + (n_digits + 1) * tone_len * 2 + cur_tone_len;
        pcap_pkt* pkt_index;
        struct dtmfpacket* dtmfpacket;

        /* BUG: inefficient */
        pkts->pkts = realloc(pkts->pkts, sizeof(*pkts->pkts) * (*n_pkts + 1));
        if (!pkts->pkts) {
            ERROR("Can't re-allocate memory for dtmf pcap pkt");
        }

        pkt_index = pkts->pkts + *n_pkts;
        pkt_index->pktlen = pktlen;
        pkt_index->ts.tv_sec = ts / 1000;
        pkt_index->ts.tv_usec = (ts % 1000) * 1000;
        pkt_index->data = malloc(pktlen); /* BUG: inefficient */
        if (!pkt_index->data) {
            ERROR("Can't allocate memory for pcap pkt data");
        }

        dtmfpacket = (struct dtmfpacket*)pkt_index->data;

        fill_default_dtmf(dtmfpacket, !marked,
                          *n_pkts + start_seq_no, n_digits * tone_len * 2 + timestamp_start,
                          uc_digit, 0, cur_tone_len);
        marked = 1; /* set marker once per event */

        pkt_index->partial_check = check(&dtmfpacket->udp.uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);

        (*n_pkts)++;
        cur_tone_len += 20;
    }
}

static void prepare_dtmf_digit_end(
        pcap_pkts* pkts, int* n_pkts, u_int16_t start_seq_no, int n_digits,
        unsigned char uc_digit, int tone_len, unsigned long ts_offset, unsigned timestamp_start)
{
    const u_long pktlen = sizeof(struct dtmfpacket);
    int i;

    for (i = 0; i < 3; i++) {
        unsigned long ts = ts_offset + (n_digits + 1) * tone_len * 2 + tone_len + i + 1;
        pcap_pkt* pkt_index;
        struct dtmfpacket* dtmfpacket;

        /* BUG: inefficient */
        pkts->pkts = realloc(pkts->pkts, sizeof(*pkts->pkts) * (*n_pkts + 1));
        if (!pkts->pkts) {
            ERROR("Can't re-allocate memory for dtmf pcap pkt");
        }

        pkt_index = pkts->pkts + *n_pkts;
        pkt_index->pktlen = pktlen;
        pkt_index->ts.tv_sec = ts / 1000;
        pkt_index->ts.tv_usec = (ts % 1000) * 1000;
        pkt_index->data = malloc(pktlen);
        if (!pkt_index->data) {
            ERROR("Can't allocate memory for pcap pkt data");
        }

        dtmfpacket = (struct dtmfpacket*)pkt_index->data;
        fill_default_dtmf(dtmfpacket, 0,
                          *n_pkts + start_seq_no, n_digits * tone_len * 2 + timestamp_start,
                          uc_digit, 1, tone_len);

        pkt_index->partial_check = check(&dtmfpacket->udp.uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);

        (*n_pkts)++;
    }
}

static void prepare_noop(
        pcap_pkts* pkts, int* n_pkts, u_int16_t* start_seq_no,
        unsigned long *ts_offset, unsigned *timestamp_start)
{
    const u_long pktlen = sizeof(struct nooppacket); /* not dtmfpacket */
    int i;

    for (i = 0; i < 20; i++) { /* 400ms of nothingness */
        unsigned long ts = *ts_offset;
        pcap_pkt* pkt_index;
        struct nooppacket* nooppacket;

        *ts_offset += 20;

        /* BUG: inefficient */
        pkts->pkts = realloc(pkts->pkts, sizeof(*pkts->pkts) * (*n_pkts + 1));
        if (!pkts->pkts) {
            ERROR("Can't re-allocate memory for noop pcap pkt");
        }

        pkt_index = pkts->pkts + *n_pkts;
        pkt_index->pktlen = pktlen;
        pkt_index->ts.tv_sec = ts / 1000;
        pkt_index->ts.tv_usec = (ts % 1000) * 1000;
        pkt_index->data = malloc(pktlen);
        if (!pkt_index->data) {
            ERROR("Can't allocate memory for pcap pkt data");
        }

        nooppacket = (struct nooppacket*)pkt_index->data;
        fill_default_noop(nooppacket, *n_pkts + *start_seq_no, *timestamp_start + ts);

        pkt_index->partial_check = check(&nooppacket->udp.uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);

        (*n_pkts)++;
        (*start_seq_no)++;
    }

    *timestamp_start += *ts_offset;
}

/* prepare a dtmf pcap
 */
int prepare_dtmf(const char* digits, pcap_pkts* pkts, u_int16_t start_seq_no)
{
    unsigned long tone_len = 200;
    const u_long pktlen = sizeof(struct dtmfpacket);
    int n_pkts = 0;
    int n_digits = 0;
    int needs_filler = 0; /* warm up the stream */
    const char* digit;

    unsigned long ts_offset = 0; /* packet timestamp */
    unsigned timestamp_start = 24000; /* RTP timestamp, should be random */

    /* If we see the DTMF as part of the entire audio stream, we'd need
     * to reuse the SSRC, but it's legal to start a new stream (new
     * SSRC) like we do.  Note that the new SSRC that will cause some
     * devices to not pick up on the first event as quickly: we can work
     * around that by adding a few empty RTP packets with this SSRC
     * first. */
    dtmf_ssrcid++;
    /* Because we need to warm up the stream (puncture NAT, make phone
     * accept the SSRC(?)), we add a few filler packets first. */
    needs_filler = 1;

    pkts->pkts = NULL;

    char* comma = strchr(digits, ',');
    if (comma) {
        tone_len = atol(comma + 1);
        if (tone_len < 50 || tone_len > 2000) {
            tone_len = 200;
        }
        *comma = '\0';
    }

    for (digit = digits; *digit; digit++) {
        unsigned char uc_digit;

        if (*digit >= '0' && *digit <= '9') {
            uc_digit = *digit - '0';
        } else if (*digit == '*') {
            uc_digit = 10;
        } else if (*digit == '#') {
            uc_digit = 11;
        } else if (*digit == 'A') {
            uc_digit = 12;
        } else if (*digit == 'B') {
            uc_digit = 13;
        } else if (*digit == 'C') {
            uc_digit = 14;
        } else if (*digit == 'D') {
            uc_digit = 15;
        } else {
            continue;
        }

        if (needs_filler) {
            prepare_noop(pkts, &n_pkts, &start_seq_no, &ts_offset,
                         &timestamp_start);
            needs_filler = 0;
        }

        prepare_dtmf_digit_start(pkts, &n_pkts, start_seq_no, n_digits, uc_digit,
                                 tone_len, ts_offset, timestamp_start);
        prepare_dtmf_digit_end(pkts, &n_pkts, start_seq_no, n_digits, uc_digit,
                               tone_len, ts_offset, timestamp_start);

        n_digits++;
    }

    pkts->max = pkts->pkts + n_pkts;
    pkts->max_length = pktlen;
    pkts->base = 0;

    return n_pkts;
}
