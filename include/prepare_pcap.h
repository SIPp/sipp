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
#include <stdint.h>
#include <time.h>

typedef struct {
    u_char* data;
    u_long pktlen;
    struct timeval ts;
    int partial_check;
} pcap_pkt;

#define PCAP_MAXPACKET 1500
typedef struct {
    char* file;
    uint16_t base;
    u_long max_length;
    pcap_pkt* max;
    pcap_pkt* pkts;
} pcap_pkts;

#ifdef __cplusplus
extern "C" {
#endif
    int check(uint16_t*, int);
    uint16_t checksum_carry(int);
    int prepare_pkts(const char*, pcap_pkts*);
    int prepare_dtmf(const char*, pcap_pkts*, uint16_t start_seq_no);
#ifdef __cplusplus
}
#endif
#endif /* PREPARE_PCAP_H */
