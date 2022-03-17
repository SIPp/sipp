/*
 * send_packets.h: from tcpreplay tools by Aaron Turner
 * http://tcpreplay.sourceforge.net/
 * send_packets.h is under BSD license (see below)
 * SIPp is under GPL license
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
#ifndef _SIPP_SEND_PACKETS_H_
#define _SIPP_SEND_PACKETS_H_

#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "prepare_pcap.h"

inline void timerdiv (struct timeval *tvp, float div);
inline void float2timer (float time, struct timeval *tvp);

#ifndef TIMEVAL_TO_TIMESPEC
#define TIMEVAL_TO_TIMESPEC(tv, ts) { \
            (ts)->tv_sec = (tv)->tv_sec; \
            (ts)->tv_nsec = (tv)->tv_usec * 1000; }
#endif
/* zero out a timer */
#ifndef timerclear
#define timerclear(tvp)         (tvp)->tv_sec = (tvp)->tv_usec = 0
#endif
/* is timer non-zero? */
#ifndef timerisset
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#endif
/* add tvp and uvp and store in vvp */
#ifndef timeradd
#define timeradd(tvp, uvp, vvp) \
        do {                                                        \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;      \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;   \
                if ((vvp)->tv_usec >= 1000000) {                    \
                        (vvp)->tv_sec++;                            \
                        (vvp)->tv_usec -= 1000000;                  \
                }                                                   \
        } while (0)
#endif
/* subtract uvp from tvp and store in vvp */
#ifndef timersub
#define timersub(tvp, uvp, vvp)                                     \
        do {                                                        \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;      \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;   \
                if ((vvp)->tv_usec < 0) {                           \
                        (vvp)->tv_sec--;                            \
                        (vvp)->tv_usec += 1000000;                  \
                }                                                   \
        } while (0)
#endif
/* compare tvp and uvp using cmp */
#ifndef timercmp
#define timercmp(tvp, uvp, cmp)                                     \
        (((tvp)->tv_sec == (uvp)->tv_sec) ?                         \
        ((tvp)->tv_usec cmp (uvp)->tv_usec) :                       \
        ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif
/* multiply tvp by x and store in uvp */
#define timermul(tvp, uvp, x)                                       \
        do {                                                        \
                (uvp)->tv_sec = (tvp)->tv_sec * x;                  \
                (uvp)->tv_usec = (tvp)->tv_usec * x;                \
                while((uvp)->tv_usec > 1000000) {                   \
                        (uvp)->tv_sec++;                            \
                        (uvp)->tv_usec -= 1000000;                  \
                }                                                   \
        } while(0)
/* device tvp by x.  store in tvp */
#define timerdiv2(tvp, x)                                           \
        do {                                                        \
                (tvp)->tv_sec = (tvp)->tv_sec / x;                  \
                (tvp)->tv_usec = (tvp)->tv_usec / x;                \
        } while(0)

/* call specific vars for RTP sending */
typedef struct {
    /* pointer to a RTP pkts container */
    pcap_pkts *pcap;
    /* Used in send_packets thread */
    struct sockaddr_storage to;
    struct sockaddr_storage from;
} play_args_t;

#ifdef __cplusplus
extern "C"
{
#endif
    int parse_play_args(const char*, pcap_pkts*);
    void free_pcaps(pcap_pkts *pkts);
    int send_packets(play_args_t*);
#ifdef __cplusplus
}
#endif
#endif/*_SIPP_SEND_PACKETS_H_*/
