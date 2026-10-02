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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA
 *
 *  Author : Deon van der Westhuysen - June 2012 - Vodacom PTY LTD
 */

#ifndef __RTPSTREAM__
#define __RTPSTREAM__

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include <sys/socket.h>

#ifdef PCAPPLAY
#include "send_packets.h"

/* the streams of the pcap plays of a call: video and text play at once
 * with audio or image, but an audio play and an image one end each other */
enum rtpstream_pcap_t {
    RTPSTREAM_PCAP_AUDIO, /* play_pcap_audio and play_dtmf */
    RTPSTREAM_PCAP_IMAGE,
    RTPSTREAM_PCAP_VIDEO,
    RTPSTREAM_PCAP_TEXT, /* real-time text, RFC 4103 */
    RTPSTREAM_PCAP_STREAMS
};
#endif

#define RTPSTREAM_MAX_FILENAMELEN 256
#define RTPSTREAM_MAX_PAYLOADNAME 256
#define RTPECHO_MAX_FILENAMELEN 256
#define RTPECHO_MAX_PAYLOADNAME 256

class JLSRTP;

struct SrtpInfoParams
{
    bool found = false;
    int primary_cryptotag = 0;
    char primary_cryptosuite[25] = "";
    char primary_cryptokeyparams[65] = "";
    int secondary_cryptotag = 0;
    char secondary_cryptosuite[25] = "";
    char secondary_cryptokeyparams[65] = "";
    bool primary_unencrypted_srtp = false;
    bool secondary_unencrypted_srtp = false;
};

struct threaddata_t;
struct taskentry_t;

/* The RTP a call received on its audio or video port, for <rtp_stats>
 * and <rtp_dtmf> */
struct rtpstream_received_t
{
    unsigned long        packets;
    /* of the first packet, as it came: with SRTP, still encrypted */
    int                  first_pt = -1;
    std::string          first_payload;
    /* the digits of the RFC 4733 events that came, each with its payload
     * type, and the timestamp of the last, whose repeats are the same */
    std::vector<std::pair<uint8_t, char>> dtmf;
    uint32_t dtmf_timestamp;
};

/* Made with new taskentry_t(), which zeroes what has no initializer */
struct taskentry_t
{
    ~taskentry_t();

    threaddata_t         *parent_thread;
    unsigned long        nextwake_ms;
    /* the audio and video RTP sockets its thread watches for the echo,
     * or -1 */
    int                  echo_watched[2] = {-1, -1};
    /* when its thread next reads what came on its RTCP sockets */
    unsigned long        rtcp_drain_ms;
    /* TI_* flags: the call's thread and the playback thread both set and
     * clear them, with atomic read-modify-writes that lose neither's */
    std::atomic<int>     flags;

    /* rtp stream information */
    unsigned long long   last_audio_timestamp;
    unsigned long long   last_video_timestamp;
    /* the playback thread's: a stream was paused at its last pass */
    bool audio_was_paused = false;
    bool video_was_paused = false;
    unsigned short       audio_seq_out;
    unsigned short       video_seq_out;
    unsigned short       audio_seq_check; /* the first packet of the pattern */
    unsigned short       audio_seq_echoed; /* the latest packet echoed */
    char                 audio_payload_type;
    char                 video_payload_type;
    unsigned int         audio_ssrc_id;
    unsigned int         video_ssrc_id;

    /* current playback information */
    int                  audio_pattern_id; // FILE:  -1 (UNUSED) -- PATTERN: <id>
    int                  video_pattern_id; // FILE:  -1 (UNUSED) -- PATTERN: <id>
    int                  audio_loop_count; // FILE:  <loopCount> -- PATTERN: -1 (UNUSED)
    int                  video_loop_count; // FILE:  <loopCount> -- PATTERN: -1 (UNUSED)
    char                 *audio_file_bytes_start;
    char                 *video_file_bytes_start;
    char                 *audio_current_file_bytes;
    char                 *video_current_file_bytes;
    int64_t              audio_file_num_bytes;
    int64_t              video_file_num_bytes;
    int64_t              audio_file_bytes_left;
    int64_t              video_file_bytes_left;

    /* playback timing information */
    int                  audio_ms_per_packet;
    int                  video_ms_per_packet;
    int                  audio_bytes_per_packet;
    int                  video_bytes_per_packet;
    int                  audio_timeticks_per_packet;
    int                  video_timeticks_per_packet;
    int                  audio_timeticks_per_ms;
    int                  video_timeticks_per_ms;

    /* new file playback information, set under the mutex */
    int                  new_audio_pattern_id; // FILE:  -1 (UNUSED) -- PATTERN: <id>
    int                  new_video_pattern_id; // FILE:  -1 (UNUSED) -- PATTERN: <id>
    char                 new_audio_payload_type;
    char                 new_video_payload_type;
    int                  new_audio_loop_count; // FILE:  <loopCount> -- PATTERN: -1 (UNUSED)
    int                  new_video_loop_count; // FILE:  <loopCount> -- PATTERN: -1 (UNUSED)
    int64_t              new_audio_file_size;
    int64_t              new_video_file_size;
    char                 *new_audio_file_bytes;
    char                 *new_video_file_bytes;
    int                  new_audio_ms_per_packet;
    int                  new_video_ms_per_packet;
    int                  new_audio_bytes_per_packet;
    int                  new_video_bytes_per_packet;
    int                  new_audio_timeticks_per_packet;
    int                  new_video_timeticks_per_packet;

    /* sockets for audio/video rtp_rtcp: the call's thread sets them up
     * as the playback thread uses them, and closes one that fails */
    std::atomic<int>     audio_rtp_socket{-1};
    std::atomic<int>     audio_rtcp_socket{-1};
    std::atomic<int>     video_rtp_socket{-1};
    std::atomic<int>     video_rtcp_socket{-1};

    /* audio/video SRTP echo activity indicators */
    int                  audio_srtp_echo_active;
    int                  video_srtp_echo_active;
    /* audio/video echo SRTP contexts */
    struct rtpecho_t     *audio_echo;
    struct rtpecho_t     *video_echo;
    /* audio/video playback (UAC) SRTP contexts */
    struct rtpsrtp_t     *audio_srtp;
    struct rtpsrtp_t     *video_srtp;

    /* rtp peer address structures */
    struct sockaddr_storage    remote_audio_rtp_addr;
    struct sockaddr_storage    remote_audio_rtcp_addr;
    struct sockaddr_storage    remote_video_rtp_addr;
    struct sockaddr_storage    remote_video_rtcp_addr;

    /* we will have a mutex per call. should we consider refactoring to */
    /* share mutexes across calls? makes the per-call code more complex */

    /* thread mananagment structures */
    std::mutex           mutex;

    unsigned long        audio_comparison_errors;
    unsigned long        video_comparison_errors;

    /* the RTP check of the pattern playing, for its verdict: the packets
     * checked, and those whose echo didn't match or didn't come */
    unsigned long        audio_check_packets;
    unsigned long        audio_check_failures;
    unsigned long        video_check_packets;
    unsigned long        video_check_failures;

    /* what came in, audio and video, under the mutex */
    rtpstream_received_t received[2];

#ifdef PCAPPLAY
    /* the pcap plays of the call, one per stream, under the mutex, from
     * the first one on; a play with no pcap is not playing */
    play_args_t          *pcap_plays;
#endif
};

struct rtpstream_callinfo_t
{
    /* made on first use: most calls don't play or echo */
    taskentry_t *taskinfo;
    int local_audioport;
    int local_videoport;
    int remote_audioport;
    int remote_videoport;
    unsigned int audio_ssrc_id;
    unsigned int video_ssrc_id;
    /* the remote media of the last rtpstream_set_remote() with an IP
     * before there was a task, for the task, and whether a later one
     * had no IP */
    bool pending_remote;
    bool pending_null_ip;
    int pending_audio_port;
    int pending_video_port;
    struct sockaddr_storage pending_audio_address;
    struct sockaddr_storage pending_video_address;
};

struct rtpstream_actinfo_t
{
    char filename[RTPSTREAM_MAX_FILENAMELEN];   // FILE: "<filename>" -- PATTERN: "pattern"
    int pattern_id;                             // FILE:  -1 -- PATTERN:  <id>
    int loop_count;                             // FILE: count -- PATTERN:  -1 (UNUSED)
    int bytes_per_packet;
    int ms_per_packet;
    int ticks_per_packet; /* need rework for 11.025 sample rate */
    int payload_type;
    char payload_name[RTPSTREAM_MAX_PAYLOADNAME];    // FILE/PATTERN: <payload_name> (e.g. "PCMU/8000", "PCMA/8000", "G729/8000", "H264/90000")
    int audio_active;
    int video_active;
};

struct rtpecho_actinfo_t
{
    int    payload_type;
    char   payload_name[RTPECHO_MAX_PAYLOADNAME];    // e.g. "PCMU/8000", "PCMA/8000", "G729/8000", "H264/90000"
    int    bytes_per_packet;
    int    audio_active;
    int    video_active;
};

int rtpstream_new_call(rtpstream_callinfo_t *callinfo);
void rtpstream_end_call(rtpstream_callinfo_t *callinfo);
/* Stop the playback threads: the RTP check verdicts of their patterns */
int rtpstream_shutdown();

int rtpstream_get_local_audioport(rtpstream_callinfo_t *callinfo);
int rtpstream_get_local_videoport(rtpstream_callinfo_t *callinfo);
void rtpstream_set_remote(rtpstream_callinfo_t* callinfo, const char* audio_ip, int audio_port,
                          const char* video_ip, int video_port);

int rtpstream_set_srtp_audio_local(rtpstream_callinfo_t *callinfo, SrtpInfoParams &p);
int rtpstream_set_srtp_audio_remote(rtpstream_callinfo_t *callinfo, SrtpInfoParams &p);
int rtpstream_set_srtp_video_local(rtpstream_callinfo_t *callinfo, SrtpInfoParams &p);
int rtpstream_set_srtp_video_remote(rtpstream_callinfo_t *callinfo, SrtpInfoParams &p);

int rtpstream_cache_file(char *filename,
                         int mode /* 0: FILE - 1: PATTERN */,
                         int id,
                         int bytes_per_packet,
                         int stream_type /* 0: AUDIO - 1: VIDEO */);
void rtpstream_play(rtpstream_callinfo_t *callinfo, rtpstream_actinfo_t *actioninfo, const JLSRTP& txUACAudio, const JLSRTP& rxUACAudio);
void rtpstream_pause(rtpstream_callinfo_t *callinfo);
void rtpstream_resume(rtpstream_callinfo_t *callinfo);
/* The millisecond the call's rtp_stream playback is due to end in: 0 when
 * no file or pattern plays, ULONG_MAX when the end is not known, as when
 * paused. */
unsigned long rtpstream_play_end(rtpstream_callinfo_t *callinfo);

void rtpstream_playapattern(rtpstream_callinfo_t *callinfo, rtpstream_actinfo_t *actioninfo, const JLSRTP& txUACAudio, const JLSRTP& rxUACAudio);
void rtpstream_pauseapattern(rtpstream_callinfo_t *callinfo);
void rtpstream_resumeapattern(rtpstream_callinfo_t *callinfo);

void rtpstream_playvpattern(rtpstream_callinfo_t *callinfo, rtpstream_actinfo_t *actioninfo, const JLSRTP& txUACVideo, const JLSRTP& rxUACVideo);
void rtpstream_pausevpattern(rtpstream_callinfo_t *callinfo);
void rtpstream_resumevpattern(rtpstream_callinfo_t *callinfo);

#ifdef PCAPPLAY
/* Play a pcap on a stream of the call, in its playback thread, ending
 * the play on that stream (and an audio or image one on the other) if
 * there is one; 0 if it cannot */
int rtpstream_play_pcap(rtpstream_callinfo_t *callinfo, rtpstream_pcap_t stream, const play_args_t *play);
/* The addresses of the pcap play on a stream have changed */
void rtpstream_update_pcap(rtpstream_callinfo_t *callinfo, rtpstream_pcap_t stream, const play_args_t *play);
#endif

/* What the call's audio or video port received, when a scenario has
 * <rtp_stats> */
rtpstream_received_t rtpstream_received(rtpstream_callinfo_t *callinfo, bool video);

int rtpstream_rtpecho_startaudio(rtpstream_callinfo_t *callinfo, const JLSRTP& rxUASAudio, const JLSRTP& txUASAudio);
int rtpstream_rtpecho_updateaudio(rtpstream_callinfo_t *callinfo, const JLSRTP& rxUASAudio, const JLSRTP& txUASAudio);
int rtpstream_rtpecho_stopaudio(rtpstream_callinfo_t *callinfo);

int rtpstream_rtpecho_startvideo(rtpstream_callinfo_t *callinfo, const JLSRTP& rxUASVideo, const JLSRTP& txUASVideo);
int rtpstream_rtpecho_updatevideo(rtpstream_callinfo_t *callinfo, const JLSRTP& rxUASVideo, const JLSRTP& txUASVideo);
int rtpstream_rtpecho_stopvideo(rtpstream_callinfo_t *callinfo);


#endif
