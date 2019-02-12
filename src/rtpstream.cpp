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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sipp.hpp"
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <pthread.h>
#include "rtpstream.hpp"

#include <sys/time.h>
#include <vector>
#include <errno.h>

/* stub to add extra debugging/logging... */
static void debugprint(const char *Format, ...)
{
}

#define RTPSTREAM_FILESPERBLOCK       16
#define BIND_MAX_TRIES                100
#define RTPSTREAM_THREADBLOCKSIZE     16
#define MAX_UDP_RECV_BUFFER           8192
#define MAX_UDP_SEND_BUFFER           8192

#define TI_NULL_AUDIOIP               0x001
#define TI_NULL_VIDEOIP               0x002
#define TI_NULLIP                     (TI_NULL_AUDIOIP|TI_NULL_VIDEOIP)
#define TI_PAUSERTP                   0x004
#define TI_ECHORTP                    0x008  /* Not currently implemented */
#define TI_KILLTASK                   0x010
#define TI_RECONNECTSOCKET            0x020
#define TI_PLAYFILE                   0x040
#define TI_PAUSERTPAPATTERN           0x080
#define TI_PLAYAPATTERN               0x100
#define TI_PAUSERTPVPATTERN           0x200
#define TI_PLAYVPATTERN               0x400
#define TI_CONFIGFLAGS                (TI_KILLTASK|TI_RECONNECTSOCKET|TI_PLAYFILE|TI_PLAYAPATTERN|TI_PLAYVPATTERN)

#define PATTERN1        0xAA
#define PATTERN2        0xBB
#define PATTERN3        0xCC
#define PATTERN4        0xDD
#define PATTERN5        0xEE
#define PATTERN6        0xFF
#define NUMPATTERNS     6

struct rtp_header_t
{
    uint16_t         flags;
    uint16_t         seq;
    uint32_t         timestamp;
    uint32_t         ssrc_id;
};

struct threaddata_t
{
    pthread_mutex_t tasklist_mutex;
    int             busy_list_index;
    int             max_tasks;
    volatile int    num_tasks;
    volatile int    del_pending;
    volatile int    exit_flag;
    taskentry_t     *tasklist;
};

struct cached_file_t
{
    char   filename[RTPSTREAM_MAX_FILENAMELEN];
    char   *bytes;
    int    filesize;
};

struct cached_pattern_t
{
    int    id;
    char   *bytes;
    int    filesize;
};

cached_file_t  *cached_files= NULL;
cached_pattern_t *cached_patterns = NULL;
int            num_cached_files= 0;
int            next_rtp_port= 0;

threaddata_t  **ready_threads= NULL;
threaddata_t  **busy_threads= NULL;
int           num_busy_threads= 0;
int           num_ready_threads= 0;
int           busy_threads_max= 0;
int           ready_threads_max= 0;

unsigned int  global_ssrc_id= 0xCA110000;

FILE*         debugafile=NULL;
FILE*         debugvfile=NULL;
pthread_mutex_t  debugamutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  debugvmutex = PTHREAD_MUTEX_INITIALIZER;
FILE*         debuglsrtpafile=NULL;
FILE*         debugrsrtpafile=NULL;
pthread_mutex_t  debuglsrtpamutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  debugrsrtpamutex = PTHREAD_MUTEX_INITIALIZER;
FILE*         debuglsrtpvfile=NULL;
FILE*         debugrsrtpvfile=NULL;
pthread_mutex_t  debuglsrtpvmutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  debugrsrtpvmutex = PTHREAD_MUTEX_INITIALIZER;
FILE*         debugrefileaudio=NULL;
FILE*         debugrefilevideo=NULL;
pthread_mutex_t  debugremutexaudio = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  debugremutexvideo = PTHREAD_MUTEX_INITIALIZER;

// RTPSTREAM ECHO
pthread_t    pthread_audioecho_id;
pthread_t    pthread_videoecho_id;
bool quit_audioecho_thread = false;
bool quit_videoecho_thread = false;
pthread_mutex_t quit_mutexaudio = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t quit_mutexvideo = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t quit_cvaudio = PTHREAD_COND_INITIALIZER;
pthread_cond_t quit_cvvideo = PTHREAD_COND_INITIALIZER;

// JLSRTP contexts
JLSRTP g_txUACAudio;
JLSRTP g_rxUACAudio;
JLSRTP g_txUACVideo;
JLSRTP g_rxUACVideo;
JLSRTP g_rxUASAudio;
JLSRTP g_txUASAudio;
JLSRTP g_rxUASVideo;
JLSRTP g_txUASVideo;
pthread_mutex_t uacAudioMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t uacVideoMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t uasAudioMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t uasVideoMutex = PTHREAD_MUTEX_INITIALIZER;

//===================================================================================================

void printAudioHexUS(char const * note, unsigned char const * string, int size, int extrainfo, int moreinfo)
{
    if ((debugafile != NULL) &&
        (note != NULL) &&
        (string != NULL) &&
        rtpcheck_debug)
    {
        pthread_mutex_lock(&debugamutex);
        fprintf(debugafile, "TID: %zu %s %d %d %d [", pthread_self(), note, size, extrainfo, moreinfo);
        for (int i = 0; i < size; i++)
        {
            fprintf(debugafile, "%02X", 0x000000FF & string[i]);
        }
        fprintf(debugafile, "]\n");
        pthread_mutex_unlock(&debugamutex);
    }
}

static void printVideoHexUS(char const * note, unsigned char const * string, int size, int extrainfo, int moreinfo)
{
    if ((debugvfile != NULL) &&
        (note != NULL) &&
        (string != NULL) &&
        rtpcheck_debug)
    {
        pthread_mutex_lock(&debugvmutex);
        fprintf(debugvfile, "TID: %zu %s %d %d %d [", pthread_self(), note, size, extrainfo, moreinfo);
        for (int i = 0; i < size; i++)
        {
            fprintf(debugvfile, "%02X", 0x000000FF & string[i]);
        }
        fprintf(debugvfile, "]\n");
        pthread_mutex_unlock(&debugvmutex);
    }
}

static void printAudioHex(char const * note, char const * string, int size, int extrainfo, int moreinfo)
{
    if ((debugafile != NULL) &&
        (note != NULL) &&
        (string != NULL) &&
        rtpcheck_debug)
    {
        pthread_mutex_lock(&debugamutex);
        fprintf(debugafile, "TID: %zu %s %d %d %d [", pthread_self(), note, size, extrainfo, moreinfo);
        for (int i = 0; i < size; i++)
        {
            fprintf(debugafile, "%02X", 0x000000FF & string[i]);
        }
        fprintf(debugafile, "]\n");
        pthread_mutex_unlock(&debugamutex);
    }
}

void printAudioVector(char const * note, std::vector<unsigned long> const &v)
{
    if ((debugafile != NULL) &&
        (note != NULL) &&
        rtpcheck_debug)
    {
        pthread_mutex_lock(&debugamutex);
        fprintf(debugafile, "TID: %zu %s\n", pthread_self(), note);
        for (unsigned i = 0; i < v.size(); i++)
        {
            fprintf(debugafile, "%lu\n", v[i]);
        }
        pthread_mutex_unlock(&debugamutex);
    }
}

void printVideoHex(char const * note, char const * string, int size, int extrainfo, int moreinfo)
{
    if ((debugvfile != NULL) &&
        (note != NULL) &&
        (string != NULL) &&
        rtpcheck_debug)
    {
        pthread_mutex_lock(&debugvmutex);
        fprintf(debugvfile, "TID: %zu %s %d %d %d [", pthread_self(), note, size, extrainfo, moreinfo);
        for (int i = 0; i < size; i++)
        {
            fprintf(debugvfile, "%02X", 0x000000FF & string[i]);
        }
        fprintf(debugvfile, "]\n");
        pthread_mutex_unlock(&debugvmutex);
    }
}

void printVideoVector(char const * note, std::vector<unsigned long> const &v)
{
    if ((debugvfile != NULL) &&
        (note != NULL) &&
        rtpcheck_debug)
    {
        pthread_mutex_lock(&debugvmutex);
        fprintf(debugvfile, "TID: %zu %s\n", pthread_self(), note);
        for (unsigned i = 0; i < v.size(); i++)
        {
            fprintf(debugvfile, "%lu\n", v[i]);
        }
        pthread_mutex_unlock(&debugvmutex);
    }
}

void printLocalAudioSrtpStuff(SrtpAudioInfoParams &p)
{
    if (debuglsrtpafile != NULL)
    {
        pthread_mutex_lock(&debuglsrtpamutex);
        fprintf(debuglsrtpafile, "audio_found                     : %d\n", p.audio_found);
        fprintf(debuglsrtpafile, "primary_audio_cryptotag         : %d\n", p.primary_audio_cryptotag);
        fprintf(debuglsrtpafile, "secondary_audio_cryptotag       : %d\n", p.secondary_audio_cryptotag);
        fprintf(debuglsrtpafile, "primary_audio_cryptosuite       : %s\n", p.primary_audio_cryptosuite);
        fprintf(debuglsrtpafile, "secondary_audio_cryptosuite     : %s\n", p.secondary_audio_cryptosuite);
        fprintf(debuglsrtpafile, "primary_audio_cryptokeyparams   : %s\n", p.primary_audio_cryptokeyparams);
        fprintf(debuglsrtpafile, "secondary_audio_cryptokeyparams : %s\n", p.secondary_audio_cryptokeyparams);
        fprintf(debuglsrtpafile, "primary_unencrypted_audio_srtp  : %d\n", p.primary_unencrypted_audio_srtp);
        fprintf(debuglsrtpafile, "secondary_unencrypted_audio_srtp: %d\n", p.secondary_unencrypted_audio_srtp);
        pthread_mutex_unlock(&debuglsrtpamutex);
    }
}

void printRemoteAudioSrtpStuff(SrtpAudioInfoParams &p)
{
    if (debugrsrtpafile != NULL)
    {
        pthread_mutex_lock(&debugrsrtpamutex);
        fprintf(debugrsrtpafile, "audio_found                     : %d\n", p.audio_found);
        fprintf(debugrsrtpafile, "primary_audio_cryptotag         : %d\n", p.primary_audio_cryptotag);
        fprintf(debugrsrtpafile, "secondary_audio_cryptotag       : %d\n", p.secondary_audio_cryptotag);
        fprintf(debugrsrtpafile, "primary_audio_cryptosuite       : %s\n", p.primary_audio_cryptosuite);
        fprintf(debugrsrtpafile, "secondary_audio_cryptosuite     : %s\n", p.secondary_audio_cryptosuite);
        fprintf(debugrsrtpafile, "primary_audio_cryptokeyparams   : %s\n", p.primary_audio_cryptokeyparams);
        fprintf(debugrsrtpafile, "secondary_audio_cryptokeyparams : %s\n", p.secondary_audio_cryptokeyparams);
        fprintf(debugrsrtpafile, "primary_unencrypted_audio_srtp  : %d\n", p.primary_unencrypted_audio_srtp);
        fprintf(debugrsrtpafile, "secondary_unencrypted_audio_srtp: %d\n", p.secondary_unencrypted_audio_srtp);
        pthread_mutex_unlock(&debugrsrtpamutex);
    }
}

void printLocalVideoSrtpStuff(SrtpVideoInfoParams &p)
{
    if (debuglsrtpvfile != NULL)
    {
        pthread_mutex_lock(&debuglsrtpvmutex);
        fprintf(debuglsrtpvfile, "video_found                     : %d\n", p.video_found);
        fprintf(debuglsrtpvfile, "primary_video_cryptotag         : %d\n", p.primary_video_cryptotag);
        fprintf(debuglsrtpvfile, "secondary_video_cryptotag       : %d\n", p.secondary_video_cryptotag);
        fprintf(debuglsrtpvfile, "primary_video_cryptosuite       : %s\n", p.primary_video_cryptosuite);
        fprintf(debuglsrtpvfile, "secondary_video_cryptosuite     : %s\n", p.secondary_video_cryptosuite);
        fprintf(debuglsrtpvfile, "primary_video_cryptokeyparams   : %s\n", p.primary_video_cryptokeyparams);
        fprintf(debuglsrtpvfile, "secondary_video_cryptokeyparams : %s\n", p.secondary_video_cryptokeyparams);
        fprintf(debuglsrtpvfile, "primary_unencrypted_video_srtp  : %d\n", p.primary_unencrypted_video_srtp);
        fprintf(debuglsrtpvfile, "secondary_unencrypted_video_srtp: %d\n", p.secondary_unencrypted_video_srtp);
        pthread_mutex_unlock(&debuglsrtpvmutex);
    }
}

void printRemoteVideoSrtpStuff(SrtpVideoInfoParams &p)
{
    if (debugrsrtpvfile != NULL)
    {
        pthread_mutex_lock(&debugrsrtpvmutex);
        fprintf(debugrsrtpvfile, "video_found                     : %d\n", p.video_found);
        fprintf(debugrsrtpvfile, "primary_video_cryptotag         : %d\n", p.primary_video_cryptotag);
        fprintf(debugrsrtpvfile, "secondary_video_cryptotag       : %d\n", p.secondary_video_cryptotag);
        fprintf(debugrsrtpvfile, "primary_video_cryptosuite       : %s\n", p.primary_video_cryptosuite);
        fprintf(debugrsrtpvfile, "secondary_video_cryptosuite     : %s\n", p.secondary_video_cryptosuite);
        fprintf(debugrsrtpvfile, "primary_video_cryptokeyparams   : %s\n", p.primary_video_cryptokeyparams);
        fprintf(debugrsrtpvfile, "secondary_video_cryptokeyparams : %s\n", p.secondary_video_cryptokeyparams);
        fprintf(debugrsrtpvfile, "primary_unencrypted_video_srtp  : %d\n", p.primary_unencrypted_video_srtp);
        fprintf(debugrsrtpvfile, "secondary_unencrypted_video_srtp: %d\n", p.secondary_unencrypted_video_srtp);
        pthread_mutex_unlock(&debugrsrtpvmutex);
    }
}

int set_bit(unsigned long* context, int value)
{
    int retVal = -1;

    if (context != NULL)
    {
        if (value > 0)
        {
            *context |= (1 << (value-1));
            retVal = value;
        }
        else
        {
            retVal = 0;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

int clear_bit(unsigned long* context, int value)
{
    int retVal = -1;

    if (context != NULL)
    {
        if (value > 0)
        {
            *context &= ~(1 << (value-1));
            retVal = value;
        }
        else
        {
            retVal = 0;
        }
    }
    else
    {
        retVal = -1;
    }

    return retVal;
}

/* code checked */
static void rtpstream_free_taskinfo(taskentry_t* taskinfo)
{
    if (taskinfo) {

        /* audio SRTP echo activity indicators */
        taskinfo->audio_srtp_echo_active = 0;
        taskinfo->video_srtp_echo_active = 0;

        /* close sockets associated with this call */
        if (taskinfo->audio_rtp_socket!=-1) {
            close (taskinfo->audio_rtp_socket);
        }
        if (taskinfo->audio_rtcp_socket!=-1) {
            close (taskinfo->audio_rtcp_socket);
        }
        if (taskinfo->video_rtp_socket!=-1) {
            close (taskinfo->video_rtp_socket);
        }
        if (taskinfo->video_rtcp_socket!=-1) {
            close (taskinfo->video_rtcp_socket);
        }

        /* cleanup pthread library structure */
        pthread_mutex_destroy(&(taskinfo->mutex));

        free (taskinfo);
    }
}

/* code checked */
static void rtpstream_process_task_flags(taskentry_t* taskinfo)
{
    if (taskinfo->flags&TI_RECONNECTSOCKET) {
        int remote_addr_len;
        int rc = -1;

        remote_addr_len= media_ip_is_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

        /* enter critical section to lock address updates */
        /* may want to leave this out -- low chance of race condition */
        pthread_mutex_lock (&(taskinfo->mutex));

        /* If we have valid ip and port numbers for audio rtp stream */
        if (!(taskinfo->flags & TI_NULL_AUDIOIP))
        {
            if (taskinfo->audio_rtcp_socket!=-1) {
                rc= connect (taskinfo->audio_rtcp_socket, (struct sockaddr *) & (taskinfo->remote_audio_rtcp_addr), remote_addr_len);
                if (rc < 0) {
                    debugprint("closing audio rtcp socket %d due to error %d in rtpstream_process_task_flags taskinfo=%p\n",
                               taskinfo->audio_rtcp_socket, errno, taskinfo);
                    close(taskinfo->audio_rtcp_socket);
                    taskinfo->audio_rtcp_socket = -1;
                }
            }

            if (taskinfo->audio_rtp_socket!=-1) {
                if (!taskinfo->audio_srtp_echo_active) {
                    rc= connect (taskinfo->audio_rtp_socket, (struct sockaddr *) & (taskinfo->remote_audio_rtp_addr), remote_addr_len);
                    if (rc < 0) {
                        debugprint("closing audio rtp socket %d due to error %d in rtpstream_process_task_flags taskinfo=%p\n",
                                   taskinfo->audio_rtp_socket, errno, taskinfo);
                        close(taskinfo->audio_rtp_socket);
                        taskinfo->audio_rtp_socket = -1;
                    }
                } else {
                    /* Do NOT perform connect() when doing SRTP echo */
                }
            }
        }

        /* If we have valid ip and port numbers for video rtp stream */
        if (!(taskinfo->flags&TI_NULL_VIDEOIP))
        {
            if (taskinfo->video_rtcp_socket!=-1) {
                rc= connect (taskinfo->video_rtcp_socket, (struct sockaddr *) & (taskinfo->remote_video_rtcp_addr), remote_addr_len);
                if (rc < 0) {
                    debugprint("closing video rtcp socket %d due to error %d in rtpstream_process_task_flags taskinfo=%p\n",
                               taskinfo->video_rtcp_socket, errno, taskinfo);
                    close(taskinfo->video_rtcp_socket);
                    taskinfo->video_rtcp_socket = -1;
                }
            }
            if (taskinfo->video_rtp_socket!=-1) {
              if (!taskinfo->video_srtp_echo_active) {
                  rc= connect (taskinfo->video_rtp_socket, (struct sockaddr *) & (taskinfo->remote_video_rtp_addr), remote_addr_len);
                  if (rc < 0) {
                      debugprint("closing video rtp socket %d due to error %d in rtpstream_process_task_flags taskinfo=%p\n",
                                 taskinfo->video_rtp_socket, errno, taskinfo);
                      close(taskinfo->video_rtp_socket);
                      taskinfo->video_rtp_socket = -1;
                  }
              } else {
                  /* Do NOT perform connect() when doing SRTP echo */
              }
            }
        }

        taskinfo->flags&= ~TI_RECONNECTSOCKET;
        pthread_mutex_unlock (&(taskinfo->mutex));
    }
    if (taskinfo->flags & TI_PLAYFILE || taskinfo->flags & TI_PLAYAPATTERN) {
        /* copy playback information */
        taskinfo->audio_pattern_id = taskinfo->new_audio_pattern_id;
        taskinfo->audio_loop_count = taskinfo->new_audio_loop_count;
        taskinfo->audio_file_bytes_start = taskinfo->new_audio_file_bytes;
        taskinfo->audio_current_file_bytes = taskinfo->new_audio_file_bytes;
        taskinfo->audio_file_num_bytes = taskinfo->new_audio_file_size;
        taskinfo->audio_file_bytes_left = taskinfo->new_audio_file_size;
        taskinfo->audio_payload_type = taskinfo->new_audio_payload_type;

        taskinfo->audio_ms_per_packet = taskinfo->new_audio_ms_per_packet;
        assert(taskinfo->audio_ms_per_packet != 0);
        taskinfo->audio_bytes_per_packet = taskinfo->new_audio_bytes_per_packet;
        taskinfo->audio_timeticks_per_packet = taskinfo->new_audio_timeticks_per_packet;
        assert(taskinfo->audio_timeticks_per_packet != 0);
        taskinfo->audio_timeticks_per_ms = taskinfo->audio_timeticks_per_packet / taskinfo->audio_ms_per_packet;

        taskinfo->last_audio_timestamp = getmilliseconds() * taskinfo->audio_timeticks_per_ms;
        if (taskinfo->flags & TI_PLAYFILE) {
            taskinfo->flags &= ~TI_PLAYFILE;
        } else if (taskinfo->flags & TI_PLAYAPATTERN) {
            taskinfo->flags &= ~TI_PLAYAPATTERN;
        }

    }

    if (taskinfo->flags&TI_PLAYVPATTERN)
    {
        /* copy playback information */
        taskinfo->video_pattern_id = taskinfo->new_video_pattern_id;
        taskinfo->video_loop_count = taskinfo->new_video_loop_count;
        taskinfo->video_file_bytes_start = taskinfo->new_video_file_bytes;
        taskinfo->video_current_file_bytes = taskinfo->new_video_file_bytes;
        taskinfo->video_file_num_bytes = taskinfo->new_video_file_size;
        taskinfo->video_file_bytes_left = taskinfo->new_video_file_size;
        taskinfo->video_payload_type = taskinfo->new_video_payload_type;

        taskinfo->video_ms_per_packet = taskinfo->new_video_ms_per_packet;
        assert(taskinfo->video_ms_per_packet != 0);
        taskinfo->video_bytes_per_packet = taskinfo->new_video_bytes_per_packet;
        taskinfo->video_timeticks_per_packet = taskinfo->new_video_timeticks_per_packet;
        assert(taskinfo->video_timeticks_per_packet != 0);
        taskinfo->video_timeticks_per_ms = taskinfo->video_timeticks_per_packet / taskinfo->video_ms_per_packet;

        taskinfo->last_video_timestamp = getmilliseconds() * taskinfo->video_timeticks_per_ms;
        taskinfo->flags &= ~TI_PLAYVPATTERN;
    }
}

/**** todo - check code ****/
static unsigned long rtpstream_playrtptask(taskentry_t *taskinfo,
                                           unsigned long  timenow_ms,
                                           unsigned long* comparison_acheck,
                                           std::vector<unsigned long> &rs_apackets,
                                           unsigned long* comparison_vcheck,
                                           std::vector<unsigned long> &rs_vpackets,
                                           int taskindex)
{
    int                  rc;
    unsigned long        next_wake;
    unsigned long long   target_timestamp;
    int                  compresult;
    struct timeval       tv;
    fd_set               readfds;
    std::vector<unsigned char> rtp_header;
    std::vector<unsigned char> payload_data;
    std::vector<unsigned char> audio_out;
    std::vector<unsigned char> audio_in;
    std::vector<unsigned char> video_out;
    std::vector<unsigned char> video_in;
    unsigned short host_flags = 0;
    unsigned short host_seqnum = 0;
    unsigned int host_timestamp = 0;
    unsigned int host_ssrc = 0;
    unsigned short audio_seq_in = 0;
    unsigned short video_seq_in = 0;
    unsigned int audio_in_size = 0;
    unsigned int video_in_size = 0;

    union {
        rtp_header_t hdr;
        char buffer[MAX_UDP_RECV_BUFFER];
    } udp_recv_temp;

    union {
        rtp_header_t hdr;
        char buffer[MAX_UDP_RECV_BUFFER];
    } udp_recv_audio;

    union {
        rtp_header_t hdr;
        char buffer[MAX_UDP_SEND_BUFFER];
    } udp_send_audio;

    union {
        rtp_header_t hdr;
        char buffer[MAX_UDP_RECV_BUFFER];
    } udp_recv_video;

    union {
        rtp_header_t hdr;
        char buffer[MAX_UDP_SEND_BUFFER];
    } udp_send_video;


    tv.tv_sec = 0;
    tv.tv_usec = 10000; /* 10ms */

    *comparison_acheck = 0;
    *comparison_vcheck = 0;

    printAudioHex("----AUDIO RTP SOCKET----", "", 0, taskindex, taskinfo->audio_rtp_socket);
    printVideoHex("----VIDEO RTP SOCKET----", "", 0, taskindex, taskinfo->video_rtp_socket);

    /* OK, now to play - sockets are supposed to be non-blocking */
    /* no support for video stream at this stage. will need some work */

    next_wake = timenow_ms + 100; /* default next wakeup time */

    if ((taskinfo->audio_rtp_socket != -1) &&
        (taskindex >= 0) &&
        (taskindex <= ((int)rs_apackets.size() - 1)))
    {
        /* are we playing back an audio file/pattern? */
        if (taskinfo->audio_loop_count)
        {
            target_timestamp = timenow_ms * taskinfo->audio_timeticks_per_ms;
            next_wake = timenow_ms + taskinfo->audio_ms_per_packet - timenow_ms % taskinfo->audio_ms_per_packet;
            if (taskinfo->flags&(TI_NULL_AUDIOIP|TI_PAUSERTP|TI_PAUSERTPAPATTERN))
            {
                /* when paused, set timestamp so stream appears to be up to date */
                taskinfo->last_audio_timestamp = target_timestamp;
            }

            if (taskinfo->last_audio_timestamp < target_timestamp)
            {
                /* need to send rtp payload - build rtp packet header... */
                memset(udp_send_audio.buffer, 0, sizeof(udp_send_audio));
                udp_send_audio.hdr.flags= htons(0x8000|taskinfo->audio_payload_type);
                udp_send_audio.hdr.seq= htons(taskinfo->audio_seq_out);
                udp_send_audio.hdr.timestamp= htonl((uint32_t) (taskinfo->last_audio_timestamp & 0XFFFFFFFF));
                udp_send_audio.hdr.ssrc_id= htonl(taskinfo->audio_ssrc_id);
                /* add payload data to the packet - handle buffer wraparound */
                if (taskinfo->audio_file_bytes_left>=taskinfo->audio_bytes_per_packet)
                {
                    /* no need for fancy acrobatics */
                    memcpy (udp_send_audio.buffer+sizeof(rtp_header_t),taskinfo->audio_current_file_bytes,taskinfo->audio_bytes_per_packet);
                }
                else
                {
                    /* copy from end and then begining of file. does not handle the */
                    /* case where file is shorter than the packet length!! */
                    memcpy (udp_send_audio.buffer+sizeof(rtp_header_t),taskinfo->audio_current_file_bytes,taskinfo->audio_file_bytes_left);
                    memcpy (udp_send_audio.buffer+sizeof(rtp_header_t)+taskinfo->audio_file_bytes_left,taskinfo->audio_file_bytes_start,taskinfo->audio_bytes_per_packet-taskinfo->audio_file_bytes_left);
                }

                pthread_mutex_lock(&uacAudioMutex);
                if (g_txUACAudio.getCryptoTag() != 0)
                {
                    // GRAB RTP HEADER
                    rtp_header.resize(sizeof(rtp_header_t), 0);
                    memcpy(rtp_header.data(), udp_send_audio.buffer, sizeof(rtp_header_t) /*12*/);
                    // GRAB RTP PAYLOAD DATA
                    payload_data.resize(taskinfo->audio_bytes_per_packet, 0);
                    memcpy(payload_data.data(), udp_send_audio.buffer+sizeof(rtp_header_t), taskinfo->audio_bytes_per_packet);

                    // ENCRYPT
                    rc = g_txUACAudio.processOutgoingPacket(taskinfo->audio_seq_out, rtp_header, payload_data, audio_out);
                    printAudioHex("TXUACAUDIO -- processOutgoingPacket() rc==", "", rc, 0, 0);
                }
                else
                {
                    // NOENCRYPTION
                    audio_out.resize(sizeof(rtp_header_t)+taskinfo->audio_bytes_per_packet, 0);
                    memcpy(audio_out.data(), udp_send_audio.buffer, sizeof(rtp_header_t)+taskinfo->audio_bytes_per_packet);
                }

                /* now send the actual packet */
                rc= send (taskinfo->audio_rtp_socket,audio_out.data(),audio_out.size(),0);
                if (rc<0)
                {
                    printAudioHex("SEND FAILED: ", "", rc, errno, 0);

                    /* handle sending errors */
                    if ((errno==EAGAIN)||(errno==EWOULDBLOCK)||(errno==EINTR))
                    {
                        next_wake= timenow_ms+2; /* retry after short sleep */
                    }
                    else
                    {
                        /* this looks like a permanent error  - should we ignore ENETUNREACH? */
                        debugprint ("closing rtp socket %d due to error %d in rtpstream_new_call callinfo=%p\n",taskinfo->audio_rtp_socket,errno);
                        close (taskinfo->audio_rtp_socket);
                        taskinfo->audio_rtp_socket= -1;
                    }
                }
                else
                {
                    /* statistics - only count successful sends */
                    rtpstream_abytes_out+= taskinfo->audio_bytes_per_packet+sizeof(rtp_header_t);
                    rtpstream_apckts++;       // GLOBAL RTP packet counter
                    rs_apackets[taskindex]++; // TASK-specific RTP packet counter

                    printAudioHexUS("SIPP SUCCESS SEND LOG: ", audio_out.data(), audio_out.size(), rc, rtpstream_apckts);

                    FD_ZERO(&readfds);
                    FD_SET(taskinfo->audio_rtp_socket, &readfds);
                    rc = select(taskinfo->audio_rtp_socket+1, &readfds, NULL, NULL, &tv);

                    if (FD_ISSET(taskinfo->audio_rtp_socket, &readfds))
                    {
                        /* this is temp code - will have to reorganize if/when we include echo functionality */
                        /* just keep listening on rtp socket (is this really required?) - ignore any errors */
                        if (g_rxUACAudio.getCryptoTag() != 0)
                        {
                            audio_in_size = sizeof(rtp_header_t)+taskinfo->audio_bytes_per_packet+g_rxUACAudio.getAuthenticationTagSize();
                        }
                        else
                        {
                            // NOENCRYPTION
                            audio_in_size = sizeof(rtp_header_t)+taskinfo->audio_bytes_per_packet;
                        }
                        audio_in.resize(audio_in_size, 0);
                        while ((rc= recv (taskinfo->audio_rtp_socket,audio_in.data(),audio_in.size(),0))>=0)
                        {
                            /* for now we will just ignore any received data or receive errors */
                            /* separate code path for RTP echo */
                            rtpstream_abytes_in+= rc;
                            printAudioHexUS("SIPP SUCCESS RECV LOG: ", audio_in.data(), audio_in.size(), rc, rtpstream_apckts);
                        }

                        if (g_rxUACAudio.getCryptoTag() != 0)
                        {
                            // DECRYPT
                            rtp_header.clear();
                            payload_data.clear();

                            audio_seq_in = ntohs(((rtp_header_t*)audio_in.data())->seq);
                            rc = g_rxUACAudio.processIncomingPacket(audio_seq_in, audio_in, rtp_header, payload_data);
                            printAudioHex("RXUACAUDIO -- processIncomingPacket() rc==", "", rc, 0, 0);

                            host_flags = ntohs(((rtp_header_t*)audio_in.data())->flags);
                            host_seqnum = ntohs(((rtp_header_t*)audio_in.data())->seq);
                            host_timestamp = ntohl(((rtp_header_t*)audio_in.data())->timestamp);
                            host_ssrc = ntohl(((rtp_header_t*)audio_in.data())->ssrc_id);

                            audio_in[0] = (host_flags >> 8) & 0xFF;
                            audio_in[1] = host_flags & 0xFF;
                            audio_in[2] = (host_seqnum >> 8) & 0xFF;
                            audio_in[3] = host_seqnum & 0xFF;
                            audio_in[4] = (host_timestamp >> 24) & 0xFF;
                            audio_in[5] = (host_timestamp >> 16) & 0xFF;
                            audio_in[6] = (host_timestamp >> 8) & 0xFF;
                            audio_in[7] = host_timestamp & 0xFF;
                            audio_in[8] = (host_ssrc >> 24) & 0xFF;
                            audio_in[9] = (host_ssrc >> 16) & 0xFF;
                            audio_in[10]= (host_ssrc >> 8) & 0xFF;
                            audio_in[11]= host_ssrc & 0xFF;

                            memset(udp_recv_audio.buffer, 0, sizeof(udp_recv_audio));
                            memcpy(udp_recv_audio.buffer, rtp_header.data(), rtp_header.size());
                            memcpy(udp_recv_audio.buffer+sizeof(rtp_header_t), payload_data.data(), payload_data.size());
                        }
                        else
                        {
                            // NOENCRYPTION
                            host_flags = ntohs(((rtp_header_t*)audio_in.data())->flags);
                            host_seqnum = ntohs(((rtp_header_t*)audio_in.data())->seq);
                            host_timestamp = ntohl(((rtp_header_t*)audio_in.data())->timestamp);
                            host_ssrc = ntohl(((rtp_header_t*)audio_in.data())->ssrc_id);

                            audio_in[0] = (host_flags >> 8) & 0xFF;
                            audio_in[1] = host_flags & 0xFF;
                            audio_in[2] = (host_seqnum >> 8) & 0xFF;
                            audio_in[3] = host_seqnum & 0xFF;
                            audio_in[4] = (host_timestamp >> 24) & 0xFF;
                            audio_in[5] = (host_timestamp >> 16) & 0xFF;
                            audio_in[6] = (host_timestamp >> 8) & 0xFF;
                            audio_in[7] = host_timestamp & 0xFF;
                            audio_in[8] = (host_ssrc >> 24) & 0xFF;
                            audio_in[9] = (host_ssrc >> 16) & 0xFF;
                            audio_in[10]= (host_ssrc >> 8) & 0xFF;
                            audio_in[11]= host_ssrc & 0xFF;

                            memset(udp_recv_audio.buffer, 0, sizeof(udp_recv_audio));
                            memcpy(udp_recv_audio.buffer, audio_in.data(), audio_in.size());
                        }

                        // VALIDATION TEST
                        compresult = 0;
                        compresult = memcmp(udp_send_audio.buffer+sizeof(rtp_header_t),
                                            udp_recv_audio.buffer+sizeof(rtp_header_t),
                                            taskinfo->audio_bytes_per_packet /* PAYLOAD comparison ONLY -- header EXCLUDED*/);
                        if (compresult == 0)
                        {
                            // SUCCESS
                            printAudioHex("COMPARISON OK ", "", 0, taskinfo->audio_comparison_errors, rtpstream_apckts);
                            *comparison_acheck = 0;
                        }
                        else
                        {
                            // FAILURE
                            taskinfo->audio_comparison_errors++;
                            printAudioHex("COMPARISON FAILED", "", 0, taskinfo->audio_comparison_errors, rtpstream_apckts);
                            *comparison_acheck = 1;
                        }
                    }
                    else
                    {
                        taskinfo->audio_comparison_errors++;
                        printAudioHex("NODATA", "", 0, taskinfo->audio_comparison_errors, rtpstream_apckts);
                        *comparison_acheck = 1;
                    }

                    /* advance playback pointer to next packet */
                    taskinfo->audio_seq_out++;
                    /* must change if timer ticks per packet can be fractional */
                    taskinfo->last_audio_timestamp+= taskinfo->audio_timeticks_per_packet;
                    taskinfo->audio_file_bytes_left-= taskinfo->audio_bytes_per_packet;
                    if (taskinfo->audio_file_bytes_left>0)
                    {
                        taskinfo->audio_current_file_bytes+= taskinfo->audio_bytes_per_packet;
                    }
                    else
                    {
                        taskinfo->audio_current_file_bytes= taskinfo->audio_file_bytes_start-taskinfo->audio_file_bytes_left;
                        taskinfo->audio_file_bytes_left+= taskinfo->audio_file_num_bytes;
                        if (taskinfo->audio_loop_count>0)
                        {
                            /* one less loop to play. -1 (infinite loops) will stay as is */
                            taskinfo->audio_loop_count--;
                        }
                    }
                    if (taskinfo->last_audio_timestamp<target_timestamp)
                    {
                        /* no sleep if we are behind */
                        next_wake= timenow_ms;
                    }
                } /* if (rc < 0) */
                pthread_mutex_unlock(&uacAudioMutex);
            } /* if (taskinfo->last_audio_timestamp<target_timestamp) */
            else
            {
                printAudioHex("TIMESTAMP NOT QUITE RIGHT...", "", 0, 0, 0);
                *comparison_acheck = -1;
            }
        } /* if (taskinfo->audio_loop_count) */
        else
        {
          /* not busy playing back a file -  put possible rtp echo code here. */
        }
    } // if (taskinfo->audio_rtp_socket!=-1)

    if (taskinfo->audio_rtcp_socket!=-1)
    {
        /* just keep listening on rtcp socket (is this really required?) - ignore any errors */
        while ((rc= recv (taskinfo->audio_rtcp_socket,udp_recv_temp.buffer,sizeof(udp_recv_temp.buffer),0))>=0)
        {
            /*
             * rtpstream_abytes_in+= rc;
             */
        }
    }

    if ((taskinfo->video_rtp_socket != -1) &&
        (taskindex >= 0) &&
        (taskindex <= ((int)rs_vpackets.size() - 1)))
    {
        /* are we playing back a video file/pattern? */
        if (taskinfo->video_loop_count)
        {
            target_timestamp = timenow_ms * taskinfo->video_timeticks_per_ms;
            next_wake = timenow_ms + taskinfo->video_ms_per_packet - timenow_ms % taskinfo->video_ms_per_packet;
            if (taskinfo->flags&(TI_NULL_VIDEOIP|TI_PAUSERTP|TI_PAUSERTPVPATTERN))
            {
                /* when paused, set timestamp so stream appears to be up to date */
                taskinfo->last_video_timestamp = target_timestamp;
            }

            if (taskinfo->last_video_timestamp < target_timestamp)
            {
                /* need to send rtp payload - build rtp packet header... */
                memset(udp_send_video.buffer, 0, sizeof(udp_send_video));
                udp_send_video.hdr.flags= htons(0x8000|taskinfo->video_payload_type);
                udp_send_video.hdr.seq= htons(taskinfo->video_seq_out);
                udp_send_video.hdr.timestamp= htonl((uint32_t) (taskinfo->last_video_timestamp & 0XFFFFFFFF));
                udp_send_video.hdr.ssrc_id= htonl(taskinfo->video_ssrc_id);
                /* add payload data to the packet - handle buffer wraparound */
                if (taskinfo->video_file_bytes_left>=taskinfo->video_bytes_per_packet)
                {
                    /* no need for fancy acrobatics */
                    memcpy (udp_send_video.buffer+sizeof(rtp_header_t),taskinfo->video_current_file_bytes,taskinfo->video_bytes_per_packet);
                }
                else
                {
                    /* copy from end and then begining of file. does not handle the */
                    /* case where file is shorter than the packet length!! */
                    memcpy (udp_send_video.buffer+sizeof(rtp_header_t),taskinfo->video_current_file_bytes,taskinfo->video_file_bytes_left);
                    memcpy (udp_send_video.buffer+sizeof(rtp_header_t)+taskinfo->video_file_bytes_left,taskinfo->video_file_bytes_start,taskinfo->video_bytes_per_packet-taskinfo->video_file_bytes_left);
                }

                pthread_mutex_lock(&uacVideoMutex);
                if (g_txUACVideo.getCryptoTag() != 0)
                {
                    // GRAB RTP HEADER
                    rtp_header.resize(sizeof(rtp_header_t), 0);
                    memcpy(rtp_header.data(), udp_send_video.buffer, sizeof(rtp_header_t) /*12*/);
                    // GRAB RTP PAYLOAD DATA
                    payload_data.resize(taskinfo->video_bytes_per_packet, 0);
                    memcpy(payload_data.data(), udp_send_video.buffer+sizeof(rtp_header_t), taskinfo->video_bytes_per_packet);

                    // ENCRYPT
                    rc = g_txUACVideo.processOutgoingPacket(taskinfo->video_seq_out, rtp_header, payload_data, video_out);
                    printVideoHex("TXUACVIDEO -- processOutgoingPacket() rc==", "", rc, 0, 0);
                }
                else
                {
                    // NOENCRYPTION
                    video_out.resize(sizeof(rtp_header_t)+taskinfo->video_bytes_per_packet, 0);
                    memcpy(video_out.data(), udp_send_video.buffer, sizeof(rtp_header_t)+taskinfo->video_bytes_per_packet);
                }

                /* now send the actual packet */
                rc= send (taskinfo->video_rtp_socket,video_out.data(),video_out.size(),0);
                if (rc<0)
                {
                    printVideoHex("SEND FAILED: ", "", rc, errno, 0);

                    /* handle sending errors */
                    if ((errno==EAGAIN)||(errno==EWOULDBLOCK)||(errno==EINTR))
                    {
                        next_wake= timenow_ms+2; /* retry after short sleep */
                    }
                    else
                    {
                        /* this looks like a permanent error  - should we ignore ENETUNREACH? */
                        debugprint ("closing rtp socket %d due to error %d in rtpstream_new_call callinfo=%p\n",taskinfo->video_rtp_socket,errno);
                        close (taskinfo->video_rtp_socket);
                        taskinfo->video_rtp_socket= -1;
                    }
                }
                else
                {
                    /* statistics - only count successful sends */
                    rtpstream_vbytes_out+= taskinfo->video_bytes_per_packet+sizeof(rtp_header_t);
                    rtpstream_vpckts++;       // GLOBAL RTP packet counter
                    rs_vpackets[taskindex]++; // TASK-specific RTP packet counter

                    printVideoHexUS("SIPP SUCCESS SEND LOG: ", video_out.data(), video_out.size(), rc, rtpstream_vpckts);

                    FD_ZERO(&readfds);
                    FD_SET(taskinfo->video_rtp_socket, &readfds);
                    rc = select(taskinfo->video_rtp_socket+1, &readfds, NULL, NULL, &tv);

                    if (FD_ISSET(taskinfo->video_rtp_socket, &readfds))
                    {
                        /* this is temp code - will have to reorganize if/when we include echo functionality */
                        /* just keep listening on rtp socket (is this really required?) - ignore any errors */
                        if (g_rxUACVideo.getCryptoTag() != 0)
                        {
                            video_in_size = sizeof(rtp_header_t)+taskinfo->video_bytes_per_packet+g_rxUACVideo.getAuthenticationTagSize();
                        }
                        else
                        {
                            // NOENCRYPTION
                            video_in_size = sizeof(rtp_header_t)+taskinfo->video_bytes_per_packet;
                        }
                        video_in.resize(video_in_size, 0);
                        while ((rc= recv (taskinfo->video_rtp_socket,video_in.data(),video_in.size(),0))>=0)
                        {
                            /* for now we will just ignore any received data or receive errors */
                            /* separate code path for RTP echo */
                            rtpstream_vbytes_in+= rc;
                            printVideoHexUS("SIPP SUCCESS RECV LOG: ", video_in.data(), video_in.size(), rc, rtpstream_vpckts);
                        }

                        if (g_rxUACVideo.getCryptoTag() != 0)
                        {
                            // DECRYPT
                            rtp_header.clear();
                            payload_data.clear();
                            video_seq_in = ntohs(((rtp_header_t*)video_in.data())->seq);
                            rc = g_rxUACVideo.processIncomingPacket(video_seq_in, video_in, rtp_header, payload_data);
                            printVideoHex("RXUACVIDEO -- processIncomingPacket() rc==", "", rc, 0, 0);

                            host_flags = ntohs(((rtp_header_t*)video_in.data())->flags);
                            host_seqnum = ntohs(((rtp_header_t*)video_in.data())->seq);
                            host_timestamp = ntohl(((rtp_header_t*)video_in.data())->timestamp);
                            host_ssrc = ntohl(((rtp_header_t*)video_in.data())->ssrc_id);

                            video_in[0] = (host_flags >> 8) & 0xFF;
                            video_in[1] = host_flags & 0xFF;
                            video_in[2] = (host_seqnum >> 8) & 0xFF;
                            video_in[3] = host_seqnum & 0xFF;
                            video_in[4] = (host_timestamp >> 24) & 0xFF;
                            video_in[5] = (host_timestamp >> 16) & 0xFF;
                            video_in[6] = (host_timestamp >> 8) & 0xFF;
                            video_in[7] = host_timestamp & 0xFF;
                            video_in[8] = (host_ssrc >> 24) & 0xFF;
                            video_in[9] = (host_ssrc >> 16) & 0xFF;
                            video_in[10]= (host_ssrc >> 8) & 0xFF;
                            video_in[11]= host_ssrc & 0xFF;

                            memset(udp_recv_video.buffer, 0, sizeof(udp_recv_video));
                            memcpy(udp_recv_video.buffer, rtp_header.data(), rtp_header.size());
                            memcpy(udp_recv_video.buffer+sizeof(rtp_header_t), payload_data.data(), payload_data.size());
                        }
                        else
                        {
                            // NOENCRYPTION
                            host_flags = ntohs(((rtp_header_t*)video_in.data())->flags);
                            host_seqnum = ntohs(((rtp_header_t*)video_in.data())->seq);
                            host_timestamp = ntohl(((rtp_header_t*)video_in.data())->timestamp);
                            host_ssrc = ntohl(((rtp_header_t*)video_in.data())->ssrc_id);

                            video_in[0] = (host_flags >> 8) & 0xFF;
                            video_in[1] = host_flags & 0xFF;
                            video_in[2] = (host_seqnum >> 8) & 0xFF;
                            video_in[3] = host_seqnum & 0xFF;
                            video_in[4] = (host_timestamp >> 24) & 0xFF;
                            video_in[5] = (host_timestamp >> 16) & 0xFF;
                            video_in[6] = (host_timestamp >> 8) & 0xFF;
                            video_in[7] = host_timestamp & 0xFF;
                            video_in[8] = (host_ssrc >> 24) & 0xFF;
                            video_in[9] = (host_ssrc >> 16) & 0xFF;
                            video_in[10]= (host_ssrc >> 8) & 0xFF;
                            video_in[11]= host_ssrc & 0xFF;

                            memset(udp_recv_video.buffer, 0, sizeof(udp_recv_video));
                            memcpy(udp_recv_video.buffer, video_in.data(), video_in.size());
                        }

                        // VALIDATION TEST
                        compresult = 0;
                        compresult = memcmp(udp_send_video.buffer+sizeof(rtp_header_t),
                                            udp_recv_video.buffer+sizeof(rtp_header_t),
                                            taskinfo->video_bytes_per_packet /* PAYLOAD comparison ONLY -- header EXCLUDED*/);
                        if (compresult == 0)
                        {
                            // SUCCESS
                            printVideoHex("COMPARISON OK ", "", 0, taskinfo->video_comparison_errors, rtpstream_vpckts);
                            *comparison_vcheck = 0;
                        }
                        else
                        {
                            // FAILURE
                            taskinfo->video_comparison_errors++;
                            printVideoHex("COMPARISON FAILED", "", 0, taskinfo->video_comparison_errors, rtpstream_vpckts);
                            *comparison_vcheck = 1;
                        }
                    }
                    else
                    {
                        taskinfo->video_comparison_errors++;
                        printVideoHex("NODATA", "", 0, taskinfo->video_comparison_errors, rtpstream_vpckts);
                        *comparison_vcheck = 1;
                    }

                    /* advance playback pointer to next packet */
                    taskinfo->video_seq_out++;
                    /* must change if timer ticks per packet can be fractional */
                    taskinfo->last_video_timestamp+= taskinfo->video_timeticks_per_packet;
                    taskinfo->video_file_bytes_left-= taskinfo->video_bytes_per_packet;
                    if (taskinfo->video_file_bytes_left>0)
                    {
                        taskinfo->video_current_file_bytes+= taskinfo->video_bytes_per_packet;
                    }
                    else
                    {
                        taskinfo->video_current_file_bytes= taskinfo->video_file_bytes_start-taskinfo->video_file_bytes_left;
                        taskinfo->video_file_bytes_left+= taskinfo->video_file_num_bytes;
                        if (taskinfo->video_loop_count>0)
                        {
                            /* one less loop to play. -1 (infinite loops) will stay as is */
                            taskinfo->video_loop_count--;
                        }
                    }
                    if (taskinfo->last_video_timestamp<target_timestamp)
                    {
                        /* no sleep if we are behind */
                        next_wake= timenow_ms;
                    }
                } /* if (rc < 0) */
                pthread_mutex_unlock(&uacVideoMutex);
            } /* if (taskinfo->last_video_timestamp<target_timestamp) */
            else
            {
                printVideoHex("TIMESTAMP NOT QUITE RIGHT...", "", 0, 0, 0);
                *comparison_vcheck = -1;
            }
        } /* if (taskinfo->video_loop_count) */
        else
        {
          /* not busy playing back a file -  put possible rtp echo code here. */
        }
    }

    if (taskinfo->video_rtcp_socket!=-1)
    {
        /* just keep listening on rtcp socket (is this really required?) - ignore any errors */
        while ((rc= recv (taskinfo->video_rtcp_socket,udp_recv_temp.buffer,sizeof(udp_recv_temp),0))>=0)
        {
            /*
             * rtpstream_vbytes_in+= rc;
             */
        }
    }

    return next_wake;
}

/*********************************************************************************/
/*********************************************************************************/
/*********************************************************************************/

/* code checked */
static void* rtpstream_playback_thread(void* params)
{
    threaddata_t   *threaddata = (threaddata_t *) params;
    taskentry_t    *taskinfo = NULL;
    int            taskindex;

    unsigned long  timenow_ms;
    unsigned long  waketime_ms;
    int            sleeptime_us;

    unsigned long  comparison_acheck;
    unsigned long  comparison_vcheck;
    unsigned long  rtpresult;
    int i = 0;
    std::vector<unsigned long> rs_apackets;
    std::vector<unsigned long> rs_vpackets;
    std::vector<unsigned long> rs_artpcheck;
    std::vector<unsigned long> rs_vrtpcheck;
    double verdict;

    comparison_acheck = 0;
    comparison_vcheck = 0;
    rtpresult = 0; /* includes BOTH AUDIO/VIDEO checks */
    rs_apackets.resize(threaddata->max_tasks);
    rs_vpackets.resize(threaddata->max_tasks);
    rs_artpcheck.resize(threaddata->max_tasks);
    rs_vrtpcheck.resize(threaddata->max_tasks);
    verdict = 0.0;

    rtpstream_numthreads++; /* perhaps wrap this in a mutex? */

    // INITIALIZE AUDIO/VIDEO COMPARISON ERRORS
    for (taskindex = 0; taskindex < threaddata->num_tasks; taskindex++)
    {
        (&threaddata->tasklist)[taskindex]->audio_comparison_errors = 0;
        (&threaddata->tasklist)[taskindex]->video_comparison_errors = 0;
    }

    // ROBUSTNESS CHECK
    for (taskindex = 0; taskindex < threaddata->num_tasks; taskindex++)
    {
        taskinfo = (&threaddata->tasklist)[taskindex];

        if (taskinfo->audio_active)
        {
            if (
                (taskinfo->new_audio_ms_per_packet == 0) ||
                (taskinfo->new_audio_loop_count < -1) ||
                (taskinfo->new_audio_pattern_id < -1) ||
                (taskinfo->new_audio_pattern_id > 6) ||
                (taskinfo->new_audio_payload_type < 0) ||
                (taskinfo->new_audio_payload_type > 127)
               )
            {
                // AUDIO VALIDATION FAILED -- ABORT MISSION
                threaddata->exit_flag = 1;
            }
        }
        else if (taskinfo->video_active)
        {
            if (
                (taskinfo->new_video_ms_per_packet == 0) ||
                (taskinfo->new_video_loop_count < -1) ||
                (taskinfo->new_video_pattern_id < -1) ||
                (taskinfo->new_video_pattern_id > 6) ||
                (taskinfo->new_video_payload_type < 0) ||
                (taskinfo->new_video_payload_type > 127)
               )
            {
                // VIDEO VALIDATION FAILED -- ABORT MISSION
                threaddata->exit_flag = 1;
            }
        }
    }

    while (!threaddata->exit_flag)
    {
        timenow_ms= getmilliseconds();
        waketime_ms= timenow_ms+ 100; /* default sleep 100ms */

        /* iterate through tasks and handle playback and other actions */
        for (taskindex=0;taskindex<threaddata->num_tasks;taskindex++)
        {
            printAudioHex("----DEBUG CURRENTTASK/NUMTASKS----", "", 0, taskindex, threaddata->num_tasks);
            printVideoHex("----DEBUG CURRENTTASK/NUMTASKS----", "", 0, taskindex, threaddata->num_tasks);
            taskinfo= (&threaddata->tasklist)[taskindex];
            if (taskinfo->flags&TI_CONFIGFLAGS)
            {
                if (taskinfo->flags&TI_KILLTASK)
                {
                    /* remove this task entry and release its resources */
                    pthread_mutex_lock (&(threaddata->tasklist_mutex));
                    (&threaddata->tasklist)[taskindex--]= (&threaddata->tasklist)[--threaddata->num_tasks];
                    threaddata->del_pending--;   /* must decrease del_pending after num_tasks */
                    pthread_mutex_unlock (&(threaddata->tasklist_mutex));
                    rtpstream_free_taskinfo (taskinfo);
                    continue;
                }
                /* handle any other config related flags */
                rtpstream_process_task_flags (taskinfo);
            }

            /* should we update current time inbetween tasks? */
            if (taskinfo->nextwake_ms<=timenow_ms)
            {
                /* task needs to execute now */
                taskinfo->nextwake_ms= rtpstream_playrtptask (taskinfo,timenow_ms,&comparison_acheck,rs_apackets,&comparison_vcheck,rs_vpackets,taskindex);

                if (comparison_acheck == 1)
                {
                    rs_artpcheck[taskindex]++;
                    printAudioHex("----FAILED RTP CHECK----", "", 0, rs_artpcheck[taskindex], rtpstream_apckts);
                }
                else
                {
                    printAudioHex("----PASSED RTP CHECK----", "", 0, rs_artpcheck[taskindex], rtpstream_apckts);
                }

                if (comparison_vcheck == 1)
                {
                    rs_vrtpcheck[taskindex]++;
                    printVideoHex("----FAILED RTP CHECK----", "", 0, rs_vrtpcheck[taskindex], rtpstream_vpckts);
                }
                else
                {
                    printVideoHex("----PASSED RTP CHECK----", "", 0, rs_vrtpcheck[taskindex], rtpstream_vpckts);
                }
            }
            if (waketime_ms>taskinfo->nextwake_ms)
            {
                waketime_ms= taskinfo->nextwake_ms;
            }
        }
        /* sleep until next iteration of playback loop */
        sleeptime_us= (waketime_ms-getmilliseconds())*1000;
        if (sleeptime_us>0)
        {
            usleep (sleeptime_us);
        }
    }

    // EXITING... CALCULATE RESULT
    printAudioVector("----RTPCHECKS----", rs_artpcheck);
    printVideoVector("----RTPCHECKS----", rs_vrtpcheck);
    printAudioVector("----PACKET COUNTS----", rs_apackets);
    printVideoVector("----PACKET COUNTS----", rs_vpackets);

    for (i = 0; i < threaddata->max_tasks; i++)
    {
        if (rs_apackets[i] > 0)
        {
            verdict = ((double)rs_artpcheck[i] / (double)rs_apackets[i]);
            if (verdict >= audiotolerance)
            {
                // PACKETS TRANSMITTED IN TASK -- RTP CHECK FAILED
                set_bit(&rtpresult, taskinfo->audio_pattern_id);
            }
            else
            {
                // PACKETS TRANSMITTED IN TASK -- RTP CHECK SUCCEEDED
                //
                // FIXME
                //
                // "rtpresult" is currently limiting us in reporting detailed
                // results of per-task RTP check success/failures --
                // therefore at the present time we use it to indicate
                // the combined results of ALL tasks RTP checks for ALL
                // RTP patterns -- which means that bits are currently only
                // set for a given pattern in a given task if its RTP check
                // has failed -- this does not matter if its RTP check has
                // succeeded since "rtpresult" is initialized to ZERO by
                // default...
            }
        }
        else
        {
            // NO PACKETS TRANSMITTED IN TASK -- NO-OP...
        }

        if (rs_vpackets[i] > 0)
        {
            verdict = ((double)rs_vrtpcheck[i] / (double)rs_vpackets[i]);
            if (verdict >= videotolerance)
            {
                // PACKETS TRANSMITTED IN TASK -- RTP CHECK FAILED
                set_bit(&rtpresult, taskinfo->video_pattern_id);
            }
            else
            {
                // PACKETS TRANSMITTED IN TASK -- RTP CHECK SUCCEEDED
                //
                // FIXME
                //
                // "rtpresult" is currently limiting us in reporting detailed
                // results of per-task RTP check success/failures --
                // therefore at the present time we use it to indicate
                // the combined results of ALL tasks RTP checks for ALL
                // RTP patterns -- which means that bits are currently only
                // set for a given pattern in a given task if its RTP check
                // has failed -- this does not matter if its RTP check has
                // succeeded since "rtpresult" is initialized to ZERO by
                // default...
            }
        }
        else
        {
            // NO PACKETS TRANSMITTED IN TASK -- NO-OP...
        }
    }

    /* Free all task and thread resources and exit the thread */
    for (taskindex=0;taskindex<threaddata->num_tasks;taskindex++)
    {
        /* check if we should delete this thread, else let owner call clear it */
        /* small chance of race condition in this code */
        taskinfo= (&threaddata->tasklist)[taskindex];
        if (taskinfo->flags&TI_KILLTASK) {
            rtpstream_free_taskinfo (taskinfo);
        } else {
            taskinfo->parent_thread= NULL; /* no longer associated with a thread */
        }
    }
    pthread_mutex_destroy(&(threaddata->tasklist_mutex));
    free (threaddata);
    rtpstream_numthreads--; /* perhaps wrap this in a mutex? */

    // PTHREAD EXIT...
    printAudioHex("PLAYBACK THREAD EXITING...", "", 0, rtpresult, 0);
    printVideoHex("PLAYBACK THREAD EXITING...", "", 0, rtpresult, 0);
    pthread_exit((void*) rtpresult);

    return NULL;
}

/* code checked */
static int rtpstream_start_task (rtpstream_callinfo_t *callinfo)
{
    int           ready_index;
    int           allocsize;
    threaddata_t  **threadlist;
    threaddata_t  *threaddata;
    pthread_t     threadID;

    /* safety check... */
    if (!callinfo->taskinfo) {
        return 0;
    }

    /* we count on the fact that only one thread can add/remove playback tasks */
    /* thus we don't have mutexes to protect the thread list objects.          */
    for (ready_index=0;ready_index<num_ready_threads;ready_index++) {
        /* ready threads have a spare task slot or should have one very shortly */
        /* if we find a task with no spare slots, just skip to the next one.    */
        if (ready_threads[ready_index]->num_tasks<ready_threads[ready_index]->max_tasks) {
            /* we found a thread with an open task slot. */
            break;
        }
    }

    if (ready_index==num_ready_threads) {
        /* did not find a thread with spare task slots, thus we create one here */
        if (num_ready_threads>=ready_threads_max) {
            /* need to allocate more memory for thread list */
            ready_threads_max+= RTPSTREAM_THREADBLOCKSIZE;
            threadlist= (threaddata_t **) realloc (ready_threads,sizeof(*ready_threads)*ready_threads_max);
            if (!threadlist) {
                /* could not allocate bigger block... worry [about it later] */
                ready_threads_max-= RTPSTREAM_THREADBLOCKSIZE;
                return 0;
            }
            ready_threads= threadlist;
        }
        /* create and initialise data structure for new thread */
        allocsize= sizeof(*threaddata)+sizeof(threaddata->tasklist)*(rtp_tasks_per_thread-1);
        threaddata= (threaddata_t *) malloc (allocsize);
        if (!threaddata) {
            return 0;
        }
        memset (threaddata,0,allocsize);
        threaddata->max_tasks= rtp_tasks_per_thread;
        threaddata->busy_list_index= -1;
        pthread_mutex_init(&(threaddata->tasklist_mutex),NULL);
        /* create the thread itself */
        if (pthread_create(&threadID,NULL,rtpstream_playback_thread,threaddata)) {
            /* error creating the thread */
            free (threaddata);
            return 0;
        }

        printAudioHex("CREATED THREAD: ", "", 0, (int)(long long)threadID, 0);
        printVideoHex("CREATED THREAD: ", "", 0, (int)(long long)threadID, 0);

        // Save threadID
        callinfo->threadID = threadID;
        /* Add thread to list of ready (spare capacity) threads */
        ready_threads[num_ready_threads++]= threaddata;
    }

    /* now add new task to a spare slot in our thread tasklist */
    threaddata= ready_threads[ready_index];
    callinfo->taskinfo->parent_thread= threaddata;
    pthread_mutex_lock (&(threaddata->tasklist_mutex));
    (&threaddata->tasklist)[threaddata->num_tasks++]= callinfo->taskinfo;
    pthread_mutex_unlock (&(threaddata->tasklist_mutex));

    /* this check relies on playback thread to decrement num_tasks before */
    /* decrementing del_pending -- else we need to lock before this test  */
    if ((threaddata->del_pending==0)&&(threaddata->num_tasks>=threaddata->max_tasks)) {
        /* move this thread to the busy list - no free task slots */
        /* first check if the busy list is big enough to hold new thread */
        if (num_busy_threads>=busy_threads_max) {
            /* need to allocate more memory for thread list */
            busy_threads_max+= RTPSTREAM_THREADBLOCKSIZE;
            threadlist= (threaddata_t **) realloc (busy_threads,sizeof(*busy_threads)*busy_threads_max);
            if (!threadlist) {
                /* could not allocate bigger block... leave thread in ready list */
                busy_threads_max-= RTPSTREAM_THREADBLOCKSIZE;
                return 1; /* success, sort of */
            }
            busy_threads= threadlist;
        }
        /* add to busy list */
        threaddata->busy_list_index= num_busy_threads;
        busy_threads[num_busy_threads++]= threaddata;
        /* remove from ready list */
        ready_threads[ready_index]= ready_threads[--num_ready_threads];
    }

    return 1; /* done! */
}

/* code checked */
static void rtpstream_stop_task(rtpstream_callinfo_t* callinfo)
{
    threaddata_t  **threadlist;
    taskentry_t   *taskinfo= callinfo->taskinfo;
    int           busy_index;

    if (taskinfo)
    {
        if (taskinfo->parent_thread)
        {
            /* this call's task is registered with an executing thread */
            /* first move owning thread to the ready list - will be ready soon */
            busy_index= taskinfo->parent_thread->busy_list_index;
            if (busy_index>=0)
            {
                /* make sure we have enough entries in ready list */
                if (num_ready_threads>=ready_threads_max)
                {
                    /* need to allocate more memory for thread list */
                    ready_threads_max+= RTPSTREAM_THREADBLOCKSIZE;
                    threadlist= (threaddata_t **) realloc (ready_threads,sizeof(*ready_threads)*ready_threads_max);
                    if (!threadlist)
                    {
                        /* could not allocate bigger block... reset max threads */
                        /* this is a problem - ready thread gets "lost" on busy list */
                        ready_threads_max-= RTPSTREAM_THREADBLOCKSIZE;
                    }
                    else
                    {
                        ready_threads= threadlist;
                    }
                }

                if (num_ready_threads<ready_threads_max)
                {
                    /* OK, got space on ready list, move to ready list */
                    busy_threads[busy_index]->busy_list_index= -1;
                    ready_threads[num_ready_threads++]= busy_threads[busy_index];
                    num_busy_threads--;
                    /* fill up gap in the busy thread list */
                    if (busy_index!=num_busy_threads)
                    {
                        busy_threads[busy_index]= busy_threads[num_busy_threads];
                        busy_threads[busy_index]->busy_list_index= busy_index;
                    }
                }
            }
            /* then ask the thread to destory this task (and its memory) */
            pthread_mutex_lock (&(taskinfo->parent_thread->tasklist_mutex));
            taskinfo->parent_thread->del_pending++;
            taskinfo->flags|= TI_KILLTASK;
            pthread_mutex_unlock (&(taskinfo->parent_thread->tasklist_mutex));

            // PTHREAD IS NOT JOINABLE HERE...
        }
        else
        {
            /* no playback thread owner, just free it */
            rtpstream_free_taskinfo (taskinfo);
        }
        callinfo->taskinfo= NULL;
    }
}

/* code checked */
int rtpstream_new_call (rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_new_call callinfo=%p\n",callinfo);

    taskentry_t   *taskinfo;

    /* general init */
    memset (callinfo,0,sizeof(*callinfo));

    // zero remote audio/video ports
    callinfo->remote_audioport = 0;
    callinfo->remote_videoport = 0;

    taskinfo= (taskentry_t *) malloc (sizeof(*taskinfo));
    if (!taskinfo) {
        /* cannot allocate taskinfo memory - bubble error up */
        return 0;
    }
    callinfo->taskinfo= taskinfo;

    memset (taskinfo,0,sizeof(*taskinfo));
    taskinfo->flags= TI_NULLIP;
    /* socket descriptors */
    taskinfo->audio_rtp_socket= -1;
    taskinfo->audio_rtcp_socket= -1;
    taskinfo->video_rtp_socket= -1;
    taskinfo->video_rtcp_socket= -1;

    /* audio/video SRTP echo activity indicators */
    taskinfo->audio_srtp_echo_active = 0;
    taskinfo->video_srtp_echo_active = 0;

    /* rtp stream members */
    taskinfo->audio_ssrc_id= global_ssrc_id++;
    taskinfo->video_ssrc_id= global_ssrc_id++;

    /* pthread mutexes */
    pthread_mutex_init(&(callinfo->taskinfo->mutex),NULL);

    return 1;
}

/* code checked */
void rtpstream_end_call (rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_end_call callinfo=%p\n",callinfo);

    /* stop playback thread(s) for this call */
    rtpstream_stop_task (callinfo);

    // zero remote audio/video ports
    callinfo->remote_audioport = 0;
    callinfo->remote_videoport = 0;
}

/* code checked */
int rtpstream_cache_file (char *filename,
                          int mode /* 0: FILE -- 1: PATTERN */,
                          int id,
                          int bytes_per_packet,
                          int stream_type)
{
    int           count= 0;
    cached_file_t *newfilecachelist;
    cached_pattern_t *newpatterncachelist;
    char          *filecontents;
    struct stat   statbuffer;
    FILE          *f;

    debugprint ("rtpstream_cache_file filename=%s mode=%d id=%d bytes_per_packet=%d stream_type=%d\n", filename, mode, id, bytes_per_packet, stream_type);

    if ((debugafile == NULL) &&
        rtpcheck_debug &&
        (stream_type == 0))
    {
        debugafile = fopen("debugafile", "w");
        if (debugafile == NULL)
        {
            /* error encountered opening audio debug file */
            return -1;
        }
    }

    if ((debugvfile == NULL) &&
        rtpcheck_debug &&
        (stream_type == 1))
    {
        debugvfile = fopen("debugvfile", "w");
        if (debugvfile == NULL)
        {
            /* error encountered opening video debug file */
            return -1;
        }
    }

    if (mode == 1)
    {
        if ((id < 1) || (id > NUMPATTERNS))
        {
            /* invalid pattern ID specified */
            return -1;
        }

        /* cached pattern entries are stored in a dynamically grown array. */
        /* could use a binary (or avl) tree but number of files should  */
        /* be small and doesn't really justify the effort.              */
        while (count<num_cached_files)
        {
            count++;
        }

        if (!(num_cached_files%RTPSTREAM_FILESPERBLOCK)) {
            /* Time to allocate more memory for the next block of files */
            newpatterncachelist= (cached_pattern_t*) realloc(cached_patterns,sizeof(*cached_patterns)*(num_cached_files+RTPSTREAM_FILESPERBLOCK));
            if (!newpatterncachelist) {
                /* out of memory */
                return -1;
            }
            cached_patterns= newpatterncachelist;
        }

        cached_patterns[num_cached_files].bytes= (char*)malloc(bytes_per_packet);
        if (cached_patterns[num_cached_files].bytes == NULL)
        {
            /* out of memory */
            return -1;
        }

        if (id == 1)
        {
            memset(cached_patterns[num_cached_files].bytes, PATTERN1, bytes_per_packet);
        }
        else if (id == 2)
        {
            memset(cached_patterns[num_cached_files].bytes, PATTERN2, bytes_per_packet);
        }
        else if (id == 3)
        {
            memset(cached_patterns[num_cached_files].bytes, PATTERN3, bytes_per_packet);
        }
        else if (id == 4)
        {
            memset(cached_patterns[num_cached_files].bytes, PATTERN4, bytes_per_packet);
        }
        else if (id == 5)
        {
            memset(cached_patterns[num_cached_files].bytes, PATTERN5, bytes_per_packet);
        }
        else if (id == 6)
        {
            memset(cached_patterns[num_cached_files].bytes, PATTERN6, bytes_per_packet);
        }

        cached_patterns[num_cached_files].filesize= bytes_per_packet;
        cached_patterns[num_cached_files].id = id;

        return num_cached_files++; /* one new cached pattern */
    }
    else
    {
        /* cached file entries are stored in a dynamically grown array. */
        /* could use a binary (or avl) tree but number of files should  */
        /* be small and doesn't really justify the effort.              */
        while (count<num_cached_files) {
            if (!strcmp(cached_files[count].filename,filename)) {
                /* found the file already loaded. just return index */
                return count;
            }
            count++;
        }

        /* Allocate memory and load file */
        if (stat(filename,&statbuffer)) {
            /* could not get file information */
            return -1;
        }
        f= fopen(filename,"rb");
        if (!f) {
            /* could not open file */
            return -1;
        }

        filecontents= (char *)malloc (statbuffer.st_size);
        if (!filecontents) {
            /* could not alloc mem */
            return -1;
        }
        if (!fread (filecontents,statbuffer.st_size,1,f)) {
            /* could not read file */
            free (filecontents);
            return -1;
        }
        fclose (f);

        if (!(num_cached_files%RTPSTREAM_FILESPERBLOCK)) {
            /* Time to allocate more memory for the next block of files */
            newfilecachelist= (cached_file_t*) realloc(cached_files,sizeof(*cached_files)*(num_cached_files+RTPSTREAM_FILESPERBLOCK));
            if (!newfilecachelist) {
                /* out of memory */
                free (filecontents);
                return -1;
            }
            cached_files= newfilecachelist;
        }
        cached_files[num_cached_files].bytes= filecontents;
        strncpy(cached_files[num_cached_files].filename,filename,sizeof(cached_files[num_cached_files].filename) - 1);
        cached_files[num_cached_files].filesize=statbuffer.st_size;
        return num_cached_files++;
    }
}

static int rtpstream_setsocketoptions (int sock)
{
    /* set socket non-blocking */
    int flags= fcntl(sock,F_GETFL,0);
    if (fcntl(sock,F_SETFL,flags|O_NONBLOCK)==-1) {
        return 0;
    }

    /* set buffer size */
    unsigned int buffsize= rtp_buffsize;

    /* Increase buffer sizes for this sockets */
    if(setsockopt(sock,SOL_SOCKET,SO_SNDBUF,(char*)&buffsize,sizeof(buffsize))) {
        return 0;
    }
    if(setsockopt(sock,SOL_SOCKET,SO_RCVBUF,(char*)&buffsize,sizeof(buffsize))) {
        return 0;
    }

    return 1; /* success */
}

/* code checked */
static int rtpstream_get_localport (int *rtpsocket, int *rtcpsocket)
{
    int                       port_number;
    int                       tries;
    struct sockaddr_storage   address;

    debugprint ("rtpstream_get_localport\n");

    if (next_rtp_port < media_port)
    {
        next_rtp_port = media_port;
    }

    /* initialise address family and IP address for media socket */
    memset(&address,0,sizeof(address));
    address.ss_family= media_ip_is_ipv6?AF_INET6:AF_INET;
    if ((media_ip_is_ipv6?
         inet_pton(AF_INET6,media_ip,&((_RCAST(struct sockaddr_in6 *,&address))->sin6_addr)):
         inet_pton(AF_INET,media_ip,&((_RCAST(struct sockaddr_in *,&address))->sin_addr)))!=1) {
        WARNING("Could not set up media IP for RTP streaming");
        return 0;
    }

    /* create new UDP listen socket */
    *rtpsocket= socket(media_ip_is_ipv6?PF_INET6:PF_INET,SOCK_DGRAM,0);
    if (*rtpsocket==-1) {
        WARNING("Could not open socket for RTP streaming: %s", strerror(errno));
        return 0;
    }

    for (tries=0;tries<BIND_MAX_TRIES;tries++) {
        /* try a sequence of port numbers until we find one where we can bind    */
        /* should normally be the first port we try, unless we have long-running */
        /* calls or somebody else is nicking ports.                              */

        port_number = next_rtp_port;
        /* skip rtp ports in multples of 2 (allow for rtp plus rtcp) */
        next_rtp_port += 2;
        if (next_rtp_port > (max_rtp_port - 1)) {
            next_rtp_port = media_port;
        }

        sockaddr_update_port(&address, port_number);
        if (::bind(*rtpsocket,(sockaddr *)(void *)&address,
                   sizeof(address)) == 0) {
            break;
        }
    }
    /* Exit here if we didn't get a suitable port for rtp stream */
    if (tries==BIND_MAX_TRIES) {
        close (*rtpsocket);
        *rtpsocket= -1;
        WARNING("Could not bind port for RTP streaming after %d tries", tries);
        return 0;
    }

    if (!rtpstream_setsocketoptions (*rtpsocket)) {
        close (*rtpsocket);
        *rtpsocket= -1;
        WARNING("Could not set socket options for RTP streaming");
        return 0;
    }

    /* create socket for rtcp - ignore any errors */
    *rtcpsocket= socket(media_ip_is_ipv6?PF_INET6:PF_INET,SOCK_DGRAM,0);
    if (*rtcpsocket!=-1) {
        /* try to bind it to our preferred address */
        sockaddr_update_port(&address, port_number + 1);
        if (::bind(*rtcpsocket,(sockaddr *)(void *)&address,
                   sizeof(address)) == 0) {
            /* could not bind the rtcp socket to required port. so we delete it */
            close (*rtcpsocket);
            *rtcpsocket= -1;
        }
        if (!rtpstream_setsocketoptions (*rtcpsocket)) {
            close (*rtcpsocket);
            *rtcpsocket= -1;
        }
    }

    return port_number;
}

/* code checked */
int rtpstream_get_local_audioport (rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_get_local_audioport callinfo=%p",callinfo);

    int   rtp_socket;
    int   rtcp_socket;

    if (!callinfo->taskinfo) {
        return 0;
    }

    if (callinfo->local_audioport) {
        /* already a port assigned to this call */
        debugprint (" ==> %d\n",callinfo->local_audioport);
        return callinfo->local_audioport;
    }

    callinfo->local_audioport= rtpstream_get_localport (&rtp_socket,&rtcp_socket);

    debugprint (" ==> %d\n",callinfo->local_audioport);

    /* assign rtp and rtcp sockets to callinfo. must assign rtcp socket first */
    callinfo->taskinfo->audio_rtcp_socket= rtcp_socket;
    callinfo->taskinfo->audio_rtp_socket= rtp_socket;

    /* start playback task if not already started */
    if (!callinfo->taskinfo->parent_thread) {
        if (!rtpstream_start_task (callinfo)) {
            /* error starting playback task */
            return 0;
        }
    }

    /* make sure the new socket gets bound to destination address (if any) */
    callinfo->taskinfo->flags|= TI_RECONNECTSOCKET;

    return callinfo->local_audioport;
}

/* code checked */
int rtpstream_get_local_videoport (rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_get_local_videoport callinfo=%p",callinfo);

    int   rtp_socket;
    int   rtcp_socket;

    if (!callinfo->taskinfo) {
        return 0;
    }

    if (callinfo->local_videoport) {
        /* already a port assigned to this call */
        debugprint (" ==> %d\n",callinfo->local_videoport);
        return callinfo->local_videoport;
    }

    callinfo->local_videoport= rtpstream_get_localport (&rtp_socket,&rtcp_socket);

    debugprint (" ==> %d\n",callinfo->local_videoport);

    /* assign rtp and rtcp sockets to callinfo. must assign rtcp socket first */
    callinfo->taskinfo->video_rtcp_socket= rtcp_socket;
    callinfo->taskinfo->video_rtp_socket= rtp_socket;

    /* start playback task if not already started */
    if (!callinfo->taskinfo->parent_thread) {
        if (!rtpstream_start_task (callinfo)) {
            /* error starting playback task */
            return 0;
        }
    }

    /* make sure the new socket gets bound to destination address (if any) */
    callinfo->taskinfo->flags|= TI_RECONNECTSOCKET;

    return callinfo->local_videoport;
}

/* code checked */
void rtpstream_set_remote(rtpstream_callinfo_t* callinfo, int ip_ver, const char* ip_addr,
                          int audio_port, int video_port)
{
    struct sockaddr_storage   address;
    struct in_addr            *ip4_addr;
    struct in6_addr           *ip6_addr;
    taskentry_t               *taskinfo;
    unsigned                  count;
    int                       nonzero_ip;

    debugprint("rtpstream_set_remote callinfo=%p, ip_ver %d ip_addr %s audio %d video %d\n",
               callinfo, ip_ver, ip_addr, audio_port, video_port);

    taskinfo= callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return;
    }

    nonzero_ip= 0;
    taskinfo->flags|= TI_NULLIP;   /// TODO: this (may) cause a gap in playback, if playback thread gets to exec while this is set and before new IP is checked.

    /* test that media ip address version match remote ip address version? */

    /* initialise address family and IP address for remote socket */
    memset(&address,0,sizeof(address));
    if (media_ip_is_ipv6) {
        /* process ipv6 address */
        address.ss_family= AF_INET6;
        ip6_addr= &((_RCAST(struct sockaddr_in6 *,&address))->sin6_addr);
        if (inet_pton(AF_INET6,ip_addr,ip6_addr)==1) {
            for (count=0;count<sizeof(*ip6_addr);count++) {
                if (((char*)ip6_addr)[count]) {
                    nonzero_ip= 1;
                    break;
                }
            }
        }
    } else {
        /* process ipv4 address */
        address.ss_family= AF_INET;
        ip4_addr= &((_RCAST(struct sockaddr_in *,&address))->sin_addr);
        if (inet_pton(AF_INET,ip_addr,ip4_addr)==1) {
            for (count=0;count<sizeof(*ip4_addr);count++) {
                if (((char*)ip4_addr)[count]) {
                    nonzero_ip= 1;
                    break;
                }
            }
        }
    }

    if (!nonzero_ip) {
        return;
    }

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock (&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset (&(taskinfo->remote_audio_rtp_addr),0,sizeof(taskinfo->remote_audio_rtp_addr));
    memset (&(taskinfo->remote_audio_rtcp_addr),0,sizeof(taskinfo->remote_audio_rtcp_addr));
    memset (&(taskinfo->remote_video_rtp_addr),0,sizeof(taskinfo->remote_video_rtp_addr));
    memset (&(taskinfo->remote_video_rtcp_addr),0,sizeof(taskinfo->remote_video_rtcp_addr));

    /* Audio */
    if (audio_port) {
        // store remote audio port for later reference
        callinfo->remote_audioport = audio_port;
        sockaddr_update_port(&address, audio_port);
        memcpy (&(taskinfo->remote_audio_rtp_addr),&address,sizeof(address));

        sockaddr_update_port(&address, audio_port + 1);
        memcpy (&(taskinfo->remote_audio_rtcp_addr),&address,sizeof(address));

        taskinfo->flags&= ~TI_NULL_AUDIOIP;
    }

    /* Video */
    if (video_port) {
        // store remote video port for later reference
        callinfo->remote_videoport = video_port;
        sockaddr_update_port(&address, video_port);
        memcpy (&(taskinfo->remote_video_rtp_addr),&address,sizeof(address));

        sockaddr_update_port(&address, video_port + 1);
        memcpy (&(taskinfo->remote_video_rtcp_addr),&address,sizeof(address));

        taskinfo->flags&= ~TI_NULL_VIDEOIP;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock (&(taskinfo->mutex));

    taskinfo->flags|= TI_RECONNECTSOCKET;

    /* may want to start a playback (listen) task here if no task running? */
    /* only makes sense if we decide to send 0-filled packets on idle */
}

int rtpstream_set_srtp_audio_local(rtpstream_callinfo_t *callinfo, SrtpAudioInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo= callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug)
    {
        if (debuglsrtpafile == NULL)
        {
            if (sendMode == MODE_CLIENT)
            {
                debuglsrtpafile = fopen("debuglsrtpafile_uac", "w");
            }
            else if (sendMode == MODE_SERVER)
            {
                debuglsrtpafile = fopen("debuglsrtpafile_uas", "w");
            }
            if (debuglsrtpafile == NULL)
            {
                /* error encountered opening local srtp debug file */
                return -1;
            }
        }
    }

    printLocalAudioSrtpStuff(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock (&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset (&(taskinfo->local_srtp_audio_params),0,sizeof(taskinfo->local_srtp_audio_params));

    /* Audio */
    if (p.audio_found) {
        taskinfo->local_srtp_audio_params.audio_found = true;
        taskinfo->local_srtp_audio_params.primary_audio_cryptotag = p.primary_audio_cryptotag;
        taskinfo->local_srtp_audio_params.secondary_audio_cryptotag = p.secondary_audio_cryptotag;
        strncpy(taskinfo->local_srtp_audio_params.primary_audio_cryptosuite, p.primary_audio_cryptosuite, 23);
        strncpy(taskinfo->local_srtp_audio_params.secondary_audio_cryptosuite, p.secondary_audio_cryptosuite, 23);
        strncpy(taskinfo->local_srtp_audio_params.primary_audio_cryptokeyparams, p.primary_audio_cryptokeyparams, 40);
        strncpy(taskinfo->local_srtp_audio_params.secondary_audio_cryptokeyparams, p.secondary_audio_cryptokeyparams, 40);
        taskinfo->local_srtp_audio_params.primary_unencrypted_audio_srtp = p.primary_unencrypted_audio_srtp;
        taskinfo->local_srtp_audio_params.secondary_unencrypted_audio_srtp = p.secondary_unencrypted_audio_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock (&(taskinfo->mutex));

    if (srtpcheck_debug)
    {
        if (debuglsrtpafile)
        {
            fclose(debuglsrtpafile);
            debuglsrtpafile = NULL;
        }
    }

    return 0;
}

int rtpstream_set_srtp_audio_remote(rtpstream_callinfo_t *callinfo, SrtpAudioInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo= callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug)
    {
        if (debugrsrtpafile == NULL)
        {
            if (sendMode == MODE_CLIENT)
            {
                debugrsrtpafile = fopen("debugrsrtpafile_uac", "w");
            }
            else if (sendMode == MODE_SERVER)
            {
                debugrsrtpafile = fopen("debugrsrtpafile_uas", "w");
            }
            if (debugrsrtpafile == NULL)
            {
                /* error encountered opening local srtp debug file */
                return -1;
            }
        }
    }

    printRemoteAudioSrtpStuff(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock (&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset (&(taskinfo->remote_srtp_audio_params),0,sizeof(taskinfo->remote_srtp_audio_params));

    /* Audio */
    if (p.audio_found) {
        taskinfo->remote_srtp_audio_params.audio_found = true;
        taskinfo->remote_srtp_audio_params.primary_audio_cryptotag = p.primary_audio_cryptotag;
        taskinfo->remote_srtp_audio_params.secondary_audio_cryptotag = p.secondary_audio_cryptotag;
        strncpy(taskinfo->remote_srtp_audio_params.primary_audio_cryptosuite, p.primary_audio_cryptosuite, 23);
        strncpy(taskinfo->remote_srtp_audio_params.secondary_audio_cryptosuite, p.secondary_audio_cryptosuite, 23);
        strncpy(taskinfo->remote_srtp_audio_params.primary_audio_cryptokeyparams, p.primary_audio_cryptokeyparams, 40);
        strncpy(taskinfo->remote_srtp_audio_params.secondary_audio_cryptokeyparams, p.secondary_audio_cryptokeyparams, 40);
        taskinfo->remote_srtp_audio_params.primary_unencrypted_audio_srtp = p.primary_unencrypted_audio_srtp;
        taskinfo->remote_srtp_audio_params.secondary_unencrypted_audio_srtp = p.secondary_unencrypted_audio_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock (&(taskinfo->mutex));

    if (srtpcheck_debug)
    {
        if (debugrsrtpafile)
        {
            fclose(debugrsrtpafile);
            debugrsrtpafile = NULL;
        }
    }

    return 0;
}

int rtpstream_set_srtp_video_local(rtpstream_callinfo_t *callinfo, SrtpVideoInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo= callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug)
    {
        if (debuglsrtpvfile == NULL)
        {
            if (sendMode == MODE_CLIENT)
            {
                debuglsrtpvfile = fopen("debuglsrtpvfile_uac", "w");
            }
            else if (sendMode == MODE_SERVER)
            {
                debuglsrtpvfile = fopen("debuglsrtpvfile_uas", "w");
            }
            if (debuglsrtpvfile == NULL)
            {
                /* error encountered opening local srtp debug file */
                return -1;
            }
        }
    }

    printLocalVideoSrtpStuff(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock (&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset (&(taskinfo->local_srtp_video_params),0,sizeof(taskinfo->local_srtp_video_params));

    /* Video */
    if (p.video_found) {
        taskinfo->local_srtp_video_params.video_found = true;
        taskinfo->local_srtp_video_params.primary_video_cryptotag = p.primary_video_cryptotag;
        taskinfo->local_srtp_video_params.secondary_video_cryptotag = p.secondary_video_cryptotag;
        strncpy(taskinfo->local_srtp_video_params.primary_video_cryptosuite, p.primary_video_cryptosuite, 23);
        strncpy(taskinfo->local_srtp_video_params.secondary_video_cryptosuite, p.secondary_video_cryptosuite, 23);
        strncpy(taskinfo->local_srtp_video_params.primary_video_cryptokeyparams, p.primary_video_cryptokeyparams, 40);
        strncpy(taskinfo->local_srtp_video_params.secondary_video_cryptokeyparams, p.secondary_video_cryptokeyparams, 40);
        taskinfo->local_srtp_video_params.primary_unencrypted_video_srtp = p.primary_unencrypted_video_srtp;
        taskinfo->local_srtp_video_params.secondary_unencrypted_video_srtp = p.secondary_unencrypted_video_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock (&(taskinfo->mutex));

    if (srtpcheck_debug)
    {
        if (debuglsrtpvfile)
        {
            fclose(debuglsrtpvfile);
            debuglsrtpvfile = NULL;
        }
    }

    return 0;
}

int rtpstream_set_srtp_video_remote(rtpstream_callinfo_t *callinfo, SrtpVideoInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo= callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug)
    {
        if (debugrsrtpvfile == NULL)
        {
            if (sendMode == MODE_CLIENT)
            {
                debugrsrtpvfile = fopen("debugrsrtpvfile_uac", "w");
            }
            else if (sendMode == MODE_SERVER)
            {
                debugrsrtpvfile = fopen("debugrsrtpvfile_uas", "w");
            }
            if (debugrsrtpvfile == NULL)
            {
                /* error encountered opening local srtp debug file */
                return -1;
            }
        }
    }

    printRemoteVideoSrtpStuff(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock (&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset (&(taskinfo->remote_srtp_video_params),0,sizeof(taskinfo->remote_srtp_video_params));

    /* Video */
    if (p.video_found) {
        taskinfo->remote_srtp_video_params.video_found = true;
        taskinfo->remote_srtp_video_params.primary_video_cryptotag = p.primary_video_cryptotag;
        taskinfo->remote_srtp_video_params.secondary_video_cryptotag = p.secondary_video_cryptotag;
        strncpy(taskinfo->remote_srtp_video_params.primary_video_cryptosuite, p.primary_video_cryptosuite, 23);
        strncpy(taskinfo->remote_srtp_video_params.secondary_video_cryptosuite, p.secondary_video_cryptosuite, 23);
        strncpy(taskinfo->remote_srtp_video_params.primary_video_cryptokeyparams, p.primary_video_cryptokeyparams, 40);
        strncpy(taskinfo->remote_srtp_video_params.secondary_video_cryptokeyparams, p.secondary_video_cryptokeyparams, 40);
        taskinfo->remote_srtp_video_params.primary_unencrypted_video_srtp = p.primary_unencrypted_video_srtp;
        taskinfo->remote_srtp_video_params.secondary_unencrypted_video_srtp = p.secondary_unencrypted_video_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock (&(taskinfo->mutex));

    if (srtpcheck_debug)
    {
        if (debugrsrtpvfile)
        {
            fclose(debugrsrtpvfile);
            debugrsrtpvfile = NULL;
        }
    }

    return 0;
}

/* code checked */
void rtpstream_play (rtpstream_callinfo_t *callinfo, rtpstream_actinfo_t *actioninfo)
{
    debugprint ("rtpstream_play callinfo=%p filename %s pattern_id %d loop %d bytes %d payload %d ptime %d tick %d\n",
        callinfo,
        actioninfo->filename,
        actioninfo->pattern_id,
        actioninfo->loop_count,
        actioninfo->bytes_per_packet,
        actioninfo->payload_type,
        actioninfo->ms_per_packet,
        actioninfo->ticks_per_packet);

    int           file_index= rtpstream_cache_file (actioninfo->filename,
                                                    0 /* FILE MODE */,
                                                    actioninfo->pattern_id,
                                                    actioninfo->bytes_per_packet,
                                                    0 /* AUDIO */);
    taskentry_t   *taskinfo= callinfo->taskinfo;

    if (file_index<0) {
        return; /* cannot find file to play */
    }

    if (!taskinfo) {
        return; /* no task data structure */
    }

    /* make sure we have an open socket from which to play the audio file */
    rtpstream_get_local_audioport (callinfo);

    /* save file parameter in taskinfo structure */
    taskinfo->new_audio_pattern_id= actioninfo->pattern_id;
    taskinfo->new_audio_loop_count= actioninfo->loop_count;
    taskinfo->new_audio_bytes_per_packet= actioninfo->bytes_per_packet;
    taskinfo->new_audio_file_size= cached_files[file_index].filesize;
    taskinfo->new_audio_file_bytes= cached_files[file_index].bytes;
    taskinfo->new_audio_ms_per_packet= actioninfo->ms_per_packet;
    taskinfo->new_audio_timeticks_per_packet= actioninfo->ticks_per_packet;
    taskinfo->new_audio_payload_type= actioninfo->payload_type;
    taskinfo->audio_active = actioninfo->audio_active;
    taskinfo->video_active = actioninfo->video_active;

    /* set flag that we have a new file to play */
    taskinfo->flags|= TI_PLAYFILE;
}

/* code checked */
void rtpstream_pause (rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_pause callinfo=%p\n",callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags|= TI_PAUSERTP;
    }
}

/* code checked */
void rtpstream_resume (rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_resume callinfo=%p\n",callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags&= ~TI_PAUSERTP;
    }
}

void rtpstream_playapattern(rtpstream_callinfo_t *callinfo, rtpstream_actinfo_t *actioninfo, JLSRTP& txUACAudio, JLSRTP& rxUACAudio)
{
    debugprint ("rtpstream_playapattern callinfo=%p filename %s pattern_id %d loop %d bytes %d payload %d ptime %d tick %d\n",
            callinfo,
            actioninfo->filename,
            actioninfo->pattern_id,
            actioninfo->loop_count,
            actioninfo->bytes_per_packet,
            actioninfo->payload_type,
            actioninfo->ms_per_packet,
            actioninfo->ticks_per_packet);

    int           file_index= rtpstream_cache_file (actioninfo->filename,
                                                    1 /* PATTERN MODE */,
                                                    actioninfo->pattern_id,
                                                    actioninfo->bytes_per_packet,
                                                    0 /* AUDIO */);
    taskentry_t   *taskinfo= callinfo->taskinfo;

    if (file_index<0)
    {
        return; /* ERROR encountered */
    }

    if (!taskinfo)
    {
        return; /* no task data structure */
    }

    /* make sure we have an open socket from which to play the audio file */
    rtpstream_get_local_audioport (callinfo);

    /* save file parameter in taskinfo structure */
    taskinfo->new_audio_pattern_id = actioninfo->pattern_id;
    taskinfo->new_audio_payload_type= actioninfo->payload_type;
    taskinfo->new_audio_loop_count= actioninfo->loop_count;

    taskinfo->new_audio_file_size= cached_patterns[file_index].filesize;
    taskinfo->new_audio_file_bytes= cached_patterns[file_index].bytes;

    taskinfo->new_audio_ms_per_packet= actioninfo->ms_per_packet;
    taskinfo->new_audio_bytes_per_packet= actioninfo->bytes_per_packet;
    taskinfo->new_audio_timeticks_per_packet= actioninfo->ticks_per_packet;
    taskinfo->audio_comparison_errors = 0;
    taskinfo->audio_active = actioninfo->audio_active;
    taskinfo->video_active = actioninfo->video_active;

    /* set flag that we have a new file to play */
    taskinfo->flags|= TI_PLAYAPATTERN;

    pthread_mutex_lock(&uacAudioMutex);
    g_txUACAudio = txUACAudio;
    g_rxUACAudio = rxUACAudio;
    pthread_mutex_unlock(&uacAudioMutex);
}

void rtpstream_pauseapattern(rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_pauseapattern callinfo=%p\n",callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags|= TI_PAUSERTPAPATTERN;
    }
}

void rtpstream_resumeapattern(rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_resumeapattern callinfo=%p\n",callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags&= ~TI_PAUSERTPAPATTERN;
    }
}

void rtpstream_playvpattern(rtpstream_callinfo_t *callinfo, rtpstream_actinfo_t *actioninfo, JLSRTP& txUACVideo, JLSRTP& rxUACVideo)
{
    debugprint ("rtpstream_playvpattern callinfo=%p filename %s pattern_id %d loop %d bytes %d payload %d ptime %d tick %d\n",
            callinfo,
            actioninfo->filename,
            actioninfo->pattern_id,
            actioninfo->loop_count,
            actioninfo->bytes_per_packet,
            actioninfo->payload_type,
            actioninfo->ms_per_packet,
            actioninfo->ticks_per_packet);

    int           file_index= rtpstream_cache_file (actioninfo->filename,
                                                    1 /* PATTERN MODE */,
                                                    actioninfo->pattern_id,
                                                    actioninfo->bytes_per_packet,
                                                    1 /* VIDEO */);
    taskentry_t   *taskinfo= callinfo->taskinfo;

    if (file_index<0)
    {
        return; /* ERROR encountered */
    }

    if (!taskinfo)
    {
        return; /* no task data structure */
    }

    /* make sure we have an open socket from which to play the video file */
    rtpstream_get_local_videoport (callinfo);

    /* save file parameter in taskinfo structure */
    taskinfo->new_video_pattern_id = actioninfo->pattern_id;
    taskinfo->new_video_payload_type= actioninfo->payload_type;
    taskinfo->new_video_loop_count= actioninfo->loop_count;

    taskinfo->new_video_file_size= cached_patterns[file_index].filesize;
    taskinfo->new_video_file_bytes= cached_patterns[file_index].bytes;

    taskinfo->new_video_ms_per_packet= actioninfo->ms_per_packet;
    taskinfo->new_video_bytes_per_packet= actioninfo->bytes_per_packet;
    taskinfo->new_video_timeticks_per_packet= actioninfo->ticks_per_packet;
    taskinfo->video_comparison_errors = 0;
    taskinfo->audio_active = actioninfo->audio_active;
    taskinfo->video_active = actioninfo->video_active;

    /* set flag that we have a new file to play */
    taskinfo->flags|= TI_PLAYVPATTERN;

    pthread_mutex_lock(&uacVideoMutex);
    g_txUACVideo = txUACVideo;
    g_rxUACVideo = rxUACVideo;
    pthread_mutex_unlock(&uacVideoMutex);
}

void rtpstream_pausevpattern(rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_pausevpattern callinfo=%p\n",callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags|= TI_PAUSERTPVPATTERN;
    }
}

void rtpstream_resumevpattern(rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_resumevpattern callinfo=%p\n",callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags&= ~TI_PAUSERTPVPATTERN;
    }
}

void rtpstream_audioecho_thread (void * param)
{
    char* msg = (char*)alloca(media_bufsize);
    ssize_t nr;
    ssize_t ns;
    sipp_socklen_t len;
    struct sockaddr_storage remote_rtp_addr;
    sigset_t mask;
    int rc = 0;
    int exit_code = 0;
    struct timespec tspec;
    int sock = 0;
    int flags;
    std::vector<unsigned char> rtp_header;
    std::vector<unsigned char> payload_data;
    std::vector<unsigned char> audio_packet_in;
    std::vector<unsigned char> audio_packet_out;
    unsigned short audio_seq = 0;
    unsigned short seq_num = 0;
    unsigned short host_flags = 0;
    unsigned short host_seqnum = 0;
    unsigned int host_timestamp = 0;
    unsigned int host_ssrc = 0;
    bool abnormal_termination = false;

    tspec.tv_sec = 0;
    tspec.tv_nsec = 10000000; /* 10ms */
    if (param != NULL)
    {
        sock = *(int*)param;
    }

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0)
    {
        pthread_mutex_lock(&debugremutexaudio);
        if (debugrefileaudio != NULL)
        {
            fprintf(debugrefileaudio, "rtp_audioecho_thread():  fcntl() GETFL UNBLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexaudio);
        pthread_exit((void*) 1);
    }

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        pthread_mutex_lock(&debugremutexaudio);
        if (debugrefileaudio != NULL)
        {
            fprintf(debugrefileaudio, "rtp_audioecho_thread():  fcntl() SETFL UNBLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexaudio);
        pthread_exit((void*) 2);
    }

    sigfillset(&mask); /* Mask all allowed signals */
    rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (rc) {
        //WARNING("pthread_sigmask returned %d in rtpstream_echo_thread", rc);
        pthread_mutex_lock(&debugremutexaudio);
        if (debugrefileaudio != NULL)
        {
            fprintf(debugrefileaudio, "pthread_sigmask returned %d in rtpstream_audioecho_thread", rc);
        }
        pthread_mutex_unlock(&debugremutexaudio);
        pthread_exit((void*) 3);
    }

    pthread_mutex_lock(&quit_mutexaudio);
    while (!quit_audioecho_thread)
    {
        rc = pthread_cond_timedwait(&quit_cvaudio, &quit_mutexaudio, &tspec);
        if ((rc == ETIMEDOUT) &&
            !quit_audioecho_thread)
        {
            pthread_mutex_lock(&uasAudioMutex);
            nr = 0;
            memset(msg, 0, media_bufsize);
            len = sizeof(remote_rtp_addr);
            audio_packet_in.resize(sizeof(rtp_header_t)+g_rxUASAudio.getSrtpPayloadSize()+g_rxUASAudio.getAuthenticationTagSize(), 0);
            nr = recvfrom(sock, audio_packet_in.data(), audio_packet_in.size(), MSG_DONTWAIT /* NON-BLOCKING */, (sockaddr *)(void *) &remote_rtp_addr, &len);

            if (nr >= 0) {
                // Good to go -- buffer should contain "nr" bytes
                seq_num = 0;
                seq_num = (audio_packet_in[2] << 8) | audio_packet_in[3];

                pthread_mutex_lock(&debugremutexaudio);
                if (debugrefileaudio != NULL)
                {
                    fprintf(debugrefileaudio, "DATA SUCCESSFULLY RECEIVED [AUDIO] nr=%zd...", nr);
                }
                for (int i = 0; i < 12; i++)
                {
                    if (debugrefileaudio != NULL)
                    {
                        fprintf(debugrefileaudio, "%02X", 0xFFFFFFFF & audio_packet_in[i]);
                    }
                }
                if (debugrefileaudio != NULL)
                {
                    fprintf(debugrefileaudio, "\n");
                }
                pthread_mutex_unlock(&debugremutexaudio);

                if (g_rxUASAudio.getCryptoTag() != 0)
                {
                    rtp_header.clear();
                    payload_data.clear();

                    // DECRYPT
                    rc = g_rxUASAudio.processIncomingPacket(audio_seq, audio_packet_in, rtp_header, payload_data);
                    pthread_mutex_lock(&debugremutexaudio);
                    if (debugrefileaudio != NULL)
                    {
                        fprintf(debugrefileaudio, "RXUASAUDIO -- processIncomingPacket() rc==%d\n", rc);
                    }
                    pthread_mutex_unlock(&debugremutexaudio);

                    host_flags = ntohs(((rtp_header_t*)audio_packet_in.data())->flags);
                    host_seqnum = ntohs(((rtp_header_t*)audio_packet_in.data())->seq);
                    host_timestamp = ntohl(((rtp_header_t*)audio_packet_in.data())->timestamp);
                    host_ssrc = ntohl(((rtp_header_t*)audio_packet_in.data())->ssrc_id);

                    audio_packet_in[0] = (host_flags >> 8) & 0xFF;
                    audio_packet_in[1] = host_flags & 0xFF;
                    audio_packet_in[2] = (host_seqnum >> 8) & 0xFF;
                    audio_packet_in[3] = host_seqnum & 0xFF;
                    audio_packet_in[4] = (host_timestamp >> 24) & 0xFF;
                    audio_packet_in[5] = (host_timestamp >> 16) & 0xFF;
                    audio_packet_in[6] = (host_timestamp >> 8) & 0xFF;
                    audio_packet_in[7] = host_timestamp & 0xFF;
                    audio_packet_in[8] = (host_ssrc >> 24) & 0xFF;
                    audio_packet_in[9] = (host_ssrc >> 16) & 0xFF;
                    audio_packet_in[10]= (host_ssrc >> 8) & 0xFF;
                    audio_packet_in[11]= host_ssrc & 0xFF;

                    memset(msg, 0, media_bufsize);
                    memcpy(msg, rtp_header.data(), rtp_header.size());
                    memcpy(msg+sizeof(rtp_header_t), payload_data.data(), payload_data.size());
                }

                if (g_txUASAudio.getCryptoTag() != 0)
                {
                    audio_packet_out.clear();

                    // GRAB RTP HEADER
                    rtp_header.resize(sizeof(rtp_header_t), 0);
                    memcpy(rtp_header.data(), msg, sizeof(rtp_header_t) /*12*/);
                    // GRAB RTP PAYLOAD DATA
                    payload_data.resize(g_txUASAudio.getSrtpPayloadSize(), 0);
                    memcpy(payload_data.data(), msg+sizeof(rtp_header_t), g_txUASAudio.getSrtpPayloadSize());

                    // ENCRYPT
                    rc = g_txUASAudio.processOutgoingPacket(audio_seq, rtp_header, payload_data, audio_packet_out);
                    pthread_mutex_lock(&debugremutexaudio);
                    if (debugrefileaudio != NULL)
                    {
                        fprintf(debugrefileaudio, "TXUASAUDIO -- processOutgoingPacket() rc==%d\n", rc);
                    }
                    pthread_mutex_unlock(&debugremutexaudio);
                }

                ns = sendto(sock, audio_packet_out.data(), sizeof(rtp_header_t)+g_txUASAudio.getSrtpPayloadSize()+g_txUASAudio.getAuthenticationTagSize(), MSG_DONTWAIT, (sockaddr *)(void *) &remote_rtp_addr, len);

                if (ns != nr) {
                    pthread_mutex_lock(&debugremutexaudio);
                    if (debugrefileaudio != NULL)
                    {
                        fprintf(debugrefileaudio, "DATA SUCCESSFULLY SENT [AUDIO] seq_num=[%u] -- MISMATCHED RECV/SENT BYTE COUNT -- errno=%d nr=%zd ns=%zd\n", seq_num, errno, nr, ns);
                    }
                    pthread_mutex_unlock(&debugremutexaudio);
                } else {
                    pthread_mutex_lock(&debugremutexaudio);
                    if (debugrefileaudio != NULL)
                    {
                        fprintf(debugrefileaudio, "DATA SUCCESSFULLY SENT [AUDIO] seq_num=[%u]...\n", seq_num);
                    }
                    pthread_mutex_unlock(&debugremutexaudio);
                }

                rtp_pckts++;
                rtp_bytes += ns;
                audio_seq++;
            }
            else if ((nr < 0) &&
                     (errno == EAGAIN)) {
                // No data to be read (no activity on socket)
                //pthread_mutex_lock(&debugremutexaudio);
                //if (debugrefileaudio != NULL)
                //{
                //    fprintf(debugrefileaudio, "No activity on audioecho socket (EAGAIN)...\n");
                //}
                //pthread_mutex_unlock(&debugremutexaudio);
            }
            else {
                // Other error occurred during read
                //WARNING("%s %i", "Error on RTP echo reception - stopping rtpstream echo - errno=", errno);
                pthread_mutex_lock(&debugremutexaudio);
                if (debugrefileaudio != NULL)
                {
                    fprintf(debugrefileaudio, "Error on RTP echo reception - unable to perform rtpstream audioecho - errno=%d\n", errno);
                }
                pthread_mutex_unlock(&debugremutexaudio);
                abnormal_termination = true;
            }
            pthread_mutex_unlock(&uasAudioMutex);
        }
        else
        {
            pthread_mutex_lock(&debugremutexaudio);
            if (debugrefileaudio != NULL)
            {
                fprintf(debugrefileaudio, "rtp_audioecho_thread():  pthread_cond_timedwait() non-timeout:  rc: %d quit_audioecho_thread: %d\n", rc, quit_audioecho_thread);
            }
            pthread_mutex_unlock(&debugremutexaudio);
        }
    }
    pthread_mutex_unlock(&quit_mutexaudio);

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0)
    {
        pthread_mutex_lock(&debugremutexaudio);
        if (debugrefileaudio != NULL)
        {
            fprintf(debugrefileaudio, "rtp_audioecho_thread():  fcntl() GETFL BLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexaudio);
        pthread_exit((void*) 6);
    }

    if (fcntl(sock, F_SETFL, flags & (~O_NONBLOCK)) < 0)
    {
        pthread_mutex_lock(&debugremutexaudio);
        if (debugrefileaudio != NULL)
        {
            fprintf(debugrefileaudio, "rtp_audioecho_thread():  fcntl() SETFL BLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexaudio);
        pthread_exit((void*) 7);
    }

    if (abnormal_termination)
    {
        exit_code = -1;
    }
    else
    {
        exit_code = 0;
    }

    pthread_exit(reinterpret_cast<void*>(exit_code));
}

void rtpstream_videoecho_thread (void * param)
{
    char* msg = (char*)alloca(media_bufsize);
    ssize_t nr;
    ssize_t ns;
    sipp_socklen_t len;
    struct sockaddr_storage remote_rtp_addr;
    sigset_t mask;
    int rc = 0;
    int exit_code = 0;
    struct timespec tspec;
    int sock = 0;
    int flags;
    std::vector<unsigned char> rtp_header;
    std::vector<unsigned char> payload_data;
    std::vector<unsigned char> video_packet_in;
    std::vector<unsigned char> video_packet_out;
    unsigned short video_seq = 0;
    unsigned short seq_num = 0;
    unsigned short host_flags = 0;
    unsigned short host_seqnum = 0;
    unsigned int host_timestamp = 0;
    unsigned int host_ssrc = 0;
    bool abnormal_termination = false;

    tspec.tv_sec = 0;
    tspec.tv_nsec = 10000000; /* 10ms */
    if (param != NULL)
    {
        sock = *(int*)param;
    }

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0)
    {
        pthread_mutex_lock(&debugremutexvideo);
        if (debugrefilevideo != NULL)
        {
            fprintf(debugrefilevideo, "rtp_videoecho_thread():  fcntl() GETFL UNBLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexvideo);
        pthread_exit((void*) 1);
    }

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        pthread_mutex_lock(&debugremutexvideo);
        if (debugrefilevideo != NULL)
        {
            fprintf(debugrefilevideo, "rtp_videoecho_thread():  fcntl() SETFL UNBLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexvideo);
        pthread_exit((void*) 2);
    }

    sigfillset(&mask); /* Mask all allowed signals */
    rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (rc) {
        //WARNING("pthread_sigmask returned %d in rtpstream_echo_thread", rc);
        pthread_mutex_lock(&debugremutexvideo);
        if (debugrefilevideo != NULL)
        {
            fprintf(debugrefilevideo, "pthread_sigmask returned %d in rtpstream_videoecho_thread", rc);
        }
        pthread_mutex_unlock(&debugremutexvideo);
        pthread_exit((void*) 3);
    }

    pthread_mutex_lock(&quit_mutexvideo);
    while (!quit_videoecho_thread)
    {
        rc = pthread_cond_timedwait(&quit_cvvideo, &quit_mutexvideo, &tspec);
        if ((rc == ETIMEDOUT) &&
            !quit_videoecho_thread)
        {
            pthread_mutex_lock(&uasVideoMutex);
            nr = 0;
            memset(msg, 0, media_bufsize);
            len = sizeof(remote_rtp_addr);
            video_packet_in.resize(sizeof(rtp_header_t)+g_rxUASVideo.getSrtpPayloadSize()+g_rxUASVideo.getAuthenticationTagSize(), 0);
            nr = recvfrom(sock, video_packet_in.data(), video_packet_in.size(), MSG_DONTWAIT /* NON-BLOCKING */, (sockaddr *)(void *) &remote_rtp_addr, &len);

            if (nr >= 0) {
                // Good to go -- buffer should contain "nr" bytes
                seq_num = 0;
                seq_num = (video_packet_in[2] << 8) | video_packet_in[3];

                pthread_mutex_lock(&debugremutexvideo);
                if (debugrefilevideo != NULL)
                {
                    fprintf(debugrefilevideo, "DATA SUCCESSFULLY RECEIVED [VIDEO] nr=%zd...", nr);
                }
                for (int i = 0; i < 12; i++)
                {
                    if (debugrefilevideo != NULL)
                    {
                        fprintf(debugrefilevideo, "%02X", 0xFFFFFFFF & video_packet_in[i]);
                    }
                }
                if (debugrefilevideo != NULL)
                {
                    fprintf(debugrefilevideo, "\n");
                }
                pthread_mutex_unlock(&debugremutexvideo);

                if (g_rxUASVideo.getCryptoTag() != 0)
                {
                    rtp_header.clear();
                    payload_data.clear();
                    // DECRYPT
                    rc = g_rxUASVideo.processIncomingPacket(video_seq, video_packet_in, rtp_header, payload_data);
                    pthread_mutex_lock(&debugremutexvideo);
                    if (debugrefilevideo != NULL)
                    {
                        fprintf(debugrefilevideo, "RXUASVIDEO -- processIncomingPacket() rc==%d\n", rc);
                    }
                    pthread_mutex_unlock(&debugremutexvideo);

                    host_flags = ntohs(((rtp_header_t*)video_packet_in.data())->flags);
                    host_seqnum = ntohs(((rtp_header_t*)video_packet_in.data())->seq);
                    host_timestamp = ntohl(((rtp_header_t*)video_packet_in.data())->timestamp);
                    host_ssrc = ntohl(((rtp_header_t*)video_packet_in.data())->ssrc_id);

                    video_packet_in[0] = (host_flags >> 8) & 0xFF;
                    video_packet_in[1] = host_flags & 0xFF;
                    video_packet_in[2] = (host_seqnum >> 8) & 0xFF;
                    video_packet_in[3] = host_seqnum & 0xFF;
                    video_packet_in[4] = (host_timestamp >> 24) & 0xFF;
                    video_packet_in[5] = (host_timestamp >> 16) & 0xFF;
                    video_packet_in[6] = (host_timestamp >> 8) & 0xFF;
                    video_packet_in[7] = host_timestamp & 0xFF;
                    video_packet_in[8] = (host_ssrc >> 24) & 0xFF;
                    video_packet_in[9] = (host_ssrc >> 16) & 0xFF;
                    video_packet_in[10]= (host_ssrc >> 8) & 0xFF;
                    video_packet_in[11]= host_ssrc & 0xFF;

                    memset(msg, 0, media_bufsize);
                    memcpy(msg, rtp_header.data(), rtp_header.size());
                    memcpy(msg+sizeof(rtp_header_t), payload_data.data(), payload_data.size());
                }

                if (g_txUASVideo.getCryptoTag() != 0)
                {
                    video_packet_out.clear();
                    // ENCRYPT
                    // GRAB RTP HEADER
                    rtp_header.resize(sizeof(rtp_header_t), 0);
                    memcpy(rtp_header.data(), msg, sizeof(rtp_header_t) /*12*/);
                    // GRAB RTP PAYLOAD DATA
                    payload_data.resize(g_txUASVideo.getSrtpPayloadSize(), 0);
                    memcpy(payload_data.data(), msg+sizeof(rtp_header_t), g_txUASVideo.getSrtpPayloadSize());

                    // ENCRYPT
                    rc = g_txUASVideo.processOutgoingPacket(video_seq, rtp_header, payload_data, video_packet_out);
                    pthread_mutex_lock(&debugremutexvideo);
                    if (debugrefilevideo != NULL)
                    {
                        fprintf(debugrefilevideo, "TXUASVIDEO -- processOutgoingPacket() rc==%d\n", rc);
                    }
                    pthread_mutex_unlock(&debugremutexvideo);
                }

                ns = sendto(sock, video_packet_out.data(), sizeof(rtp_header_t)+g_txUASVideo.getSrtpPayloadSize()+g_txUASVideo.getAuthenticationTagSize(), MSG_DONTWAIT, (sockaddr *)(void *) &remote_rtp_addr, len);

                if (ns != nr) {
                    pthread_mutex_lock(&debugremutexvideo);
                    if (debugrefilevideo != NULL)
                    {
                        fprintf(debugrefilevideo, "DATA SUCCESSFULLY SENT [VIDEO] seq_num=[%u] -- MISMATCHED RECV/SENT BYTE COUNT -- errno=%d nr=%zd ns=%zd\n", seq_num, errno, nr, ns);
                    }
                    pthread_mutex_unlock(&debugremutexvideo);
                } else {
                    pthread_mutex_lock(&debugremutexvideo);
                    if (debugrefilevideo != NULL)
                    {
                        fprintf(debugrefilevideo, "DATA SUCCESSFULLY SENT [VIDEO] seq_num[%u]...\n", seq_num);
                    }
                    pthread_mutex_unlock(&debugremutexvideo);
                }

                rtp2_pckts++;
                rtp2_bytes += ns;
                video_seq++;
            }
            else if ((nr < 0) &&
                     (errno == EAGAIN)) {
                // No data to be read (no activity on socket)
                //pthread_mutex_lock(&debugremutexvideo);
                //if (debugrefilevideo != NULL)
                //{
                //fprintf(debugrefilevideo, "No activity on videoecho socket (EAGAIN)...\n");
                //}
                //pthread_mutex_unlock(&debugremutexvideo);
            }
            else {
                // Other error occurred during read
                //WARNING("%s %i", "Error on RTP echo reception - stopping rtpstream echo - errno=", errno);
                pthread_mutex_lock(&debugremutexvideo);
                if (debugrefilevideo != NULL)
                {
                    fprintf(debugrefilevideo, "Error on RTP echo reception - unable to perform rtpstream videoecho - errno=%d\n", errno);
                }
                pthread_mutex_unlock(&debugremutexvideo);
                abnormal_termination = true;
            }
            pthread_mutex_unlock(&uasVideoMutex);
        }
        else
        {
            pthread_mutex_lock(&debugremutexvideo);
            if (debugrefilevideo != NULL)
            {
                fprintf(debugrefilevideo, "rtp_videoecho_thread():  pthread_cond_timedwait() non-timeout:  rc: %d quit_videoecho_thread: %d\n", rc, quit_videoecho_thread);
            }
            pthread_mutex_unlock(&debugremutexvideo);
        }
    }
    pthread_mutex_unlock(&quit_mutexvideo);

    if ((flags = fcntl(sock, F_GETFL, 0)) < 0)
    {
        pthread_mutex_lock(&debugremutexvideo);
        if (debugrefilevideo != NULL)
        {
            fprintf(debugrefilevideo, "rtp_videoecho_thread():  fcntl() GETFL BLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexvideo);
        pthread_exit((void*) 6);
    }

    if (fcntl(sock, F_SETFL, flags & (~O_NONBLOCK)) < 0)
    {
        pthread_mutex_lock(&debugremutexvideo);
        if (debugrefilevideo != NULL)
        {
            fprintf(debugrefilevideo, "rtp_videoecho_thread():  fcntl() SETFL BLOCK failed...\n");
        }
        pthread_mutex_unlock(&debugremutexvideo);
        pthread_exit((void*) 7);
    }

    if (abnormal_termination)
    {
        exit_code = -1;
    }
    else
    {
        exit_code = 0;
    }

    pthread_exit(reinterpret_cast<void*>(exit_code));
}

int rtpstream_rtpecho_startaudio(rtpstream_callinfo_t *callinfo, JLSRTP& rxUASAudio, JLSRTP& txUASAudio)
{
    debugprint ("rtpstream_rtpecho_startaudio callinfo=%p\n",callinfo);

    taskentry_t   *taskinfo= callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    taskinfo->audio_srtp_echo_active = 1;

    pthread_mutex_lock(&debugremutexaudio);
    if (srtpcheck_debug)
    {
        if (debugrefileaudio == NULL)
        {
            debugrefileaudio = fopen("debugrefileaudio", "w");
            if (debugrefileaudio == NULL)
            {
                /* error encountered opening audio debug file */
                pthread_mutex_lock(&debugremutexaudio);
                return -2;
            }
        }
    }
    pthread_mutex_unlock(&debugremutexaudio);

    pthread_mutex_lock(&debugremutexaudio);
    if (debugrefileaudio != NULL)
    {
        fprintf(debugrefileaudio, "rtpstream_rtpecho_startaudio reached...\n");
    }
    printLocalAudioSrtpStuff(taskinfo->local_srtp_audio_params);
    printRemoteAudioSrtpStuff(taskinfo->remote_srtp_audio_params);
    pthread_mutex_unlock(&debugremutexaudio);

    /* Create first RTP echo thread for audio */
    pthread_mutex_lock(&uasAudioMutex);
    g_rxUASAudio = rxUASAudio;
    g_txUASAudio = txUASAudio;
    pthread_mutex_unlock(&uasAudioMutex);

    if (taskinfo->audio_rtp_socket > 0) {
        if (pthread_create(&pthread_audioecho_id, NULL, (void *(*)(void *)) rtpstream_audioecho_thread, (void*)&taskinfo->audio_rtp_socket) == -1) {
            ERROR_NO("Unable to create RTP audio echo thread");
            return -7;
        }
    }

    return 0;
}

int rtpstream_rtpecho_updateaudio(rtpstream_callinfo_t *callinfo, JLSRTP& rxUASAudio, JLSRTP& txUASAudio)
{
    debugprint ("rtpstream_rtpecho_updateaudio callinfo=%p\n",callinfo);

    taskentry_t   *taskinfo= callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    taskinfo->audio_srtp_echo_active = 1;

    pthread_mutex_lock(&debugremutexaudio);
    if (debugrefileaudio != NULL)
    {
        fprintf(debugrefileaudio, "rtpstream_rtpecho_updateaudio reached...\n");
    }
    printLocalAudioSrtpStuff(taskinfo->local_srtp_audio_params);
    printRemoteAudioSrtpStuff(taskinfo->remote_srtp_audio_params);
    pthread_mutex_unlock(&debugremutexaudio);

    pthread_mutex_lock(&uasAudioMutex);
    g_rxUASAudio = rxUASAudio;
    g_txUASAudio = txUASAudio;
    pthread_mutex_unlock(&uasAudioMutex);

    return 0;
}

int rtpstream_rtpecho_stopaudio(rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_rtpecho_stopaudio callinfo=%p\n",callinfo);

    taskentry_t   *taskinfo= callinfo->taskinfo;
    ResultCheck r;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    taskinfo->audio_srtp_echo_active = 0;

    pthread_mutex_lock(&quit_mutexaudio);

    pthread_mutex_lock(&debugremutexaudio);
    if (debugrefileaudio != NULL)
    {
        fprintf(debugrefileaudio, "MAIN:  Setting quit_audioecho_thread flag to TRUE...\n");
    }
    pthread_mutex_unlock(&debugremutexaudio);
    quit_audioecho_thread = true;
    pthread_mutex_lock(&debugremutexaudio);
    if (debugrefileaudio != NULL)
    {
        fprintf(debugrefileaudio, "MAIN:  Sending QUIT signal...\n");
    }
    pthread_mutex_unlock(&debugremutexaudio);
    pthread_cond_signal(&quit_cvaudio);

    pthread_mutex_unlock(&quit_mutexaudio);

    pthread_mutex_lock(&debugremutexaudio);
    if (debugrefileaudio != NULL)
    {
        fprintf(debugrefileaudio, "rtpstream_rtpecho_stopaudio reached...\n");
    }
    printLocalAudioSrtpStuff(taskinfo->local_srtp_audio_params);
    printRemoteAudioSrtpStuff(taskinfo->remote_srtp_audio_params);
    pthread_mutex_unlock(&debugremutexaudio);

    if (pthread_join(pthread_audioecho_id, &r.p) == 0)
    {
        // successfully joined audio thread
        pthread_mutex_lock(&debugremutexaudio);
        if (debugrefileaudio != NULL)
        {
            fprintf(debugrefileaudio, "successfully joined audio thread: %d\n", r.i);
        }
        pthread_mutex_unlock(&debugremutexaudio);
    }
    else
    {
        // error joining audio thread
        pthread_mutex_lock(&debugremutexaudio);
        if (debugrefileaudio != NULL)
        {
            fprintf(debugrefileaudio, "error joining audio thread: %d\n", r.i);
        }
        pthread_mutex_unlock(&debugremutexaudio);
    }

    pthread_mutex_lock(&debugremutexaudio);
    if (srtpcheck_debug)
    {
        if (debugrefileaudio)
        {
            fclose(debugrefileaudio);
        }
    }
    pthread_mutex_unlock(&debugremutexaudio);

    return r.i;
}

int rtpstream_rtpecho_startvideo(rtpstream_callinfo_t *callinfo, JLSRTP& rxUASVideo, JLSRTP& txUASVideo)
{
    debugprint ("rtpstream_rtpecho_startvideo callinfo=%p\n",callinfo);

    taskentry_t   *taskinfo= callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    taskinfo->video_srtp_echo_active = 1;

    pthread_mutex_lock(&debugremutexvideo);
    if (srtpcheck_debug)
    {
        if (debugrefilevideo == NULL)
        {
            debugrefilevideo = fopen("debugrefilevideo", "w");
            if (debugrefilevideo == NULL)
            {
                /* error encountered opening audio debug file */
                pthread_mutex_unlock(&debugremutexvideo);
                return -2;
            }
        }
    }
    pthread_mutex_unlock(&debugremutexvideo);

    pthread_mutex_lock(&debugremutexvideo);
    if (debugrefilevideo != NULL)
    {
        fprintf(debugrefilevideo, "rtpstream_rtpecho_startvideo reached...\n");
    }
    printLocalVideoSrtpStuff(taskinfo->local_srtp_video_params);
    printRemoteVideoSrtpStuff(taskinfo->remote_srtp_video_params);
    pthread_mutex_unlock(&debugremutexvideo);

    /* Create second RTP echo thread for video */
    pthread_mutex_lock(&uasVideoMutex);
    g_rxUASVideo = rxUASVideo;
    g_txUASVideo = txUASVideo;
    pthread_mutex_unlock(&uasVideoMutex);

    if (taskinfo->video_rtp_socket > 0) {
        if (pthread_create(&pthread_videoecho_id, NULL, (void *(*)(void *)) rtpstream_videoecho_thread, (void*)&taskinfo->video_rtp_socket) == -1) {
            ERROR_NO("Unable to create RTP video echo thread");
            return -8;
        }
    }

    return 0;
}

int rtpstream_rtpecho_updatevideo(rtpstream_callinfo_t *callinfo, JLSRTP& rxUASVideo, JLSRTP& txUASVideo)
{
    debugprint ("rtpstream_rtpecho_updatevideo callinfo=%p\n",callinfo);

    taskentry_t   *taskinfo= callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    taskinfo->video_srtp_echo_active = 1;

    pthread_mutex_lock(&debugremutexvideo);
    if (debugrefilevideo != NULL)
    {
        fprintf(debugrefilevideo, "rtpstream_rtpecho_updatevideo reached...\n");
    }
    printLocalVideoSrtpStuff(taskinfo->local_srtp_video_params);
    printRemoteVideoSrtpStuff(taskinfo->remote_srtp_video_params);
    pthread_mutex_unlock(&debugremutexvideo);

    pthread_mutex_lock(&uasVideoMutex);
    g_rxUASVideo = rxUASVideo;
    g_txUASVideo = txUASVideo;
    pthread_mutex_unlock(&uasVideoMutex);

    return 0;
}

int rtpstream_rtpecho_stopvideo(rtpstream_callinfo_t *callinfo)
{
    debugprint ("rtpstream_rtpecho_stopvideo callinfo=%p\n",callinfo);

    taskentry_t   *taskinfo= callinfo->taskinfo;
    ResultCheck r;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    taskinfo->video_srtp_echo_active = 0;

    pthread_mutex_lock(&quit_mutexvideo);

    pthread_mutex_lock(&debugremutexvideo);
    if (debugrefilevideo != NULL)
    {
        fprintf(debugrefilevideo, "MAIN:  Setting quit_videoecho_thread flags to TRUE...\n");
    }
    pthread_mutex_unlock(&debugremutexvideo);
    quit_videoecho_thread = true;
    pthread_mutex_lock(&debugremutexvideo);
    if (debugrefilevideo != NULL)
    {
        fprintf(debugrefilevideo, "MAIN:  Sending QUIT signal...\n");
    }
    pthread_mutex_unlock(&debugremutexvideo);
    pthread_cond_signal(&quit_cvvideo);

    pthread_mutex_unlock(&quit_mutexvideo);

    pthread_mutex_lock(&debugremutexvideo);
    if (debugrefilevideo != NULL)
    {
        fprintf(debugrefilevideo, "rtpstream_rtpecho_stopvideo reached...\n");
    }
    printLocalVideoSrtpStuff(taskinfo->local_srtp_video_params);
    printRemoteVideoSrtpStuff(taskinfo->remote_srtp_video_params);
    pthread_mutex_unlock(&debugremutexvideo);

    if (pthread_join(pthread_videoecho_id, &r.p) == 0)
    {
        // successfully joined video thread
        pthread_mutex_lock(&debugremutexvideo);
        if (debugrefilevideo != NULL)
        {
            fprintf(debugrefilevideo, "successfully joined video thread: %d\n", r.i);
        }
        pthread_mutex_unlock(&debugremutexvideo);
    }
    else
    {
        // error joining video thread
        pthread_mutex_lock(&debugremutexvideo);
        if (debugrefilevideo != NULL)
        {
            fprintf(debugrefilevideo, "error joining video thread: %d\n", r.i);
        }
        pthread_mutex_unlock(&debugremutexvideo);
    }

    pthread_mutex_lock(&debugremutexvideo);
    if (srtpcheck_debug)
    {
        if (debugrefilevideo)
        {
            fclose(debugrefilevideo);
        }
    }
    pthread_mutex_unlock(&debugremutexvideo);

    return r.i;
}

/* code checked */
int rtpstream_shutdown(thread_map& threadIDs)
{
    int            count= 0;
    void*          rtpresult;
    int            total_rtpresults;

    rtpresult = NULL;
    total_rtpresults = 0;

    debugprint ("rtpstream_shutdown\n");

    /* signal all playback threads that they should exit */
    if (ready_threads) {
        for (count=0;count<num_ready_threads;count++) {
            ready_threads[count]->exit_flag= 1;
        }
        free (ready_threads);
        ready_threads= NULL;
    }

    if (busy_threads) {
        for (count=0;count<num_busy_threads;count++) {
            busy_threads[count]->exit_flag= 1;
        }
        free(busy_threads);
        busy_threads = NULL;
    }

    /* first make sure no playback threads are accessing the file buffers */
    /* else small chance the playback thread tries to access freed memory */
    while (rtpstream_numthreads) {
        usleep (50000);
    }

    // PTHREAD JOIN HERE...
    for (thread_map::iterator iter = threadIDs.begin(); iter != threadIDs.end(); ++iter)
    {
        printAudioHex("EXISTING THREADID: ", "", 0, (int)(long long)iter->first, 0);
        printVideoHex("EXISTING THREADID: ", "", 0, (int)(long long)iter->first, 0);
        if (pthread_join(iter->first, &rtpresult))
        {
            // error joining thread
            printAudioHex("ERROR RETURNED BY PTHREAD_JOIN!", "", 0, 0, 0);
            printVideoHex("ERROR RETURNED BY PTHREAD_JOIN!", "", 0, 0, 0);
            return -2;
        }

        total_rtpresults |= (long)rtpresult;
        printAudioHex("JOINED THREAD: ", "", 0, (long)rtpresult, total_rtpresults);
        printVideoHex("JOINED THREAD: ", "", 0, (long)rtpresult, total_rtpresults);
    }

    /* now free cached file bytes and structure */
    if (cached_files)
    {
        for (count=0;count<num_cached_files;count++) {
            free (cached_files[count].bytes);
        }
        free (cached_files);
        cached_files= NULL;
    }

    /* now free cached patterns bytes and structure */
    if (cached_patterns)
    {
        for (count=0;count<num_cached_files;count++) {
            free (cached_patterns[count].bytes);
        }
        free (cached_patterns);
        cached_patterns= NULL;
    }

    if (debugvfile &&
        rtpcheck_debug)
    {
        fclose(debugvfile);
    }

    if (debugafile &&
        rtpcheck_debug)
    {
        fclose(debugafile);
    }

    pthread_mutex_destroy(&debugamutex);

    return total_rtpresults;
}
