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
#include <poll.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <pthread.h>
#include "rtpstream.hpp"
#include "srtp_channel.hpp"

#include <sys/time.h>
#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>
#include <errno.h>
#include <sstream>
#include <fcntl.h>

/* stub to add extra debugging/logging... */
static void debugprint(const char* format, ...)
{
#if 0
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
#endif
}

static unsigned long tid_self() {
    return reinterpret_cast<unsigned long>(pthread_self());
}

struct free_delete {
    void operator()(void* x) { free(x); }
};
template<class T> using my_unique_ptr = std::unique_ptr<T, free_delete>;

#define RTPSTREAM_FILESPERBLOCK       16
#define RTPSTREAM_THREADBLOCKSIZE     16
#define MAX_UDP_RECV_BUFFER           8192
#define MAX_UDP_SEND_BUFFER           8192

#define TI_NULL_AUDIOIP               0x001
#define TI_NULL_VIDEOIP               0x002
#define TI_NULLIP                     (TI_NULL_AUDIOIP | TI_NULL_VIDEOIP)
#define TI_PAUSERTP                   0x004
#define TI_ECHORTP                    0x008  /* Not currently implemented */
#define TI_KILLTASK                   0x010
#define TI_RECONNECTSOCKET            0x020
#define TI_PLAYFILE                   0x040
#define TI_PAUSERTPAPATTERN           0x080
#define TI_PLAYAPATTERN               0x100
#define TI_PAUSERTPVPATTERN           0x200
#define TI_PLAYVPATTERN               0x400
#define TI_CONFIGFLAGS                (TI_KILLTASK | TI_RECONNECTSOCKET | TI_PLAYFILE | TI_PLAYAPATTERN | TI_PLAYVPATTERN)

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
    explicit threaddata_t(unsigned int max_tasks) : max_tasks(max_tasks), tasklist(max_tasks) {}

    pthread_t id;
    pthread_mutex_t tasklist_mutex;
    int             busy_list_index = -1;
    unsigned int    max_tasks;
    /* The tasks its loops walk, each added one included: they walk
     * without the mutex that adding one takes, and read it with acquire
     * loads, which see the task that the release store counts. */
    std::atomic<unsigned int> num_tasks{0};
    volatile int    del_pending = 0;
    volatile int    exit_flag = 0;
    int             wake_fds[2]; /* a pipe to wake the thread up */
#ifdef PCAPPLAY
    int             pcap_socket = -1; /* the raw socket of its pcap plays */
#endif
    std::vector<taskentry_t*> tasklist; /* max_tasks of them */
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
    int  filesize;
};

cached_file_t  *cached_files = nullptr;
cached_pattern_t *cached_patterns = nullptr;
int            num_cached_files = 0;
int            num_cached_patterns = 0;
int            next_rtp_port = 0;

threaddata_t  **ready_threads = nullptr;
threaddata_t  **busy_threads = nullptr;
int           num_busy_threads = 0;
int           num_ready_threads = 0;
int           busy_threads_max = 0;
int           ready_threads_max = 0;

enum class Where {
    Local,
    Remote
};
enum class Type {
    Audio,
    Video,
};

class DebugFile
{
public:
    ~DebugFile()
    {
        if (fp)
        {
            fclose(fp);
        }
    }

    bool open(const char* filename)
    {
        std::lock_guard lock(mutex);
        if (fp) return true;
        int fd = ::open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return false;
        fp = fdopen(fd, "w");
        return !!fp;
    }

    void close()
    {
        std::lock_guard lock(mutex);
        if (fp)
        {
            fclose(fp);
            fp = nullptr;
        }
    }

    void printHex(
        char const* note,
        char const* string,
        unsigned int size,
        unsigned long long extrainfo,
        int moreinfo
    ) const;
    void printHexUS(
        char const* note,
        unsigned char const* string,
        unsigned int size,
        unsigned long long extrainfo,
        int moreinfo
    ) const
    {
        printHex(note, reinterpret_cast<char const*>(string), size, extrainfo, moreinfo);
    }
    void printf(const char* format, ...) const
    {
        if (!fp)
        {
            return;
        }
        std::lock_guard lock(mutex);
        if (!fp)
        {
            return;
        }
        va_list args;
        va_start(args, format);
        // fprintf(fp, "TID: %lu ", tid_self());
        vfprintf(fp, format, args);
        va_end(args);
    }

protected:
    /* checked before locking, so a closed file costs no lock */
    std::atomic<FILE*> fp{nullptr};
    mutable std::mutex mutex;
};

class RtpEchoDebugFile : public DebugFile
{
public:
    RtpEchoDebugFile(Type type) : type(type) {}

    bool open()
    {
        if (fp)
        {
            return true;
        }
        std::ostringstream oss;
        oss << "debugrefile" << (type == Type::Audio ? "audio" : "video") << '_' << time(NULL) << ".log";
        return DebugFile::open(oss.str().c_str());
    }
    void printReceived(unsigned char const* data, unsigned int size) const;

private:
    Type type;
};

class SrtpDebugFile : public DebugFile
{
public:
    SrtpDebugFile(Where where, Type type) :
        where(where),
        type(type) {}

    bool open()
    {
        if (fp)
        {
            return true;
        }
        const bool isClient = (sendMode == MODE_CLIENT);
        if (!isClient && sendMode != MODE_SERVER)
        {
            return false;
        }
        std::ostringstream oss;
        oss << "debug"
            << (where == Where::Local ? 'l' : 'r')
            << "srtp"
            << (type == Type::Audio ? 'a' : 'v')
            << "file_"
            << (isClient ? "uac" : "uas");
        return DebugFile::open(oss.str().c_str());
    }
    void printCrypto(const SrtpInfoParams &p) const;

private:
    Where where;
    Type type;
};

static DebugFile debugafile;
static DebugFile debugvfile;
static SrtpDebugFile debuglsrtpafile(Where::Local, Type::Audio);
static SrtpDebugFile debugrsrtpafile(Where::Remote, Type::Audio);
static SrtpDebugFile debuglsrtpvfile(Where::Local, Type::Video);
static SrtpDebugFile debugrsrtpvfile(Where::Remote, Type::Video);
static RtpEchoDebugFile debugrefileaudio(Type::Audio);
static RtpEchoDebugFile debugrefilevideo(Type::Video);

// RTPSTREAM ECHO -- a call's audio or video echo, which its playback
// thread does; guarded by the task's mutex
struct rtpecho_t
{
    SrtpChannel rx;
    SrtpChannel tx;
    bool error = false; /* failed to receive */
};

// RTPSTREAM PLAYBACK -- a call's UAC SRTP contexts, which its playback
// thread sends and receives with; guarded by the task's mutex
struct rtpsrtp_t
{
    SrtpChannel tx;
    SrtpChannel rx;
};

//===================================================================================================

static unsigned long long getThreadId(pthread_t p)
{
    unsigned long long retVal = -1;

#if defined(__APPLE__)
    int rc = -1;
    uint64_t thread_id = 0;
    rc = pthread_threadid_np(p, &thread_id);
    if (rc == 0)
    {
        retVal = thread_id;
    }
    else
    {
        retVal = -1;
    }
#elif defined(__CYGWIN__)
    retVal = -1; // CygWin uses dummy thread IDs in pthread_t
#else  // !__APPLE__ && !__CYGWIN__
    retVal = (unsigned long long)p;
#endif // __APPLE__

    return retVal;
}

void DebugFile::printHex(
    char const* note,
    char const* string,
    unsigned int size,
    unsigned long long extrainfo,
    int moreinfo
) const
{
    if (!rtpcheck_debug || !fp)
    {
        return;
    }
    std::lock_guard lock(mutex);
    if (!fp || !note || !string)
    {
        return;
    }
    fprintf(fp, "TID: %lu %s %u 0x%llx %d [", tid_self(), note, size, extrainfo, moreinfo);
    for (unsigned int i = 0; i < size; i++)
    {
        fprintf(fp, "%02X", 0xFF & string[i]);
    }
    fprintf(fp, "]\n");
}

void RtpEchoDebugFile::printReceived(unsigned char const* data, unsigned int size) const
{
    if (!fp)
    {
        return;
    }
    std::lock_guard lock(mutex);
    if (!fp || !data)
    {
        return;
    }
    fprintf(fp, "DATA SUCCESSFULLY RECEIVED [%s] nr = %u...",
        type == Type::Audio ? "AUDIO" : "VIDEO",
        size);
    for (int i = 0; i < 12; i++)
    {
        fprintf(fp, "%02X", 0xFF & data[i]);
    }
    fprintf(fp, "\n");
}

void SrtpDebugFile::printCrypto(const SrtpInfoParams &p) const
{
    std::lock_guard lock(mutex);
    if (!fp)
    {
        return;
    }
    fprintf(fp, "found                     : %d\n", p.found);
    fprintf(fp, "primary_cryptotag         : %d\n", p.primary_cryptotag);
    fprintf(fp, "secondary_cryptotag       : %d\n", p.secondary_cryptotag);
    fprintf(fp, "primary_cryptosuite       : %s\n", p.primary_cryptosuite);
    fprintf(fp, "secondary_cryptosuite     : %s\n", p.secondary_cryptosuite);
    fprintf(fp, "primary_cryptokeyparams   : %s\n", p.primary_cryptokeyparams);
    fprintf(fp, "secondary_cryptokeyparams : %s\n", p.secondary_cryptokeyparams);
    fprintf(fp, "primary_unencrypted_srtp  : %d\n", p.primary_unencrypted_srtp);
    fprintf(fp, "secondary_unencrypted_srtp: %d\n", p.secondary_unencrypted_srtp);
}

int set_bit(unsigned long* context, int value)
{
    int retVal = -1;

    if (context != nullptr)
    {
        if (value > 0)
        {
            *context |= (1 << (value - 1));
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

    if (context != nullptr)
    {
        if (value > 0)
        {
            *context &= ~(1 << (value - 1));
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
taskentry_t::~taskentry_t()
{
    /* close sockets associated with this call */
    if (audio_rtp_socket != -1) {
        close(audio_rtp_socket);
    }
    if (audio_rtcp_socket != -1) {
        close(audio_rtcp_socket);
    }
    if (video_rtp_socket != -1) {
        close(video_rtp_socket);
    }
    if (video_rtcp_socket != -1) {
        close(video_rtcp_socket);
    }

    delete audio_echo;
    delete video_echo;
    delete audio_srtp;
    delete video_srtp;

    /* cleanup pthread library structure */
    pthread_mutex_destroy(&mutex);
}

/* Copy size bytes of a file that plays in a loop into dest, from
 * offset on: from its start again at its end, as often as it takes
 * for a file shorter than a packet. */
static void rtpstream_copy_loop(char* dest, int size, const char* file, int file_size, int offset)
{
    while (size > 0)
    {
        int count = std::min(size, file_size - offset);
        memcpy(dest, file + offset, count);
        dest += count;
        size -= count;
        offset = 0;
    }
}

/* Give the verdict of the RTP check of a task's audio or video pattern,
 * setting the pattern's bit in *rtpresult if it failed, and start the
 * check over: at the end of the task, or when it plays something else. */
static void rtpstream_check_verdict(taskentry_t* taskinfo, bool video, unsigned long* rtpresult)
{
    unsigned long& packets = video ? taskinfo->video_check_packets : taskinfo->audio_check_packets;
    unsigned long& failures = video ? taskinfo->video_check_failures : taskinfo->audio_check_failures;
    DebugFile const& debugfile = video ? debugvfile : debugafile;

    if (packets > 0)
    {
        debugfile.printHex("----RTP CHECK VERDICT----", "", 0, failures, packets);
        if ((double)failures / (double)packets >= (video ? videotolerance : audiotolerance))
        {
            set_bit(rtpresult, video ? taskinfo->video_pattern_id : taskinfo->audio_pattern_id);
        }
    }
    packets = 0;
    failures = 0;
}

/* The timestamp of a stream's packet at the last multiple of its packet
 * time, where its timestamps start, and stay while it is paused. Its
 * first packet goes at once, stamped up to a packet time earlier, and
 * the others on the multiples of the packet time, with those of the
 * other streams of its thread: they go in one wake-up of the thread.
 * Streams stamped from when they started went at different phases, and
 * the thread woke up for about each packet. */
static unsigned long rtpstream_grid_ms(unsigned long timenow_ms, int ms_per_packet)
{
    return ms_per_packet > 0 ? timenow_ms - timenow_ms % ms_per_packet : timenow_ms;
}

static unsigned long long rtpstream_grid_timestamp(unsigned long timenow_ms, int ms_per_packet,
                                                   int ticks_per_ms)
{
    return (unsigned long long) rtpstream_grid_ms(timenow_ms, ms_per_packet) * ticks_per_ms;
}

/* code checked */
static void rtpstream_process_task_flags(taskentry_t* taskinfo, unsigned long* rtpresult)
{
    if (taskinfo->flags & TI_RECONNECTSOCKET) {
        int remote_addr_len;
        int rc = -1;

        remote_addr_len = media_ip_is_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

        /* enter critical section to lock address updates */
        /* may want to leave this out -- low chance of race condition */
        pthread_mutex_lock(&(taskinfo->mutex));

        /* If we have valid ip and port numbers for audio rtp stream */
        if (!(taskinfo->flags & TI_NULL_AUDIOIP))
        {
            if (taskinfo->audio_rtcp_socket != -1) {
                rc = connect(taskinfo->audio_rtcp_socket, (struct sockaddr *) & (taskinfo->remote_audio_rtcp_addr), remote_addr_len);
                if (rc < 0) {
                    debugprint("closing audio rtcp socket %d due to error %d in rtpstream_process_task_flags taskinfo = %p\n",
                               taskinfo->audio_rtcp_socket, errno, taskinfo);
                    close(taskinfo->audio_rtcp_socket);
                    taskinfo->audio_rtcp_socket = -1;
                }
            }

            if (taskinfo->audio_rtp_socket != -1) {
                if (!taskinfo->audio_srtp_echo_active) {
                    rc = connect(taskinfo->audio_rtp_socket, (struct sockaddr *) & (taskinfo->remote_audio_rtp_addr), remote_addr_len);
                    if (rc < 0) {
                        debugprint("closing audio rtp socket %d due to error %d in rtpstream_process_task_flags taskinfo = %p\n",
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
        if (!(taskinfo->flags & TI_NULL_VIDEOIP))
        {
            if (taskinfo->video_rtcp_socket != -1) {
                rc = connect(taskinfo->video_rtcp_socket, (struct sockaddr *) & (taskinfo->remote_video_rtcp_addr), remote_addr_len);
                if (rc < 0) {
                    debugprint("closing video rtcp socket %d due to error %d in rtpstream_process_task_flags taskinfo = %p\n",
                               taskinfo->video_rtcp_socket, errno, taskinfo);
                    close(taskinfo->video_rtcp_socket);
                    taskinfo->video_rtcp_socket = -1;
                }
            }
            if (taskinfo->video_rtp_socket != -1) {
                if (!taskinfo->video_srtp_echo_active) {
                    rc = connect(taskinfo->video_rtp_socket, (struct sockaddr *) & (taskinfo->remote_video_rtp_addr), remote_addr_len);
                    if (rc < 0) {
                        debugprint("closing video rtp socket %d due to error %d in rtpstream_process_task_flags taskinfo = %p\n",
                                   taskinfo->video_rtp_socket, errno, taskinfo);
                        close(taskinfo->video_rtp_socket);
                        taskinfo->video_rtp_socket = -1;
                    }
                } else {
                    /* Do NOT perform connect() when doing SRTP echo */
                }
            }
        }

        taskinfo->flags &= ~TI_RECONNECTSOCKET;
        pthread_mutex_unlock(&(taskinfo->mutex));
    }

    /* Take a new play under the mutex, for rtpstream_is_playing() to see
     * it either in the flags or in the loop counts. */
    pthread_mutex_lock(&(taskinfo->mutex));
    if (taskinfo->flags & (TI_PLAYFILE | TI_PLAYAPATTERN | TI_PLAYVPATTERN)) {
        /* it starts now, not at the task's next wake-up */
        taskinfo->nextwake_ms = 0;
    }
    if (taskinfo->flags & TI_PLAYFILE) {
        rtpstream_check_verdict(taskinfo, false, rtpresult);
        /* copy playback information */
        taskinfo->audio_pattern_id = taskinfo->new_audio_pattern_id;
        taskinfo->audio_loop_count = taskinfo->new_audio_loop_count;
        taskinfo->audio_file_bytes_start = taskinfo->new_audio_file_bytes;
        taskinfo->audio_current_file_bytes = taskinfo->new_audio_file_bytes;
        taskinfo->audio_file_num_bytes = taskinfo->new_audio_file_size;
        taskinfo->audio_file_bytes_left = taskinfo->new_audio_file_size;
        taskinfo->audio_payload_type = taskinfo->new_audio_payload_type;

        taskinfo->audio_ms_per_packet = taskinfo->new_audio_ms_per_packet;
        taskinfo->audio_bytes_per_packet = taskinfo->new_audio_bytes_per_packet;
        taskinfo->audio_timeticks_per_packet = taskinfo->new_audio_timeticks_per_packet;
        taskinfo->audio_timeticks_per_ms = taskinfo->audio_timeticks_per_packet/taskinfo->audio_ms_per_packet;

        taskinfo->last_audio_timestamp = rtpstream_grid_timestamp(getmilliseconds(), taskinfo->audio_ms_per_packet,
                                                                  taskinfo->audio_timeticks_per_ms);
        taskinfo->flags &= ~TI_PLAYFILE;
    }

    if (taskinfo->flags & TI_PLAYAPATTERN)
    {
        rtpstream_check_verdict(taskinfo, false, rtpresult);
        /* copy playback information */
        taskinfo->audio_pattern_id = taskinfo->new_audio_pattern_id;
        taskinfo->audio_loop_count = taskinfo->new_audio_loop_count;
        taskinfo->audio_file_bytes_start = taskinfo->new_audio_file_bytes;
        taskinfo->audio_current_file_bytes = taskinfo->new_audio_file_bytes;
        taskinfo->audio_file_num_bytes = taskinfo->new_audio_file_size;
        taskinfo->audio_file_bytes_left = taskinfo->new_audio_file_size;
        taskinfo->audio_payload_type = taskinfo->new_audio_payload_type;
        taskinfo->audio_seq_check = taskinfo->audio_seq_out;

        taskinfo->audio_ms_per_packet = taskinfo->new_audio_ms_per_packet;
        taskinfo->audio_bytes_per_packet = taskinfo->new_audio_bytes_per_packet;
        taskinfo->audio_timeticks_per_packet = taskinfo->new_audio_timeticks_per_packet;
        taskinfo->audio_timeticks_per_ms = taskinfo->audio_timeticks_per_packet/taskinfo->audio_ms_per_packet;

        taskinfo->last_audio_timestamp = rtpstream_grid_timestamp(getmilliseconds(), taskinfo->audio_ms_per_packet,
                                                                  taskinfo->audio_timeticks_per_ms);
        taskinfo->flags &= ~TI_PLAYAPATTERN;
    }

    if (taskinfo->flags & TI_PLAYVPATTERN)
    {
        rtpstream_check_verdict(taskinfo, true, rtpresult);
        /* copy playback information */
        taskinfo->video_pattern_id = taskinfo->new_video_pattern_id;
        taskinfo->video_loop_count = taskinfo->new_video_loop_count;
        taskinfo->video_file_bytes_start = taskinfo->new_video_file_bytes;
        taskinfo->video_current_file_bytes = taskinfo->new_video_file_bytes;
        taskinfo->video_file_num_bytes = taskinfo->new_video_file_size;
        taskinfo->video_file_bytes_left = taskinfo->new_video_file_size;
        taskinfo->video_payload_type = taskinfo->new_video_payload_type;

        taskinfo->video_ms_per_packet = taskinfo->new_video_ms_per_packet;
        taskinfo->video_bytes_per_packet = taskinfo->new_video_bytes_per_packet;
        taskinfo->video_timeticks_per_packet = taskinfo->new_video_timeticks_per_packet;
        taskinfo->video_timeticks_per_ms = taskinfo->video_timeticks_per_packet/taskinfo->video_ms_per_packet;

        taskinfo->last_video_timestamp = rtpstream_grid_timestamp(getmilliseconds(), taskinfo->video_ms_per_packet,
                                                                  taskinfo->video_timeticks_per_ms);
        taskinfo->flags &= ~TI_PLAYVPATTERN;
    }
    pthread_mutex_unlock(&(taskinfo->mutex));
}

/* The millisecond to wake up in for a stream's next packet. A packet
 * goes in the millisecond of its timestamp, so the next one is the packet
 * after the last one if that goes now. When paused, the stream only keeps
 * its timestamp up to date, on the multiples of its packet time. */
static unsigned long rtpstream_next_packet_ms(unsigned long timenow_ms, bool paused,
                                              unsigned long long last_timestamp,
                                              unsigned long long target_timestamp,
                                              int ms_per_packet, int ticks_per_packet,
                                              int ticks_per_ms)
{
    if (paused) {
        return timenow_ms + ms_per_packet - timenow_ms % ms_per_packet;
    }
    if (last_timestamp <= target_timestamp) {
        last_timestamp += ticks_per_packet;
    }
    return (last_timestamp + ticks_per_ms - 1) / ticks_per_ms;
}

/**** todo - check code ****/
static unsigned long rtpstream_playrtptask(taskentry_t* taskinfo,
                                           unsigned long  timenow_ms,
                                           unsigned long* comparison_acheck,
                                           unsigned long* comparison_vcheck,
                                           unsigned int taskindex)
{
    int                  rc;
    unsigned long        next_wake;
    unsigned long long   target_timestamp;
    int                  compresult;
    struct pollfd        pfd;
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
    unsigned int audio_in_size = 0;
    unsigned int video_in_size = 0;
    unsigned short audio_seq_in = 0;
    unsigned short video_seq_in = 0;
    bool audio_echo = false; /* an echo came in */
    bool paused;

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


    pfd.events = POLLIN;

    *comparison_acheck = 0;
    *comparison_vcheck = 0;

    debugafile.printHex("----AUDIO RTP SOCKET----", "", 0, taskindex, taskinfo->audio_rtp_socket);
    debugvfile.printHex("----VIDEO RTP SOCKET----", "", 0, taskindex, taskinfo->video_rtp_socket);

    /* OK, now to play - sockets are supposed to be non-blocking */
    /* no support for video stream at this stage. will need some work */

    next_wake = timenow_ms + 100; /* default next wakeup time */

    if (taskinfo->audio_rtp_socket != -1)
    {
        /* are we playing back an audio file/pattern? */
        if (taskinfo->audio_loop_count)
        {
            target_timestamp = timenow_ms * taskinfo->audio_timeticks_per_ms;
            paused = taskinfo->flags.load(std::memory_order_relaxed) &
                     (TI_NULL_AUDIOIP | TI_PAUSERTP | TI_PAUSERTPAPATTERN);
            if (paused)
            {
                /* when paused, set timestamp so stream appears to be up to date */
                pthread_mutex_lock(&(taskinfo->mutex));
                taskinfo->last_audio_timestamp = rtpstream_grid_timestamp(timenow_ms, taskinfo->audio_ms_per_packet,
                                                                          taskinfo->audio_timeticks_per_ms);
                pthread_mutex_unlock(&(taskinfo->mutex));
            }
            /* Waking up on the multiples of the packet time, and sending
             * a packet in the millisecond after its timestamp, sent a whole
             * packet time late each packet of a stream that started on one,
             * unless the thread was late itself. */
            next_wake = rtpstream_next_packet_ms(timenow_ms, paused, taskinfo->last_audio_timestamp,
                                                 target_timestamp, taskinfo->audio_ms_per_packet,
                                                 taskinfo->audio_timeticks_per_packet,
                                                 taskinfo->audio_timeticks_per_ms);

            if (!paused && taskinfo->last_audio_timestamp <= target_timestamp)
            {
                /* need to send rtp payload - build rtp packet header... */
                memset(udp_send_audio.buffer, 0, sizeof(udp_send_audio));
                udp_send_audio.hdr.flags = htons(0x8000 | taskinfo->audio_payload_type);
                udp_send_audio.hdr.seq = htons(taskinfo->audio_seq_out);
                udp_send_audio.hdr.timestamp = htonl((uint32_t) (taskinfo->last_audio_timestamp & 0XFFFFFFFF));
                udp_send_audio.hdr.ssrc_id = htonl(taskinfo->audio_ssrc_id);
                /* add payload data to the packet - handle buffer wraparound */
                rtpstream_copy_loop(udp_send_audio.buffer + sizeof(rtp_header_t), taskinfo->audio_bytes_per_packet,
                                    taskinfo->audio_file_bytes_start, taskinfo->audio_file_num_bytes,
                                    taskinfo->audio_file_num_bytes - taskinfo->audio_file_bytes_left);

                pthread_mutex_lock(&(taskinfo->mutex));
                SrtpChannel* tx = taskinfo->audio_srtp && taskinfo->audio_srtp->tx.getCryptoTag() != 0 ? &taskinfo->audio_srtp->tx : nullptr;
                SrtpChannel* rx = taskinfo->audio_srtp && taskinfo->audio_srtp->rx.getCryptoTag() != 0 ? &taskinfo->audio_srtp->rx : nullptr;
                if (tx)
                {
                    // GRAB RTP HEADER
                    rtp_header.resize(sizeof(rtp_header_t), 0);
                    memcpy(rtp_header.data(), udp_send_audio.buffer, sizeof(rtp_header_t) /*12*/);
                    // GRAB RTP PAYLOAD DATA
                    payload_data.resize(taskinfo->audio_bytes_per_packet, 0);
                    memcpy(payload_data.data(), udp_send_audio.buffer + sizeof(rtp_header_t), taskinfo->audio_bytes_per_packet);

                    // ENCRYPT
                    rc = tx->processOutgoingPacket(taskinfo->audio_seq_out, rtp_header, payload_data, audio_out);
                    debugafile.printHex("TXUACAUDIO -- processOutgoingPacket() rc == ", "", 0, rc, 0);
                }
                else
                {
                    // NOENCRYPTION
                    audio_out.resize(sizeof(rtp_header_t) + taskinfo->audio_bytes_per_packet, 0);
                    memcpy(audio_out.data(), udp_send_audio.buffer, sizeof(rtp_header_t) + taskinfo->audio_bytes_per_packet);
                }

                /* now send the actual packet */
                rc = send(taskinfo->audio_rtp_socket, audio_out.data(), audio_out.size(), 0);
                if (rc < 0)
                {
                    debugafile.printHex("SEND FAILED: ", "", 0, rc, errno);

                    /* handle sending errors */
                    if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
                    {
                        next_wake = timenow_ms + 2; /* retry after short sleep */
                    }
                    else
                    {
                        /* this looks like a permanent error  - should we ignore ENETUNREACH? */
                        debugprint("closing rtp socket %d due to error %d in rtpstream_new_call callinfo=%p\n", taskinfo->audio_rtp_socket, errno);
                        close(taskinfo->audio_rtp_socket);
                        taskinfo->audio_rtp_socket = -1;
                    }
                }
                else
                {
                    /* statistics - only count successful sends */
                    rtpstream_abytes_out.fetch_add(taskinfo->audio_bytes_per_packet + sizeof(rtp_header_t), std::memory_order_relaxed);
                    rtpstream_apckts.fetch_add(1, std::memory_order_relaxed); // GLOBAL RTP packet counter
                    if (taskinfo->audio_pattern_id > 0)
                    {
                        taskinfo->audio_check_packets++; // the pattern packets the RTP check checks
                    }

                    debugafile.printHexUS("SIPP SUCCESS SEND LOG: ", audio_out.data(), audio_out.size(), rc, rtpstream_apckts);

                    /* poll(), not select(): the socket may be >= FD_SETSIZE */
                    pfd.fd = taskinfo->audio_rtp_socket;
                    rc = poll(&pfd, 1, 0); /* Never block */

                    if (rc > 0)
                    {
                        /* this is temp code - will have to reorganize if/when we include echo functionality */
                        /* just keep listening on rtp socket (is this really required?) - ignore any errors */
                        if (rx)
                        {
                            audio_in_size = sizeof(rtp_header_t) + taskinfo->audio_bytes_per_packet + rx->getAuthenticationTagSize();
                        }
                        else
                        {
                            // NOENCRYPTION
                            audio_in_size = sizeof(rtp_header_t) + taskinfo->audio_bytes_per_packet;
                        }

                        audio_in.resize(audio_in_size, 0);
                        while ((rc = recv(taskinfo->audio_rtp_socket, audio_in.data(), audio_in.size(), 0)) >= 0)
                        {
                            audio_echo = true;
                            /* for now we will just ignore any received data or receive errors */
                            /* separate code path for RTP echo */
                            rtpstream_abytes_in.fetch_add(rc, std::memory_order_relaxed);
                            debugafile.printHexUS("SIPP SUCCESS RECV LOG: ", audio_in.data(), audio_in.size(), rc, rtpstream_apckts);
                        }
                        if (rx)
                        {
                            // DECRYPT
                            rtp_header.clear();
                            payload_data.clear();

                            audio_seq_in = ntohs(((rtp_header_t*)audio_in.data())->seq);
                            rc = rx->processIncomingPacket(audio_seq_in, audio_in, rtp_header, payload_data);
                            debugafile.printHex("RXUACAUDIO -- processIncomingPacket() rc == ", "", 0, rc, 0);

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
                            audio_in[10] = (host_ssrc >> 8) & 0xFF;
                            audio_in[11] = host_ssrc & 0xFF;

                            memset(udp_recv_audio.buffer, 0, sizeof(udp_recv_audio));
                            memcpy(udp_recv_audio.buffer, rtp_header.data(), rtp_header.size());
                            memcpy(udp_recv_audio.buffer + sizeof(rtp_header_t), payload_data.data(), payload_data.size());
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
                            audio_in[10] = (host_ssrc >> 8) & 0xFF;
                            audio_in[11] = host_ssrc & 0xFF;

                            memset(udp_recv_audio.buffer, 0, sizeof(udp_recv_audio));
                            memcpy(udp_recv_audio.buffer, audio_in.data(), audio_in.size());
                        }

                        // VALIDATION TEST
                        if (audio_echo)
                        {
                            taskinfo->audio_seq_echoed = host_seqnum;
                        }
                        compresult = 0;
                        if (taskinfo->audio_pattern_id > 0 &&
                            (!audio_echo || (unsigned short) (host_seqnum - taskinfo->audio_seq_check) < 0x8000))
                        {
                            compresult = memcmp(udp_send_audio.buffer + sizeof(rtp_header_t),
                                                udp_recv_audio.buffer + sizeof(rtp_header_t),
                                                taskinfo->audio_bytes_per_packet /* PAYLOAD comparison ONLY -- header EXCLUDED*/);
                        }
                        /* else not the echo of a pattern packet: nothing to check */
                        if (compresult == 0)
                        {
                            // SUCCESS
                            debugafile.printHex("COMPARISON OK ", "", 0, taskinfo->audio_comparison_errors, rtpstream_apckts);
                            *comparison_acheck = 0;
                        }
                        else
                        {
                            // FAILURE
                            taskinfo->audio_comparison_errors++;
                            debugafile.printHex("COMPARISON FAILED", "", 0, taskinfo->audio_comparison_errors, rtpstream_apckts);
                            *comparison_acheck = 1;
                        }
                    }
                    else if (taskinfo->audio_pattern_id < 1 ||
                             taskinfo->audio_seq_echoed == (unsigned short) (taskinfo->audio_seq_out - 1))
                    {
                        /* no pattern to check, or the echo of the previous
                         * packet came in already: this one's is on its way */
                        *comparison_acheck = 0;
                    }
                    else
                    {
                        taskinfo->audio_comparison_errors++;
                        debugafile.printHex("NODATA", "", 0, taskinfo->audio_comparison_errors, rtpstream_apckts);
                        *comparison_acheck = 1;
                    }

                    /* advance playback pointer to next packet */
                    taskinfo->audio_seq_out++;
                    /* must change if timer ticks per packet can be fractional */
                    taskinfo->last_audio_timestamp += taskinfo->audio_timeticks_per_packet;
                    taskinfo->audio_file_bytes_left -= taskinfo->audio_bytes_per_packet;
                    if (taskinfo->audio_file_bytes_left > 0)
                    {
                        taskinfo->audio_current_file_bytes += taskinfo->audio_bytes_per_packet;
                    }
                    else
                    {
                        /* from the start of the file again: more than once
                         * in a packet, for a file shorter than a packet */
                        do
                        {
                            taskinfo->audio_file_bytes_left += taskinfo->audio_file_num_bytes;
                            if (taskinfo->audio_loop_count > 0)
                            {
                                /* one less loop to play. -1 (infinite loops) will stay as is */
                                taskinfo->audio_loop_count--;
                            }
                        } while (taskinfo->audio_file_bytes_left <= 0);
                        taskinfo->audio_current_file_bytes = taskinfo->audio_file_bytes_start + taskinfo->audio_file_num_bytes - taskinfo->audio_file_bytes_left;
                    }
                    if (taskinfo->last_audio_timestamp <= target_timestamp)
                    {
                        /* no sleep if we are behind */
                        next_wake = timenow_ms;
                    }
                } /* if (rc < 0) */
                pthread_mutex_unlock(&(taskinfo->mutex));
            } /* if (taskinfo->last_audio_timestamp <= target_timestamp) */
            else
            {
                debugafile.printHex("TIMESTAMP NOT QUITE RIGHT...", "", 0, 0, 0);
                *comparison_acheck = -1;
            }
        } /* if (taskinfo->audio_loop_count) */
        else
        {
          /* not busy playing back a file -  put possible rtp echo code here. */
        }
    } // if (taskinfo->audio_rtp_socket != -1)

    if (taskinfo->audio_rtcp_socket != -1)
    {
        /* just keep listening on rtcp socket (is this really required?) - ignore any errors */
        while ((rc = recv(taskinfo->audio_rtcp_socket, udp_recv_temp.buffer, sizeof(udp_recv_temp.buffer), 0)) >= 0)
        {
            /*
             * rtpstream_abytes_in += rc;
             */
        }
    }

    if (taskinfo->video_rtp_socket != -1)
    {
        /* are we playing back a video file/pattern? */
        if (taskinfo->video_loop_count)
        {
            target_timestamp = timenow_ms * taskinfo->video_timeticks_per_ms;
            paused = taskinfo->flags.load(std::memory_order_relaxed) &
                     (TI_NULL_VIDEOIP | TI_PAUSERTP | TI_PAUSERTPVPATTERN);
            if (paused)
            {
                /* when paused, set timestamp so stream appears to be up to date */
                pthread_mutex_lock(&(taskinfo->mutex));
                taskinfo->last_video_timestamp = rtpstream_grid_timestamp(timenow_ms, taskinfo->video_ms_per_packet,
                                                                          taskinfo->video_timeticks_per_ms);
                pthread_mutex_unlock(&(taskinfo->mutex));
            }
            /* Keep an earlier wakeup the audio stream asked for: overwriting
             * it made audio go out at the video packet rate. */
            next_wake = std::min(next_wake, rtpstream_next_packet_ms(timenow_ms, paused, taskinfo->last_video_timestamp,
                                                                     target_timestamp, taskinfo->video_ms_per_packet,
                                                                     taskinfo->video_timeticks_per_packet,
                                                                     taskinfo->video_timeticks_per_ms));

            if (!paused && taskinfo->last_video_timestamp <= target_timestamp)
            {
                /* need to send rtp payload - build rtp packet header... */
                memset(udp_send_video.buffer, 0, sizeof(udp_send_video));
                udp_send_video.hdr.flags = htons(0x8000 | taskinfo->video_payload_type);
                udp_send_video.hdr.seq = htons(taskinfo->video_seq_out);
                udp_send_video.hdr.timestamp = htonl((uint32_t) (taskinfo->last_video_timestamp & 0XFFFFFFFF));
                udp_send_video.hdr.ssrc_id = htonl(taskinfo->video_ssrc_id);
                /* add payload data to the packet - handle buffer wraparound */
                rtpstream_copy_loop(udp_send_video.buffer + sizeof(rtp_header_t), taskinfo->video_bytes_per_packet,
                                    taskinfo->video_file_bytes_start, taskinfo->video_file_num_bytes,
                                    taskinfo->video_file_num_bytes - taskinfo->video_file_bytes_left);

                pthread_mutex_lock(&(taskinfo->mutex));
                SrtpChannel* tx = taskinfo->video_srtp && taskinfo->video_srtp->tx.getCryptoTag() != 0 ? &taskinfo->video_srtp->tx : nullptr;
                SrtpChannel* rx = taskinfo->video_srtp && taskinfo->video_srtp->rx.getCryptoTag() != 0 ? &taskinfo->video_srtp->rx : nullptr;
                if (tx)
                {
                    // GRAB RTP HEADER
                    rtp_header.resize(sizeof(rtp_header_t), 0);
                    memcpy(rtp_header.data(), udp_send_video.buffer, sizeof(rtp_header_t) /*12*/);
                    // GRAB RTP PAYLOAD DATA
                    payload_data.resize(taskinfo->video_bytes_per_packet, 0);
                    memcpy(payload_data.data(), udp_send_video.buffer + sizeof(rtp_header_t), taskinfo->video_bytes_per_packet);

                    // ENCRYPT
                    rc = tx->processOutgoingPacket(taskinfo->video_seq_out, rtp_header, payload_data, video_out);
                    debugvfile.printHex("TXUACVIDEO -- processOutgoingPacket() rc == ", "", 0, rc, 0);
                }
                else
                {
                    // NOENCRYPTION
                    video_out.resize(sizeof(rtp_header_t) + taskinfo->video_bytes_per_packet, 0);
                    memcpy(video_out.data(), udp_send_video.buffer, sizeof(rtp_header_t) + taskinfo->video_bytes_per_packet);
                }

                /* now send the actual packet */
                rc = send(taskinfo->video_rtp_socket, video_out.data(), video_out.size(), 0);
                if (rc < 0)
                {
                    debugvfile.printHex("SEND FAILED: ", "", 0, rc, errno);

                    /* handle sending errors */
                    if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
                    {
                        next_wake = timenow_ms + 2; /* retry after short sleep */
                    }
                    else
                    {
                        /* this looks like a permanent error  - should we ignore ENETUNREACH? */
                        debugprint("closing rtp socket %d due to error %d in rtpstream_new_call callinfo=%p\n", taskinfo->video_rtp_socket, errno);
                        close(taskinfo->video_rtp_socket);
                        taskinfo->video_rtp_socket = -1;
                    }
                }
                else
                {
                    /* statistics - only count successful sends */
                    rtpstream_vbytes_out.fetch_add(taskinfo->video_bytes_per_packet + sizeof(rtp_header_t), std::memory_order_relaxed);
                    rtpstream_vpckts.fetch_add(1, std::memory_order_relaxed); // GLOBAL RTP packet counter
                    taskinfo->video_check_packets++; // the packets the RTP check checks

                    debugvfile.printHexUS("SIPP SUCCESS SEND LOG: ", video_out.data(), video_out.size(), rc, rtpstream_vpckts);

                    /* poll(), not select(): the socket may be >= FD_SETSIZE */
                    pfd.fd = taskinfo->video_rtp_socket;
                    rc = poll(&pfd, 1, 0); /* Never block */

                    if (rc > 0)
                    {
                        /* this is temp code - will have to reorganize if/when we include echo functionality */
                        /* just keep listening on rtp socket (is this really required?) - ignore any errors */
                        if (rx)
                        {
                            video_in_size = sizeof(rtp_header_t) + taskinfo->video_bytes_per_packet + rx->getAuthenticationTagSize();
                        }
                        else
                        {
                            // NOENCRYPTION
                            video_in_size = sizeof(rtp_header_t) + taskinfo->video_bytes_per_packet;
                        }

                        video_in.resize(video_in_size, 0);
                        while ((rc = recv(taskinfo->video_rtp_socket, video_in.data(), video_in.size(), 0)) >= 0)
                        {
                            /* for now we will just ignore any received data or receive errors */
                            /* separate code path for RTP echo */
                            rtpstream_vbytes_in.fetch_add(rc, std::memory_order_relaxed);
                            debugvfile.printHexUS("SIPP SUCCESS RECV LOG: ", video_in.data(), video_in.size(), rc, rtpstream_vpckts);
                        }

                        if (rx)
                        {
                            // DECRYPT
                            rtp_header.clear();
                            payload_data.clear();
                            video_seq_in = ntohs(((rtp_header_t*)video_in.data())->seq);
                            rc = rx->processIncomingPacket(video_seq_in, video_in, rtp_header, payload_data);
                            debugvfile.printHex("RXUACVIDEO -- processIncomingPacket() rc == ", "", 0, rc, 0);

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
                            video_in[10] = (host_ssrc >> 8) & 0xFF;
                            video_in[11] = host_ssrc & 0xFF;

                            memset(udp_recv_video.buffer, 0, sizeof(udp_recv_video));
                            memcpy(udp_recv_video.buffer, rtp_header.data(), rtp_header.size());
                            memcpy(udp_recv_video.buffer + sizeof(rtp_header_t), payload_data.data(), payload_data.size());
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
                            video_in[10] = (host_ssrc >> 8) & 0xFF;
                            video_in[11] = host_ssrc & 0xFF;

                            memset(udp_recv_video.buffer, 0, sizeof(udp_recv_video));
                            memcpy(udp_recv_video.buffer, video_in.data(), video_in.size());
                        }

                        // VALIDATION TEST
                        compresult = 0;
                        compresult = memcmp(udp_send_video.buffer + sizeof(rtp_header_t),
                                            udp_recv_video.buffer + sizeof(rtp_header_t),
                                            taskinfo->video_bytes_per_packet /* PAYLOAD comparison ONLY -- header EXCLUDED*/);
                        if (compresult == 0)
                        {
                            // SUCCESS
                            debugvfile.printHex("COMPARISON OK ", "", 0, taskinfo->video_comparison_errors, rtpstream_vpckts);
                            *comparison_vcheck = 0;
                        }
                        else
                        {
                            // FAILURE
                            taskinfo->video_comparison_errors++;
                            debugvfile.printHex("COMPARISON FAILED", "", 0, taskinfo->video_comparison_errors, rtpstream_vpckts);
                            *comparison_vcheck = 1;
                        }
                    }
                    else
                    {
                        taskinfo->video_comparison_errors++;
                        debugvfile.printHex("NODATA", "", 0, taskinfo->video_comparison_errors, rtpstream_vpckts);
                        *comparison_vcheck = 1;
                    }

                    /* advance playback pointer to next packet */
                    taskinfo->video_seq_out++;
                    /* must change if timer ticks per packet can be fractional */
                    taskinfo->last_video_timestamp += taskinfo->video_timeticks_per_packet;
                    taskinfo->video_file_bytes_left -= taskinfo->video_bytes_per_packet;
                    if (taskinfo->video_file_bytes_left > 0)
                    {
                        taskinfo->video_current_file_bytes += taskinfo->video_bytes_per_packet;
                    }
                    else
                    {
                        /* from the start of the file again: more than once
                         * in a packet, for a file shorter than a packet */
                        do
                        {
                            taskinfo->video_file_bytes_left += taskinfo->video_file_num_bytes;
                            if (taskinfo->video_loop_count > 0)
                            {
                                /* one less loop to play. -1 (infinite loops) will stay as is */
                                taskinfo->video_loop_count--;
                            }
                        } while (taskinfo->video_file_bytes_left <= 0);
                        taskinfo->video_current_file_bytes = taskinfo->video_file_bytes_start + taskinfo->video_file_num_bytes - taskinfo->video_file_bytes_left;
                    }
                    if (taskinfo->last_video_timestamp <= target_timestamp)
                    {
                        /* no sleep if we are behind */
                        next_wake = timenow_ms;
                    }
                } /* if (rc < 0) */
                pthread_mutex_unlock(&(taskinfo->mutex));
            } /* if (taskinfo->last_video_timestamp <= target_timestamp) */
            else
            {
                debugvfile.printHex("TIMESTAMP NOT QUITE RIGHT...", "", 0, 0, 0);
                *comparison_vcheck = -1;
            }
        } /* if (taskinfo->video_loop_count) */
        else
        {
          /* not busy playing back a file -  put possible rtp echo code here. */
        }
    }

    if (taskinfo->video_rtcp_socket != -1)
    {
        /* just keep listening on rtcp socket (is this really required?) - ignore any errors */
        while ((rc = recv(taskinfo->video_rtcp_socket, udp_recv_temp.buffer, sizeof(udp_recv_temp), 0)) >= 0)
        {
            /*
             * rtpstream_vbytes_in += rc;
             */
        }
    }

    return next_wake;
}

/* rtp_echo buffers of a playback thread, for all its calls */
struct rtpecho_buffers_t
{
    std::vector<unsigned char> msg;
    std::vector<unsigned char> rtp_header;
    std::vector<unsigned char> payload_data;
    std::vector<unsigned char> packet_in;
    std::vector<unsigned char> packet_out;
};

/* the most packets to echo for a call at a time, so that a flood on one
 * call holds neither its playback thread nor its mutex */
#define RTPECHO_MAX_BURST 32

/* rtp_echo: send the packets waiting on a call's audio or video RTP
 * socket back to where they came from, through its UAS SRTP contexts;
 * false if there is nothing more to watch on it */
static bool rtpstream_echotask(taskentry_t* taskinfo, bool video, rtpecho_buffers_t& buffers)
{
    const RtpEchoDebugFile& debugrefile = video ? debugrefilevideo : debugrefileaudio;
    const char* media = video ? "VIDEO" : "AUDIO";
    std::vector<unsigned char>& msg = buffers.msg;
    ssize_t nr;
    ssize_t ns;
    sipp_socklen_t len;
    struct sockaddr_storage remote_rtp_addr;
    int rc = 0;
    bool watch = true;
    std::vector<unsigned char>& rtp_header = buffers.rtp_header;
    std::vector<unsigned char>& payload_data = buffers.payload_data;
    std::vector<unsigned char>& packet_in = buffers.packet_in;
    std::vector<unsigned char>& packet_out = buffers.packet_out;
    unsigned short seq_num = 0;
    unsigned short host_flags = 0;
    unsigned short host_seqnum = 0;
    unsigned int host_timestamp = 0;
    unsigned int host_ssrc = 0;

    pthread_mutex_lock(&(taskinfo->mutex));
    rtpecho_t* echo = video ? taskinfo->video_echo : taskinfo->audio_echo;
    int sock = video ? taskinfo->video_rtp_socket : taskinfo->audio_rtp_socket;
    if (!(video ? taskinfo->video_srtp_echo_active : taskinfo->audio_srtp_echo_active) || !echo || sock == -1)
    {
        pthread_mutex_unlock(&(taskinfo->mutex));
        return false;
    }
    SrtpChannel& rx = echo->rx;
    SrtpChannel& tx = echo->tx;

    for (int i = 0; i < RTPECHO_MAX_BURST; i++)
    {
        len = sizeof(remote_rtp_addr);
        packet_in.resize(sizeof(rtp_header_t) + rx.getSrtpPayloadSize() + rx.getAuthenticationTagSize(), 0);
        nr = recvfrom(sock, packet_in.data(), packet_in.size(), MSG_DONTWAIT /* NON-BLOCKING */, (sockaddr *) (void *) &remote_rtp_addr, &len);

        if (nr < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // No more data to be read
                break;
            }
            if (errno == ECONNREFUSED)
            {
                // An ICMP port unreachable for an earlier echo: the peer
                // has closed its port, typically as its call ends.
                debugrefile.printf("%s echo peer port unreachable (ECONNREFUSED)...\n", media);
                continue;
            }
            // Other error occurred during read
            debugrefile.printf("Error on RTP echo reception - unable to perform rtpstream %s echo - errno = %d\n", media, errno);
            echo->error = true;
            watch = false;
            break;
        }

        // Good to go -- buffer should contain "nr" bytes
        seq_num = (packet_in[2] << 8) | packet_in[3];

        debugrefile.printReceived(packet_in.data(), nr);
        /* The packet to echo, without SRTP. */
        size_t plain_len = nr;
        if (rx.getCryptoTag() != 0)
        {
            rtp_header.clear();
            payload_data.clear();

            // DECRYPT
            rx.setSSRC(ntohl(((rtp_header_t*)packet_in.data())->ssrc_id)); // set incoming SSRC id
            rc = rx.processIncomingPacket(seq_num, packet_in, rtp_header, payload_data);
            debugrefile.printf("RXUAS%s -- processIncomingPacket() rc == %d\n", media, rc);

            host_flags = ntohs(((rtp_header_t*)packet_in.data())->flags);
            host_seqnum = ntohs(((rtp_header_t*)packet_in.data())->seq);
            host_timestamp = ntohl(((rtp_header_t*)packet_in.data())->timestamp);
            host_ssrc = ntohl(((rtp_header_t*)packet_in.data())->ssrc_id);

            packet_in[0] = (host_flags >> 8) & 0xFF;
            packet_in[1] = host_flags & 0xFF;
            packet_in[2] = (host_seqnum >> 8) & 0xFF;
            packet_in[3] = host_seqnum & 0xFF;
            packet_in[4] = (host_timestamp >> 24) & 0xFF;
            packet_in[5] = (host_timestamp >> 16) & 0xFF;
            packet_in[6] = (host_timestamp >> 8) & 0xFF;
            packet_in[7] = host_timestamp & 0xFF;
            packet_in[8] = (host_ssrc >> 24) & 0xFF;
            packet_in[9] = (host_ssrc >> 16) & 0xFF;
            packet_in[10] = (host_ssrc >> 8) & 0xFF;
            packet_in[11] = host_ssrc & 0xFF;

            memcpy(msg.data(), rtp_header.data(), rtp_header.size());
            memcpy(msg.data() + sizeof(rtp_header_t), payload_data.data(), payload_data.size());
            plain_len = sizeof(rtp_header_t) + payload_data.size();
        }
        else
        {
            memcpy(msg.data(), packet_in.data(), nr);
        }

        if (tx.getCryptoTag() != 0)
        {
            packet_out.clear();

            // ZERO WHAT THE PACKET DID NOT FILL
            if (plain_len < sizeof(rtp_header_t) + tx.getSrtpPayloadSize())
            {
                memset(msg.data() + plain_len, 0, sizeof(rtp_header_t) + tx.getSrtpPayloadSize() - plain_len);
            }

            // GRAB RTP HEADER
            rtp_header.resize(sizeof(rtp_header_t), 0);
            memcpy(rtp_header.data(), msg.data(), sizeof(rtp_header_t) /*12*/);
            // GRAB RTP PAYLOAD DATA
            payload_data.resize(tx.getSrtpPayloadSize(), 0);
            memcpy(payload_data.data(), msg.data() + sizeof(rtp_header_t), tx.getSrtpPayloadSize());

            // ENCRYPT
            tx.setSSRC(ntohl(((rtp_header_t*)packet_in.data())->ssrc_id)); // set incoming SSRC id
            rc = tx.processOutgoingPacket(seq_num, rtp_header, payload_data, packet_out);
            debugrefile.printf("TXUAS%s -- processOutgoingPacket() rc == %d\n", media, rc);
        }
        else
        {
            /* Plain RTP goes back as it came. */
            packet_out.assign(msg.data(), msg.data() + plain_len);
        }

        ns = sendto(sock, packet_out.data(), packet_out.size(), MSG_DONTWAIT, (sockaddr *) (void *) &remote_rtp_addr, len);

        if (ns != nr) {
            debugrefile.printf("DATA SUCCESSFULLY SENT [%s] seq_num = [%u] -- MISMATCHED RECV/SENT BYTE COUNT -- errno = %d nr = %d ns = %d\n",
                               media, seq_num, errno, int(nr), int(ns));
        } else {
            debugrefile.printf("DATA SUCCESSFULLY SENT [%s] seq_num = [%u]...\n", media, seq_num);
        }

        if (video) {
            rtp2_pckts.fetch_add(1, std::memory_order_relaxed);
            rtp2_bytes.fetch_add(ns, std::memory_order_relaxed);
        } else {
            rtp_pckts.fetch_add(1, std::memory_order_relaxed);
            rtp_bytes.fetch_add(ns, std::memory_order_relaxed);
        }
    }
    pthread_mutex_unlock(&(taskinfo->mutex));

    return watch;
}

#ifdef PCAPPLAY
/* Send the packets of a call's pcap plays that are due, and bring
 * *waketime_us forward to when the next one is */
static void rtpstream_playpcaptask(taskentry_t* taskinfo, threaddata_t* threaddata,
                                   unsigned long long* waketime_us)
{
    unsigned long long due_us;

    pthread_mutex_lock(&(taskinfo->mutex));
    for (play_args_t& play : taskinfo->pcap_plays)
    {
        if (!play.pcap)
        {
            continue;
        }
        if (send_packets_due(threaddata->pcap_socket, &play, getmicroseconds(), &due_us))
        {
            if (*waketime_us > due_us)
            {
                *waketime_us = due_us;
            }
        }
        else
        {
            send_packets_end(&play);
        }
    }
    pthread_mutex_unlock(&(taskinfo->mutex));
}
#endif

/* code checked */
static void* rtpstream_playback_thread(void* params)
{
    threaddata_t   *threaddata = (threaddata_t *) params;
    taskentry_t    *taskinfo;
    unsigned int   taskindex;

    unsigned long  timenow_ms;
    unsigned long long waketime_us;
    long long      sleeptime_us;
    int            timeout_ms;
    char           wake_buffer[64];

    unsigned long  comparison_acheck;
    unsigned long  comparison_vcheck;
    unsigned long  rtpresult;
    /* the RTP sockets of the calls to echo, and their call, video or not */
    std::vector<struct pollfd> echo_fds;
    std::vector<std::pair<taskentry_t*, bool>> echo_tasks;
    rtpecho_buffers_t echo_buffers;

    comparison_acheck = 0;
    comparison_vcheck = 0;
    rtpresult = 0; /* the patterns that failed their RTP check, a bit each */
    echo_buffers.msg.resize(media_bufsize);

    rtpstream_numthreads++;

    while (!threaddata->exit_flag)
    {
        timenow_ms = getmilliseconds();
        waketime_us = (timenow_ms + 100) * 1000ULL; /* default sleep 100ms */
        /* first in the poll set, the pipe that a new pcap play writes to */
        echo_fds.push_back({threaddata->wake_fds[0], POLLIN, 0});
        echo_tasks.push_back({nullptr, false});

        /* iterate through tasks and handle playback and other actions */
        for (taskindex = 0; taskindex < threaddata->num_tasks.load(std::memory_order_acquire); taskindex++)
        {
            debugafile.printHex("----DEBUG CURRENTTASK/NUMTASKS----", "", 0, taskindex, threaddata->num_tasks.load(std::memory_order_acquire));
            debugvfile.printHex("----DEBUG CURRENTTASK/NUMTASKS----", "", 0, taskindex, threaddata->num_tasks.load(std::memory_order_acquire));
            taskinfo = threaddata->tasklist[taskindex];
            /* acquire: with what the call stored before it set a flag */
            int flags = taskinfo->flags.load(std::memory_order_acquire);
            if (flags & TI_CONFIGFLAGS)
            {
                if (flags & TI_KILLTASK)
                {
                    /* remove this task entry and release its resources */
                    pthread_mutex_lock(&(threaddata->tasklist_mutex));
                    threaddata->tasklist[taskindex--] = threaddata->tasklist[--threaddata->num_tasks];
                    threaddata->del_pending--;   /* must decrease del_pending after num_tasks */
                    pthread_mutex_unlock(&(threaddata->tasklist_mutex));
                    /* the call ended: the verdict of its RTP check */
                    rtpstream_check_verdict(taskinfo, false, &rtpresult);
                    rtpstream_check_verdict(taskinfo, true, &rtpresult);
                    delete taskinfo;
                    continue;
                }
                /* handle any other config related flags */
                rtpstream_process_task_flags(taskinfo, &rtpresult);
            }

            /* should we update current time inbetween tasks? */
            if (taskinfo->nextwake_ms <= timenow_ms)
            {
                /* task needs to execute now */
                taskinfo->nextwake_ms = rtpstream_playrtptask(taskinfo, timenow_ms, &comparison_acheck, &comparison_vcheck, taskindex);

                if (comparison_acheck == 1)
                {
                    taskinfo->audio_check_failures++;
                    debugafile.printHex("----FAILED RTP CHECK----", "", 0, taskinfo->audio_check_failures, rtpstream_apckts);
                }
                else
                {
                    debugafile.printHex("----PASSED RTP CHECK----", "", 0, taskinfo->audio_check_failures, rtpstream_apckts);
                }

                if (comparison_vcheck == 1)
                {
                    taskinfo->video_check_failures++;
                    debugvfile.printHex("----FAILED RTP CHECK----", "", 0, taskinfo->video_check_failures, rtpstream_vpckts);
                }
                else
                {
                    debugvfile.printHex("----PASSED RTP CHECK----", "", 0, taskinfo->video_check_failures, rtpstream_vpckts);
                }
            }
            if (waketime_us > taskinfo->nextwake_ms * 1000ULL)
            {
                waketime_us = taskinfo->nextwake_ms * 1000ULL;
            }
#ifdef PCAPPLAY
            rtpstream_playpcaptask(taskinfo, threaddata, &waketime_us);
#endif

            /* watch the sockets of the calls to echo */
            pthread_mutex_lock(&(taskinfo->mutex));
            if (taskinfo->audio_srtp_echo_active && taskinfo->audio_rtp_socket != -1)
            {
                echo_fds.push_back({taskinfo->audio_rtp_socket, POLLIN, 0});
                echo_tasks.push_back({taskinfo, false});
            }
            if (taskinfo->video_srtp_echo_active && taskinfo->video_rtp_socket != -1)
            {
                echo_fds.push_back({taskinfo->video_rtp_socket, POLLIN, 0});
                echo_tasks.push_back({taskinfo, true});
            }
            pthread_mutex_unlock(&(taskinfo->mutex));
        }
        /* sleep until the next iteration of the playback loop, echoing
         * the packets that arrive meanwhile on the sockets that have one */
        for (;;)
        {
            sleeptime_us = (long long) (waketime_us - getmicroseconds());
            /* poll() counts in milliseconds: sleep the rest without it */
            timeout_ms = sleeptime_us > 0 ? (int) (sleeptime_us / 1000) : 0;
            if ((timeout_ms > 0 || echo_fds.size() > 1) &&
                poll(echo_fds.data(), echo_fds.size(), timeout_ms) > 0)
            {
                if (echo_fds[0].revents)
                {
                    /* a new play, pcap play or echo: start it now */
                    while (read(threaddata->wake_fds[0], wake_buffer, sizeof(wake_buffer)) > 0)
                    {
                    }
                    break;
                }
                for (size_t i = 1; i < echo_fds.size(); i++)
                {
                    if (echo_fds[i].revents &&
                        !rtpstream_echotask(echo_tasks[i].first, echo_tasks[i].second, echo_buffers))
                    {
                        echo_fds[i].fd = -1; /* poll() skips it */
                    }
                }
                if (timeout_ms > 0)
                {
                    continue;
                }
            }
            if (timeout_ms == 0)
            {
                sleeptime_us = (long long) (waketime_us - getmicroseconds());
                if (sleeptime_us > 0)
                {
                    usleep(sleeptime_us);
                }
                break;
            }
        }
        echo_fds.clear();
        echo_tasks.clear();
    }

    /* the verdicts of the calls still here */
    for (taskindex = 0; taskindex < threaddata->num_tasks.load(std::memory_order_acquire); taskindex++)
    {
        taskinfo = threaddata->tasklist[taskindex];
        rtpstream_check_verdict(taskinfo, false, &rtpresult);
        rtpstream_check_verdict(taskinfo, true, &rtpresult);
    }

    /* Free all task and thread resources and exit the thread */
    for (taskindex = 0; taskindex < threaddata->num_tasks.load(std::memory_order_acquire); taskindex++)
    {
        /* check if we should delete this thread, else let owner call clear it */
        /* small chance of race condition in this code */
        taskinfo = threaddata->tasklist[taskindex];
        if (taskinfo->flags & TI_KILLTASK) {
            delete taskinfo;
        } else {
            taskinfo->parent_thread = nullptr; /* no longer associated with a thread */
        }
    }
    close(threaddata->wake_fds[0]);
    close(threaddata->wake_fds[1]);
#ifdef PCAPPLAY
    if (threaddata->pcap_socket != -1)
    {
        close(threaddata->pcap_socket);
    }
#endif
    pthread_mutex_destroy(&(threaddata->tasklist_mutex));
    delete threaddata;
    rtpstream_numthreads--;

    // PTHREAD EXIT...
    debugafile.printHex("PLAYBACK THREAD EXITING...", "", 0, rtpresult, 0);
    debugvfile.printHex("PLAYBACK THREAD EXITING...", "", 0, rtpresult, 0);
    pthread_exit((void*) rtpresult);

    return nullptr;
}

/* Wake a playback thread up, if there is one, to start a new play, pcap
 * play or echo now and not after its sleep of up to 100 ms; a full pipe
 * means it wakes up anyway */
static void rtpstream_wake(threaddata_t* threaddata)
{
    if (threaddata && write(threaddata->wake_fds[1], "", 1) < 0 && errno != EAGAIN) {
        WARNING_NO("Could not wake an RTP playback thread up");
    }
}

/* code checked */
static int rtpstream_start_task(rtpstream_callinfo_t* callinfo)
{
    int           ready_index;
    threaddata_t  **threadlist;
    threaddata_t  *threaddata;
    pthread_t     threadID;

    /* safety check... */
    if (!callinfo->taskinfo) {
        return 0;
    }

    /* we count on the fact that only one thread can add/remove playback tasks */
    /* thus we don't have mutexes to protect the thread list objects.          */
    for (ready_index = 0; ready_index < num_ready_threads; ready_index++) {
        /* ready threads have a spare task slot or should have one very shortly */
        /* if we find a task with no spare slots, just skip to the next one.    */
        if (ready_threads[ready_index]->num_tasks < ready_threads[ready_index]->max_tasks) {
            /* we found a thread with an open task slot. */
            break;
        }
    }

    if (ready_index == num_ready_threads) {
        /* did not find a thread with spare task slots, thus we create one here */
        if (num_ready_threads >= ready_threads_max) {
            /* need to allocate more memory for thread list */
            ready_threads_max += RTPSTREAM_THREADBLOCKSIZE;
            threadlist = (threaddata_t **) realloc(ready_threads, sizeof(*ready_threads) * ready_threads_max);
            if (!threadlist) {
                /* could not allocate bigger block... worry [about it later] */
                ready_threads_max -= RTPSTREAM_THREADBLOCKSIZE;
                return 0;
            }
            ready_threads = threadlist;
        }
        /* create and initialise data structure for new thread */
        threaddata = new threaddata_t(rtp_tasks_per_thread);
        if (pipe(threaddata->wake_fds)) {
            delete threaddata;
            return 0;
        }
        fcntl(threaddata->wake_fds[0], F_SETFL, O_NONBLOCK);
        fcntl(threaddata->wake_fds[1], F_SETFL, O_NONBLOCK);
        pthread_mutex_init(&(threaddata->tasklist_mutex), nullptr);
        /* create the thread itself */
        if (pthread_create(&threadID, nullptr, rtpstream_playback_thread, threaddata)) {
            /* error creating the thread */
            close(threaddata->wake_fds[0]);
            close(threaddata->wake_fds[1]);
            delete threaddata;
            return 0;
        }

        threaddata->id = threadID;

        debugafile.printHex("CREATED THREAD: ", "", 0, getThreadId(threadID), 0);
        debugvfile.printHex("CREATED THREAD: ", "", 0, getThreadId(threadID), 0);

        /* Add thread to list of ready (spare capacity) threads */
        ready_threads[num_ready_threads++] = threaddata;
    }

    /* now add new task to a spare slot in our thread tasklist */
    threaddata = ready_threads[ready_index];
    callinfo->taskinfo->parent_thread = threaddata;
    callinfo->threadID = threaddata->id;
    pthread_mutex_lock(&(threaddata->tasklist_mutex));
    /* The task first, then the count: a count ahead of its task was a
     * null one. */
    unsigned int num_tasks = threaddata->num_tasks.load(std::memory_order_relaxed);
    threaddata->tasklist[num_tasks] = callinfo->taskinfo;
    threaddata->num_tasks.store(num_tasks + 1, std::memory_order_release);
    pthread_mutex_unlock(&(threaddata->tasklist_mutex));

    /* this check relies on playback thread to decrement num_tasks before */
    /* decrementing del_pending -- else we need to lock before this test  */
    if ((threaddata->del_pending == 0) && (threaddata->num_tasks >= threaddata->max_tasks)) {
        /* move this thread to the busy list - no free task slots */
        /* first check if the busy list is big enough to hold new thread */
        if (num_busy_threads >= busy_threads_max) {
            /* need to allocate more memory for thread list */
            busy_threads_max += RTPSTREAM_THREADBLOCKSIZE;
            threadlist = (threaddata_t **) realloc(busy_threads, sizeof(*busy_threads) * busy_threads_max);
            if (!threadlist) {
                /* could not allocate bigger block... leave thread in ready list */
                busy_threads_max -= RTPSTREAM_THREADBLOCKSIZE;
                return 1; /* success, sort of */
            }
            busy_threads = threadlist;
        }
        /* add to busy list */
        threaddata->busy_list_index = num_busy_threads;
        busy_threads[num_busy_threads++] = threaddata;
        /* remove from ready list */
        ready_threads[ready_index] = ready_threads[--num_ready_threads];
    }

    return 1; /* done! */
}

/* code checked */
static void rtpstream_stop_task(rtpstream_callinfo_t* callinfo)
{
    threaddata_t  **threadlist;
    taskentry_t   *taskinfo = callinfo->taskinfo;
    int           busy_index;

    if (taskinfo)
    {
#ifdef PCAPPLAY
        /* no pcap packet of the call after it ends */
        pthread_mutex_lock(&(taskinfo->mutex));
        for (play_args_t& play : taskinfo->pcap_plays)
        {
            send_packets_end(&play);
        }
        pthread_mutex_unlock(&(taskinfo->mutex));
#endif
        if (taskinfo->parent_thread)
        {
            /* this call's task is registered with an executing thread */
            /* first move owning thread to the ready list - will be ready soon */
            busy_index = taskinfo->parent_thread->busy_list_index;
            if (busy_index >= 0)
            {
                /* make sure we have enough entries in ready list */
                if (num_ready_threads >= ready_threads_max)
                {
                    /* need to allocate more memory for thread list */
                    ready_threads_max += RTPSTREAM_THREADBLOCKSIZE;
                    threadlist = (threaddata_t **) realloc(ready_threads, sizeof(*ready_threads) * ready_threads_max);
                    if (!threadlist)
                    {
                        /* could not allocate bigger block... reset max threads */
                        /* this is a problem - ready thread gets "lost" on busy list */
                        ready_threads_max -= RTPSTREAM_THREADBLOCKSIZE;
                    }
                    else
                    {
                        ready_threads = threadlist;
                    }
                }

                if (num_ready_threads < ready_threads_max)
                {
                    /* OK, got space on ready list, move to ready list */
                    busy_threads[busy_index]->busy_list_index = -1;
                    ready_threads[num_ready_threads++] = busy_threads[busy_index];
                    num_busy_threads--;
                    /* fill up gap in the busy thread list */
                    if (busy_index != num_busy_threads)
                    {
                        busy_threads[busy_index] = busy_threads[num_busy_threads];
                        busy_threads[busy_index]->busy_list_index = busy_index;
                    }
                }
            }
            /* then ask the thread to destroy this task (and its memory) */
            pthread_mutex_lock(&(taskinfo->parent_thread->tasklist_mutex));
            taskinfo->parent_thread->del_pending++;
            taskinfo->flags |= TI_KILLTASK;
            pthread_mutex_unlock(&(taskinfo->parent_thread->tasklist_mutex));

            // PTHREAD IS NOT JOINABLE HERE...
        }
        else
        {
            /* no playback thread owner, just free it */
            delete taskinfo;
        }
        callinfo->taskinfo = nullptr;
    }
}

/* code checked */
int rtpstream_new_call(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_new_call callinfo=%p\n", callinfo);

    taskentry_t  *taskinfo;

    /* general init */
    memset(callinfo, 0, sizeof(*callinfo));

    // zero remote audio/video ports
    callinfo->remote_audioport = 0;
    callinfo->remote_videoport = 0;

    taskinfo = new taskentry_t();
    callinfo->taskinfo = taskinfo;

    taskinfo->flags = TI_NULLIP;

    /* rtp stream members */
    taskinfo->audio_ssrc_id = global_ssrc_id++;
    taskinfo->video_ssrc_id = global_ssrc_id++;
    /* no echo yet: not even of the packet before the first (seq 0) */
    taskinfo->audio_seq_echoed = (unsigned short) (taskinfo->audio_seq_out - 2);

    /* pthread mutexes */
    pthread_mutex_init(&(callinfo->taskinfo->mutex), nullptr);

    return 1;
}

/* code checked */
void rtpstream_end_call(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_end_call callinfo=%p\n", callinfo);

    /* stop playback thread(s) for this call */
    rtpstream_stop_task(callinfo);

    // zero remote audio/video ports
    callinfo->remote_audioport = 0;
    callinfo->remote_videoport = 0;
}

/* code checked */
int rtpstream_cache_file(char* filename,
                          int mode /* 0: FILE -- 1: PATTERN */,
                          int id,
                          int bytes_per_packet,
                          int stream_type)
{
    int           count = 0;
    cached_file_t *newfilecachelist;
    cached_pattern_t *newpatterncachelist;
    char          *filecontents;
    struct stat   statbuffer;
    FILE          *f;

    debugprint("rtpstream_cache_file filename = %s mode = %d id = %d bytes_per_packet = %d stream_type = %d\n", filename, mode, id, bytes_per_packet, stream_type);

    if (rtpcheck_debug)
    {
        if ((stream_type == 0) && !debugafile.open("debugafile"))
        {
            /* error encountered opening audio debug file */
            return -1;
        }
        if ((stream_type == 1) && !debugvfile.open("debugvfile"))
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
        while (count < num_cached_patterns) {
            if (cached_patterns[count].id == id &&
                    cached_patterns[count].filesize == bytes_per_packet) {
                /* found the pattern already filled. just return index */
                return count;
            }
            count++;
        }

        if (!(num_cached_patterns%RTPSTREAM_FILESPERBLOCK)) {
            /* Time to allocate more memory for the next block of files */
            newpatterncachelist = (cached_pattern_t*) realloc(cached_patterns, sizeof(*cached_patterns) * (num_cached_patterns + RTPSTREAM_FILESPERBLOCK));
            if (!newpatterncachelist) {
                /* out of memory */
                return -1;
            }
            cached_patterns = newpatterncachelist;
        }

        cached_patterns[num_cached_patterns].bytes = (char*)malloc(bytes_per_packet);
        if (cached_patterns[num_cached_patterns].bytes == nullptr)
        {
            /* out of memory */
            return -1;
        }

        if (id == 1)
        {
            memset(cached_patterns[num_cached_patterns].bytes, PATTERN1, bytes_per_packet);
        }
        else if (id == 2)
        {
            memset(cached_patterns[num_cached_patterns].bytes, PATTERN2, bytes_per_packet);
        }
        else if (id == 3)
        {
            memset(cached_patterns[num_cached_patterns].bytes, PATTERN3, bytes_per_packet);
        }
        else if (id == 4)
        {
            memset(cached_patterns[num_cached_patterns].bytes, PATTERN4, bytes_per_packet);
        }
        else if (id == 5)
        {
            memset(cached_patterns[num_cached_patterns].bytes, PATTERN5, bytes_per_packet);
        }
        else if (id == 6)
        {
            memset(cached_patterns[num_cached_patterns].bytes, PATTERN6, bytes_per_packet);
        }

        cached_patterns[num_cached_patterns].filesize = bytes_per_packet;
        cached_patterns[num_cached_patterns].id = id;

        return num_cached_patterns++; /* one new cached pattern */
    }
    else
    {
        /* cached file entries are stored in a dynamically grown array. */
        /* could use a binary (or avl) tree but number of files should  */
        /* be small and doesn't really justify the effort.              */
        while (count < num_cached_files) {
            if (!strcmp(cached_files[count].filename, filename)) {
                /* found the file already loaded. just return index */
                return count;
            }
            count++;
        }

        /* Allocate memory and load file */
        if (stat(filename, &statbuffer)) {
            /* could not get file information */
            return -1;
        }
        f = fopen(filename, "rb");
        if (!f) {
            /* could not open file */
            return -1;
        }

        filecontents = (char *)malloc(statbuffer.st_size);
        if (!filecontents) {
            fclose(f);
            /* could not alloc mem */
            return -1;
        }
        if (!fread(filecontents, statbuffer.st_size, 1, f)) {
            /* could not read file */
            free(filecontents);
            fclose(f);
            return -1;
        }
        fclose(f);

        if (!(num_cached_files%RTPSTREAM_FILESPERBLOCK)) {
            /* Time to allocate more memory for the next block of files */
            newfilecachelist = (cached_file_t*) realloc(cached_files, sizeof(*cached_files) * (num_cached_files + RTPSTREAM_FILESPERBLOCK));
            if (!newfilecachelist) {
                /* out of memory */
                free(filecontents);
                return -1;
            }
            cached_files = newfilecachelist;
        }
        cached_files[num_cached_files].bytes = filecontents;
        strncpy(cached_files[num_cached_files].filename, filename, sizeof(cached_files[num_cached_files].filename) - 1);
        cached_files[num_cached_files].filesize = statbuffer.st_size;
        return num_cached_files++;
    }
}

static int rtpstream_setsocketoptions(int sock)
{
    /* set socket non-blocking */
    int flags = fcntl(sock, F_GETFL, 0);
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        return 0;
    }

    /* set buffer size */
    unsigned int buffsize = rtp_buffsize;

    /* Increase buffer sizes for this sockets */
    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&buffsize, sizeof(buffsize))) {
        return 0;
    }
    if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&buffsize, sizeof(buffsize))) {
        return 0;
    }

    return 1; /* success */
}

/* code checked */
static int rtpstream_get_localport(int* rtpsocket, int* rtcpsocket)
{
    int port_number = 0;
    int tries;
    struct sockaddr_storage address;
    int max_tries = (min_rtp_port < (max_rtp_port - 2)) ? (max_rtp_port - min_rtp_port) : 1;

    debugprint("rtpstream_get_localport\n");

    if (next_rtp_port == 0) {
        next_rtp_port = min_rtp_port;
    }

    /* initialise address family and IP address for media socket */
    memset(&address, 0, sizeof(address));
    address.ss_family = media_ip_is_ipv6 ? AF_INET6 : AF_INET;
    if ((media_ip_is_ipv6?
         inet_pton(AF_INET6, media_ip, &((_RCAST(struct sockaddr_in6 *, &address))->sin6_addr)):
         inet_pton(AF_INET, media_ip, &((_RCAST(struct sockaddr_in *, &address))->sin_addr))) != 1) {
        WARNING("Could not set up media IP for RTP streaming");
        return 0;
    }

    /* create new UDP listen socket */
    *rtpsocket = socket(media_ip_is_ipv6?PF_INET6:PF_INET, SOCK_DGRAM, 0);
    if (*rtpsocket == -1) {
        WARNING("Could not open socket for RTP streaming: %s", strerror(errno));
        return 0;
    }

    for (tries = 0; tries < max_tries; tries++) {
        /* try a sequence of port numbers until we find one where we can bind    */
        /* should normally be the first port we try, unless we have long-running */
        /* calls or somebody else is nicking ports.                              */
        port_number = next_rtp_port;

        /* skip rtp ports in multiples of 2 (allow for rtp plus rtcp) */
        next_rtp_port += 2;
        if (next_rtp_port > (max_rtp_port - 1)) {
            next_rtp_port = min_rtp_port;
        }

        sockaddr_update_port(&address, port_number);
        if (::bind(*rtpsocket, (sockaddr*)&address,
                   socklen_from_addr(&address)) == 0) {
            break;
        }
    }

    /* Exit here if we didn't get a suitable port for rtp stream */
    if (tries == max_tries) {
        close(*rtpsocket);
        *rtpsocket = -1;
        WARNING("Could not bind port for RTP streaming after %d tries", tries);
        return 0;
    }

    if (!rtpstream_setsocketoptions(*rtpsocket)) {
        close(*rtpsocket);
        *rtpsocket = -1;
        WARNING("Could not set socket options for RTP streaming");
        return 0;
    }

    /* create socket for rtcp - ignore any errors, we only bind so we
     * won't send icmp-port-unreachable when rtcp arrives */
    *rtcpsocket = socket(media_ip_is_ipv6?PF_INET6:PF_INET, SOCK_DGRAM, 0);
    if (*rtcpsocket != -1 && port_number > 0) {
        /* try to bind it to our preferred address */
        sockaddr_update_port(&address, port_number + 1);
        if (::bind(*rtcpsocket, (sockaddr *) (void *)&address,
                   socklen_from_addr(&address)) != 0) {
            /* could not bind the rtcp socket to required port. so we delete it */
            close(*rtcpsocket);
            *rtcpsocket = -1;
        } else if (!rtpstream_setsocketoptions(*rtcpsocket)) {
            close(*rtcpsocket);
            *rtcpsocket = -1;
        }
    }

    return port_number;
}

/* code checked */
int rtpstream_get_local_audioport(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_get_local_audioport callinfo=%p", callinfo);

    int   rtp_socket;
    int   rtcp_socket;

    if (!callinfo->taskinfo) {
        return 0;
    }

    if (callinfo->local_audioport) {
        /* already a port assigned to this call */
        debugprint(" ==> %d\n", callinfo->local_audioport);
        return callinfo->local_audioport;
    }

    callinfo->local_audioport = rtpstream_get_localport(&rtp_socket, &rtcp_socket);

    debugprint(" ==> %d\n", callinfo->local_audioport);

    /* assign rtp and rtcp sockets to callinfo. must assign rtcp socket first */
    callinfo->taskinfo->audio_rtcp_socket = rtcp_socket;
    callinfo->taskinfo->audio_rtp_socket = rtp_socket;

    /* start playback task if not already started */
    if (!callinfo->taskinfo->parent_thread) {
        if (!rtpstream_start_task(callinfo)) {
            /* error starting playback task */
            return 0;
        }
    }

    /* make sure the new socket gets bound to destination address (if any) */
    callinfo->taskinfo->flags |= TI_RECONNECTSOCKET;

    return callinfo->local_audioport;
}

/* code checked */
int rtpstream_get_local_videoport(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_get_local_videoport callinfo=%p", callinfo);

    int   rtp_socket;
    int   rtcp_socket;

    if (!callinfo->taskinfo) {
        return 0;
    }

    if (callinfo->local_videoport) {
        /* already a port assigned to this call */
        debugprint(" ==> %d\n", callinfo->local_videoport);
        return callinfo->local_videoport;
    }

    callinfo->local_videoport = rtpstream_get_localport(&rtp_socket, &rtcp_socket);

    debugprint(" ==> %d\n", callinfo->local_videoport);

    /* assign rtp and rtcp sockets to callinfo. must assign rtcp socket first */
    callinfo->taskinfo->video_rtcp_socket = rtcp_socket;
    callinfo->taskinfo->video_rtp_socket = rtp_socket;

    /* start playback task if not already started */
    if (!callinfo->taskinfo->parent_thread) {
        if (!rtpstream_start_task(callinfo)) {
            /* error starting playback task */
            return 0;
        }
    }

    /* make sure the new socket gets bound to destination address (if any) */
    callinfo->taskinfo->flags |= TI_RECONNECTSOCKET;

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

    taskinfo = callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return;
    }

    nonzero_ip = 0;
    taskinfo->flags |= TI_NULLIP;  /// TODO: this (may) cause a gap in playback, if playback thread gets to exec while this is set and before new IP is checked.

    /* test that media ip address version match remote ip address version? */

    /* initialise address family and IP address for remote socket */
    memset(&address, 0, sizeof(address));
    if (media_ip_is_ipv6) {
        /* process ipv6 address */
        address.ss_family = AF_INET6;
        ip6_addr = &((_RCAST(struct sockaddr_in6 *, &address))->sin6_addr);
        if (inet_pton(AF_INET6, ip_addr, ip6_addr) == 1) {
            for (count = 0; count < sizeof(*ip6_addr); count++) {
                if (((char*)ip6_addr)[count]) {
                    nonzero_ip = 1;
                    break;
                }
            }
        }
    } else {
        /* process ipv4 address */
        address.ss_family = AF_INET;
        ip4_addr = &((_RCAST(struct sockaddr_in *, &address))->sin_addr);
        if (inet_pton(AF_INET, ip_addr, ip4_addr) == 1) {
            for (count = 0; count < sizeof(*ip4_addr); count++) {
                if (((char*)ip4_addr)[count]) {
                    nonzero_ip = 1;
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
    pthread_mutex_lock(&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset(&(taskinfo->remote_audio_rtp_addr), 0, sizeof(taskinfo->remote_audio_rtp_addr));
    memset(&(taskinfo->remote_audio_rtcp_addr), 0, sizeof(taskinfo->remote_audio_rtcp_addr));
    memset(&(taskinfo->remote_video_rtp_addr), 0, sizeof(taskinfo->remote_video_rtp_addr));
    memset(&(taskinfo->remote_video_rtcp_addr), 0, sizeof(taskinfo->remote_video_rtcp_addr));

    /* Audio */
    if (audio_port) {
        // store remote audio port for later reference
        callinfo->remote_audioport = audio_port;
        sockaddr_update_port(&address, audio_port);
        memcpy(&(taskinfo->remote_audio_rtp_addr), &address, sizeof(address));

        sockaddr_update_port(&address, audio_port + 1);
        memcpy(&(taskinfo->remote_audio_rtcp_addr), &address, sizeof(address));

        taskinfo->flags &= ~TI_NULL_AUDIOIP;
    }

    /* Video */
    if (video_port) {
        // store remote video port for later reference
        callinfo->remote_videoport = video_port;
        sockaddr_update_port(&address, video_port);
        memcpy(&(taskinfo->remote_video_rtp_addr), &address, sizeof(address));

        sockaddr_update_port(&address, video_port + 1);
        memcpy(&(taskinfo->remote_video_rtcp_addr), &address, sizeof(address));

        taskinfo->flags &= ~TI_NULL_VIDEOIP;
    }

    taskinfo->flags |= TI_RECONNECTSOCKET;

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock(&(taskinfo->mutex));

    /* may want to start a playback (listen) task here if no task running? */
    /* only makes sense if we decide to send 0-filled packets on idle */
}

int rtpstream_set_srtp_audio_local(rtpstream_callinfo_t* callinfo, SrtpInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo = callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug && !debuglsrtpafile.open())
    {
        /* error encountered opening local srtp debug file */
        return -1;
    }

    debuglsrtpafile.printCrypto(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock(&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset(&(taskinfo->local_srtp_audio_params), 0, sizeof(taskinfo->local_srtp_audio_params));

    /* Audio */
    if (p.found) {
        taskinfo->local_srtp_audio_params.found = true;
        taskinfo->local_srtp_audio_params.primary_cryptotag = p.primary_cryptotag;
        taskinfo->local_srtp_audio_params.secondary_cryptotag = p.secondary_cryptotag;
        strcpy(taskinfo->local_srtp_audio_params.primary_cryptosuite, p.primary_cryptosuite);
        strcpy(taskinfo->local_srtp_audio_params.secondary_cryptosuite, p.secondary_cryptosuite);
        strcpy(taskinfo->local_srtp_audio_params.primary_cryptokeyparams, p.primary_cryptokeyparams);
        strcpy(taskinfo->local_srtp_audio_params.secondary_cryptokeyparams, p.secondary_cryptokeyparams);
        taskinfo->local_srtp_audio_params.primary_unencrypted_srtp = p.primary_unencrypted_srtp;
        taskinfo->local_srtp_audio_params.secondary_unencrypted_srtp = p.secondary_unencrypted_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock(&(taskinfo->mutex));

    return 0;
}

int rtpstream_set_srtp_audio_remote(rtpstream_callinfo_t* callinfo, SrtpInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo = callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug && !debugrsrtpafile.open())
    {
        /* error encountered opening remote srtp debug file */
        return -1;
    }

    debugrsrtpafile.printCrypto(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock(&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset(&(taskinfo->remote_srtp_audio_params), 0, sizeof(taskinfo->remote_srtp_audio_params));

    /* Audio */
    if (p.found) {
        taskinfo->remote_srtp_audio_params.found = true;
        taskinfo->remote_srtp_audio_params.primary_cryptotag = p.primary_cryptotag;
        taskinfo->remote_srtp_audio_params.secondary_cryptotag = p.secondary_cryptotag;
        strcpy(taskinfo->remote_srtp_audio_params.primary_cryptosuite, p.primary_cryptosuite);
        strcpy(taskinfo->remote_srtp_audio_params.secondary_cryptosuite, p.secondary_cryptosuite);
        strcpy(taskinfo->remote_srtp_audio_params.primary_cryptokeyparams, p.primary_cryptokeyparams);
        strcpy(taskinfo->remote_srtp_audio_params.secondary_cryptokeyparams, p.secondary_cryptokeyparams);
        taskinfo->remote_srtp_audio_params.primary_unencrypted_srtp = p.primary_unencrypted_srtp;
        taskinfo->remote_srtp_audio_params.secondary_unencrypted_srtp = p.secondary_unencrypted_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock(&(taskinfo->mutex));

    return 0;
}

int rtpstream_set_srtp_video_local(rtpstream_callinfo_t* callinfo, SrtpInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo = callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug && !debuglsrtpvfile.open())
    {
        /* error encountered opening local srtp debug file */
        return -1;
    }

    debuglsrtpvfile.printCrypto(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock(&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset(&(taskinfo->local_srtp_video_params), 0, sizeof(taskinfo->local_srtp_video_params));

    /* Video */
    if (p.found) {
        taskinfo->local_srtp_video_params.found = true;
        taskinfo->local_srtp_video_params.primary_cryptotag = p.primary_cryptotag;
        taskinfo->local_srtp_video_params.secondary_cryptotag = p.secondary_cryptotag;
        strcpy(taskinfo->local_srtp_video_params.primary_cryptosuite, p.primary_cryptosuite);
        strcpy(taskinfo->local_srtp_video_params.secondary_cryptosuite, p.secondary_cryptosuite);
        strcpy(taskinfo->local_srtp_video_params.primary_cryptokeyparams, p.primary_cryptokeyparams);
        strcpy(taskinfo->local_srtp_video_params.secondary_cryptokeyparams, p.secondary_cryptokeyparams);
        taskinfo->local_srtp_video_params.primary_unencrypted_srtp = p.primary_unencrypted_srtp;
        taskinfo->local_srtp_video_params.secondary_unencrypted_srtp = p.secondary_unencrypted_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock(&(taskinfo->mutex));

    return 0;
}

int rtpstream_set_srtp_video_remote(rtpstream_callinfo_t* callinfo, SrtpInfoParams &p)
{
    taskentry_t               *taskinfo;

    taskinfo = callinfo->taskinfo;
    if (!taskinfo) {
        /* no task info found - cannot set remote data. just return */
        return -1;
    }

    if (srtpcheck_debug && !debugrsrtpvfile.open())
    {
        /* error encountered opening local srtp debug file */
        return -1;
    }

    debugrsrtpvfile.printCrypto(p);

    /* enter critical section to lock address updates */
    /* may want to leave this out -- low chance of race condition */
    pthread_mutex_lock(&(taskinfo->mutex));

    /* clear out existing addresses  */
    memset(&(taskinfo->remote_srtp_video_params), 0, sizeof(taskinfo->remote_srtp_video_params));

    /* Video */
    if (p.found) {
        taskinfo->remote_srtp_video_params.found = true;
        taskinfo->remote_srtp_video_params.primary_cryptotag = p.primary_cryptotag;
        taskinfo->remote_srtp_video_params.secondary_cryptotag = p.secondary_cryptotag;
        strcpy(taskinfo->remote_srtp_video_params.primary_cryptosuite, p.primary_cryptosuite);
        strcpy(taskinfo->remote_srtp_video_params.secondary_cryptosuite, p.secondary_cryptosuite);
        strcpy(taskinfo->remote_srtp_video_params.primary_cryptokeyparams, p.primary_cryptokeyparams);
        strcpy(taskinfo->remote_srtp_video_params.secondary_cryptokeyparams, p.secondary_cryptokeyparams);
        taskinfo->remote_srtp_video_params.primary_unencrypted_srtp = p.primary_unencrypted_srtp;
        taskinfo->remote_srtp_video_params.secondary_unencrypted_srtp = p.secondary_unencrypted_srtp;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock(&(taskinfo->mutex));

    return 0;
}

static inline uint32_t uint_val(const char *ptr)
{
    // Read as little-endian. Do not dereference as int, since it can be misaligned.
    const unsigned char *p = reinterpret_cast<const unsigned char *>(ptr);
    return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (static_cast<uint32_t>(p[3]) << 24));
}

// wav format details:
// https://www.fatalerrors.org/a/detailed-explanation-of-wav-file-format.html
static int get_wav_header_size(const char *data, int size)
{
    const char *ptr = data;
    const char *limit = data + size;
    if (size < 42)
        return 0;
    if (!(ptr[0] == 'R' && ptr[1] == 'I' && ptr[2] == 'F' && ptr[3] == 'F'))
        return 0;
    ptr += 8;
    if (!(ptr[0] == 'W' && ptr[1] == 'A' && ptr[2] == 'V' && ptr[3] == 'E'))
        return ptr - data;
    ptr += 4;
    for (;;) {
        if (ptr + 8 > limit)
            break;
        const uint32_t chunk_size = uint_val(ptr + 4);
        const bool is_data = (ptr[0] == 'd' && ptr[1] == 'a' && ptr[2] == 't' && ptr[3] == 'a');

        ptr += 8;
        if (ptr > limit)
            return limit - data;
        if (is_data)
            return ptr - data;
        ptr += chunk_size;
    }
    return ptr - data;
}

/* Hand the call's UAC SRTP contexts to its playback thread together
 * with the play flag, under the task's mutex that the caller holds and
 * has set the new play under, so that the thread cannot play with the
 * old contexts or take half a play. */
static void rtpstream_play_srtp(taskentry_t* taskinfo, bool video, int flag,
                                JLSRTP& txUAC, JLSRTP& rxUAC)
{
    rtpsrtp_t*& srtp = video ? taskinfo->video_srtp : taskinfo->audio_srtp;
    if (srtp || txUAC.getCryptoTag() != 0 || rxUAC.getCryptoTag() != 0) {
        if (!srtp) {
            srtp = new rtpsrtp_t;
        }
        srtp->tx = txUAC;
        srtp->rx = rxUAC;
    }
    taskinfo->flags |= flag;
}

/* code checked */
void rtpstream_play(rtpstream_callinfo_t* callinfo, rtpstream_actinfo_t* actioninfo, JLSRTP& txUACAudio, JLSRTP& rxUACAudio)
{
    debugprint("rtpstream_play callinfo=%p filename %s pattern_id %d loop %d bytes %d payload %d ptime %d tick %d\n",
        callinfo,
        actioninfo->filename,
        actioninfo->pattern_id,
        actioninfo->loop_count,
        actioninfo->bytes_per_packet,
        actioninfo->payload_type,
        actioninfo->ms_per_packet,
        actioninfo->ticks_per_packet);

    int           file_index = rtpstream_cache_file(actioninfo->filename,
                                                    0 /* FILE MODE */,
                                                    actioninfo->pattern_id,
                                                    actioninfo->bytes_per_packet,
                                                    0 /* AUDIO */);
    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (file_index < 0) {
        return; /* cannot find file to play */
    }

    if (!taskinfo) {
        return; /* no task data structure */
    }

    /* make sure we have an open socket from which to play the audio file */
    rtpstream_get_local_audioport(callinfo);

    char *file_bytes = cached_files[file_index].bytes;
    int file_size = cached_files[file_index].filesize;
    /* Allow the caller to supply WAV files instead of raw audio, by skipping past headers. */
    /* Doesn't actually parse/convert anything! */
    const int header_size = get_wav_header_size(file_bytes, file_size);
    if (header_size > 0 && file_size >= header_size) {
        file_bytes += header_size;
        file_size -= header_size;
    }

    /* save file parameter in taskinfo structure */
    pthread_mutex_lock(&(taskinfo->mutex));
    taskinfo->new_audio_pattern_id = actioninfo->pattern_id;
    taskinfo->new_audio_loop_count = actioninfo->loop_count;
    taskinfo->new_audio_bytes_per_packet = actioninfo->bytes_per_packet;
    taskinfo->new_audio_file_size = file_size;
    taskinfo->new_audio_file_bytes = file_bytes;
    taskinfo->new_audio_ms_per_packet = actioninfo->ms_per_packet;
    taskinfo->new_audio_timeticks_per_packet = actioninfo->ticks_per_packet;
    taskinfo->new_audio_payload_type = actioninfo->payload_type;

    /* set flag that we have a new file to play */
    rtpstream_play_srtp(taskinfo, false, TI_PLAYFILE, txUACAudio, rxUACAudio);
    pthread_mutex_unlock(&(taskinfo->mutex));
    rtpstream_wake(taskinfo->parent_thread);
}

/* code checked */
void rtpstream_pause(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_pause callinfo=%p\n", callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags |= TI_PAUSERTP;
    }
}

/* code checked */
void rtpstream_resume(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_resume callinfo=%p\n", callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags &= ~TI_PAUSERTP;
    }
}

/* The millisecond that a play of a stream ends in, from the packets it
 * has left: 0 when it has none, ULONG_MAX when the end is not known. The
 * next packet is due in the millisecond next_ms, and the last one goes by
 * the millisecond after its own. */
static unsigned long rtpstream_stream_end(bool paused, int loop_count, int bytes_left,
                                          int num_bytes, int bytes_per_packet,
                                          unsigned long next_ms, int ms_per_packet)
{
    if (!loop_count) {
        return 0;
    }
    if (paused || loop_count < 0 || bytes_per_packet <= 0) {
        return ULONG_MAX;
    }
    unsigned long long bytes = bytes_left + (unsigned long long)(loop_count - 1) * num_bytes;
    unsigned long long packets = (bytes + bytes_per_packet - 1) / bytes_per_packet;
    return next_ms + (packets ? packets - 1 : 0) * ms_per_packet + 1;
}

unsigned long rtpstream_play_end(rtpstream_callinfo_t* callinfo)
{
    taskentry_t *taskinfo = callinfo->taskinfo;
    unsigned long audio_end, video_end;

    if (!taskinfo) {
        return 0;
    }

    /* A play the playback thread has not taken yet is in the flags, and
     * starts now, stamped from the last multiple of its packet time; one it
     * plays has loops left (-1: endless). */
    pthread_mutex_lock(&(taskinfo->mutex));
    int flags = taskinfo->flags;
    if (flags & (TI_PLAYAPATTERN | TI_PLAYVPATTERN)) {
        audio_end = ULONG_MAX;
    } else if (flags & TI_PLAYFILE) {
        audio_end = rtpstream_stream_end(flags & (TI_NULL_AUDIOIP | TI_PAUSERTP),
                                         taskinfo->new_audio_loop_count,
                                         taskinfo->new_audio_file_size,
                                         taskinfo->new_audio_file_size,
                                         taskinfo->new_audio_bytes_per_packet,
                                         rtpstream_grid_ms(getmilliseconds(), taskinfo->new_audio_ms_per_packet),
                                         taskinfo->new_audio_ms_per_packet);
    } else {
        audio_end = rtpstream_stream_end(flags & (TI_NULL_AUDIOIP | TI_PAUSERTP | TI_PAUSERTPAPATTERN),
                                         taskinfo->audio_loop_count,
                                         taskinfo->audio_file_bytes_left,
                                         taskinfo->audio_file_num_bytes,
                                         taskinfo->audio_bytes_per_packet,
                                         taskinfo->audio_timeticks_per_ms ?
                                         taskinfo->last_audio_timestamp / taskinfo->audio_timeticks_per_ms : 0,
                                         taskinfo->audio_ms_per_packet);
    }
    video_end = rtpstream_stream_end(flags & (TI_NULL_VIDEOIP | TI_PAUSERTP | TI_PAUSERTPVPATTERN),
                                     taskinfo->video_loop_count,
                                     taskinfo->video_file_bytes_left,
                                     taskinfo->video_file_num_bytes,
                                     taskinfo->video_bytes_per_packet,
                                     taskinfo->video_timeticks_per_ms ?
                                     taskinfo->last_video_timestamp / taskinfo->video_timeticks_per_ms : 0,
                                     taskinfo->video_ms_per_packet);
    pthread_mutex_unlock(&(taskinfo->mutex));
    return std::max(audio_end, video_end);
}

void rtpstream_playapattern(rtpstream_callinfo_t* callinfo, rtpstream_actinfo_t* actioninfo, JLSRTP& txUACAudio, JLSRTP& rxUACAudio)
{
    debugprint("rtpstream_playapattern callinfo=%p filename %s pattern_id %d loop %d bytes %d payload %d ptime %d tick %d\n",
            callinfo,
            actioninfo->filename,
            actioninfo->pattern_id,
            actioninfo->loop_count,
            actioninfo->bytes_per_packet,
            actioninfo->payload_type,
            actioninfo->ms_per_packet,
            actioninfo->ticks_per_packet);

    int           file_index = rtpstream_cache_file(actioninfo->filename,
                                                    1 /* PATTERN MODE */,
                                                    actioninfo->pattern_id,
                                                    actioninfo->bytes_per_packet,
                                                    0 /* AUDIO */);
    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (file_index < 0)
    {
        return; /* ERROR encountered */
    }

    if (!taskinfo)
    {
        return; /* no task data structure */
    }

    /* make sure we have an open socket from which to play the audio file */
    rtpstream_get_local_audioport(callinfo);

    /* save file parameter in taskinfo structure */
    pthread_mutex_lock(&(taskinfo->mutex));
    taskinfo->new_audio_pattern_id = actioninfo->pattern_id;
    taskinfo->new_audio_payload_type = actioninfo->payload_type;
    taskinfo->new_audio_loop_count = actioninfo->loop_count;

    taskinfo->new_audio_file_size = cached_patterns[file_index].filesize;
    taskinfo->new_audio_file_bytes = cached_patterns[file_index].bytes;

    taskinfo->new_audio_ms_per_packet = actioninfo->ms_per_packet;
    taskinfo->new_audio_bytes_per_packet = actioninfo->bytes_per_packet;
    taskinfo->new_audio_timeticks_per_packet = actioninfo->ticks_per_packet;
    taskinfo->audio_comparison_errors = 0;

    /* set flag that we have a new file to play */
    rtpstream_play_srtp(taskinfo, false, TI_PLAYAPATTERN, txUACAudio, rxUACAudio);
    pthread_mutex_unlock(&(taskinfo->mutex));
    rtpstream_wake(taskinfo->parent_thread);
}

void rtpstream_pauseapattern(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_pauseapattern callinfo=%p\n", callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags |= TI_PAUSERTPAPATTERN;
    }
}

void rtpstream_resumeapattern(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_resumeapattern callinfo=%p\n", callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags &= ~TI_PAUSERTPAPATTERN;
    }
}

void rtpstream_playvpattern(rtpstream_callinfo_t* callinfo, rtpstream_actinfo_t* actioninfo, JLSRTP& txUACVideo, JLSRTP& rxUACVideo)
{
    debugprint("rtpstream_playvpattern callinfo=%p filename %s pattern_id %d loop %d bytes %d payload %d ptime %d tick %d\n",
            callinfo,
            actioninfo->filename,
            actioninfo->pattern_id,
            actioninfo->loop_count,
            actioninfo->bytes_per_packet,
            actioninfo->payload_type,
            actioninfo->ms_per_packet,
            actioninfo->ticks_per_packet);

    int           file_index = rtpstream_cache_file(actioninfo->filename,
                                                    1 /* PATTERN MODE */,
                                                    actioninfo->pattern_id,
                                                    actioninfo->bytes_per_packet,
                                                    1 /* VIDEO */);
    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (file_index < 0)
    {
        return; /* ERROR encountered */
    }

    if (!taskinfo)
    {
        return; /* no task data structure */
    }

    /* make sure we have an open socket from which to play the video file */
    rtpstream_get_local_videoport(callinfo);

    /* save file parameter in taskinfo structure */
    pthread_mutex_lock(&(taskinfo->mutex));
    taskinfo->new_video_pattern_id = actioninfo->pattern_id;
    taskinfo->new_video_payload_type = actioninfo->payload_type;
    taskinfo->new_video_loop_count = actioninfo->loop_count;

    taskinfo->new_video_file_size = cached_patterns[file_index].filesize;
    taskinfo->new_video_file_bytes = cached_patterns[file_index].bytes;

    taskinfo->new_video_ms_per_packet = actioninfo->ms_per_packet;
    taskinfo->new_video_bytes_per_packet = actioninfo->bytes_per_packet;
    taskinfo->new_video_timeticks_per_packet = actioninfo->ticks_per_packet;
    taskinfo->video_comparison_errors = 0;

    /* set flag that we have a new file to play */
    rtpstream_play_srtp(taskinfo, true, TI_PLAYVPATTERN, txUACVideo, rxUACVideo);
    pthread_mutex_unlock(&(taskinfo->mutex));
    rtpstream_wake(taskinfo->parent_thread);
}

void rtpstream_pausevpattern(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_pausevpattern callinfo=%p\n", callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags |= TI_PAUSERTPVPATTERN;
    }
}

void rtpstream_resumevpattern(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_resumevpattern callinfo=%p\n", callinfo);

    if (callinfo->taskinfo) {
        callinfo->taskinfo->flags &= ~TI_PAUSERTPVPATTERN;
    }
}

#ifdef PCAPPLAY
int rtpstream_play_pcap(rtpstream_callinfo_t* callinfo, rtpstream_pcap_t stream, const play_args_t* play)
{
    debugprint("rtpstream_play_pcap callinfo=%p stream=%d\n", callinfo, stream);

    taskentry_t *taskinfo = callinfo->taskinfo;

    if (!taskinfo || (!taskinfo->parent_thread && !rtpstream_start_task(callinfo)))
    {
        return 0;
    }

    /* The plays of a thread are all from the media IP: one raw socket
     * for all. The main thread opens it, to exit if it cannot: the
     * playback thread would stop with the call's mutex locked. */
    threaddata_t *threaddata = taskinfo->parent_thread;
    if (threaddata->pcap_socket == -1)
    {
        threaddata->pcap_socket = send_packets_socket(&play->from);
    }

    pthread_mutex_lock(&(taskinfo->mutex));
    play_args_t& current = taskinfo->pcap_plays[stream];
    send_packets_end(&current);
    /* a switch to T.38 often keeps the remote port: an image play ends
     * the audio one, and the other way round, not to mix RTP and UDPTL */
    if (stream != RTPSTREAM_PCAP_VIDEO)
    {
        send_packets_end(&taskinfo->pcap_plays[stream == RTPSTREAM_PCAP_AUDIO ?
                                               RTPSTREAM_PCAP_IMAGE : RTPSTREAM_PCAP_AUDIO]);
    }
    current = *play;
    current.next = nullptr;
    pthread_mutex_unlock(&(taskinfo->mutex));

    rtpstream_wake(threaddata);

    return 1;
}

void rtpstream_update_pcap(rtpstream_callinfo_t* callinfo, rtpstream_pcap_t stream, const play_args_t* play)
{
    taskentry_t *taskinfo = callinfo->taskinfo;

    if (!taskinfo)
    {
        return;
    }

    pthread_mutex_lock(&(taskinfo->mutex));
    play_args_t& current = taskinfo->pcap_plays[stream];
    if (current.pcap)
    {
        current.to = play->to;
        current.from = play->from;
    }
    pthread_mutex_unlock(&(taskinfo->mutex));
}
#endif

/* Start or update the echo of a call's audio or video, which the call's
 * playback thread does, with the call's UAS SRTP contexts. */
static void rtpstream_rtpecho_set(taskentry_t* taskinfo, bool video, bool start,
                                  JLSRTP& rxUAS, JLSRTP& txUAS)
{
    pthread_mutex_lock(&(taskinfo->mutex));
    rtpecho_t*& echo = video ? taskinfo->video_echo : taskinfo->audio_echo;
    if (!echo) {
        echo = new rtpecho_t;
    }
    echo->rx = rxUAS;
    echo->tx = txUAS;
    if (start) {
        echo->error = false;
        (video ? taskinfo->video_srtp_echo_active : taskinfo->audio_srtp_echo_active) = 1;
    }
    pthread_mutex_unlock(&(taskinfo->mutex));

    /* to watch the socket from the first packet */
    if (start) {
        rtpstream_wake(taskinfo->parent_thread);
    }
}

/* Stop the echo of a call's audio or video: -1 if it failed to receive. */
static int rtpstream_rtpecho_stop(taskentry_t* taskinfo, bool video)
{
    int rc = 0;

    pthread_mutex_lock(&(taskinfo->mutex));
    rtpecho_t* echo = video ? taskinfo->video_echo : taskinfo->audio_echo;
    (video ? taskinfo->video_srtp_echo_active : taskinfo->audio_srtp_echo_active) = 0;
    if (echo && echo->error) {
        rc = -1;
    }
    pthread_mutex_unlock(&(taskinfo->mutex));

    return rc;
}

int rtpstream_rtpecho_startaudio(rtpstream_callinfo_t* callinfo, JLSRTP& rxUASAudio, JLSRTP& txUASAudio)
{
    debugprint("rtpstream_rtpecho_startaudio callinfo=%p\n", callinfo);

    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    if (srtpcheck_debug && !debugrefileaudio.open())
    {
        /* error encountered opening audio debug file */
        return -2;
    }

    debugrefileaudio.printf("rtpstream_rtpecho_startaudio reached...\n");

    rtpstream_rtpecho_set(taskinfo, false, true, rxUASAudio, txUASAudio);

    return 0;
}

int rtpstream_rtpecho_updateaudio(rtpstream_callinfo_t* callinfo, JLSRTP& rxUASAudio, JLSRTP& txUASAudio)
{
    debugprint("rtpstream_rtpecho_updateaudio callinfo=%p\n", callinfo);

    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    debugrefileaudio.printf("rtpstream_rtpecho_updateaudio reached...\n");

    rtpstream_rtpecho_set(taskinfo, false, false, rxUASAudio, txUASAudio);

    return 0;
}

int rtpstream_rtpecho_stopaudio(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_rtpecho_stopaudio callinfo=%p\n", callinfo);

    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    debugrefileaudio.printf("rtpstream_rtpecho_stopaudio reached...\n");

    return rtpstream_rtpecho_stop(taskinfo, false);
}

int rtpstream_rtpecho_startvideo(rtpstream_callinfo_t* callinfo, JLSRTP& rxUASVideo, JLSRTP& txUASVideo)
{
    debugprint("rtpstream_rtpecho_startvideo callinfo=%p\n", callinfo);

    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    if (srtpcheck_debug && !debugrefilevideo.open())
    {
        /* error encountered opening video debug file */
        return -2;
    }

    debugrefilevideo.printf("rtpstream_rtpecho_startvideo reached...\n");

    rtpstream_rtpecho_set(taskinfo, true, true, rxUASVideo, txUASVideo);

    return 0;
}

int rtpstream_rtpecho_updatevideo(rtpstream_callinfo_t* callinfo, JLSRTP& rxUASVideo, JLSRTP& txUASVideo)
{
    debugprint("rtpstream_rtpecho_updatevideo callinfo=%p\n", callinfo);

    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    debugrefilevideo.printf("rtpstream_rtpecho_updatevideo reached...\n");

    rtpstream_rtpecho_set(taskinfo, true, false, rxUASVideo, txUASVideo);

    return 0;
}

int rtpstream_rtpecho_stopvideo(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_rtpecho_stopvideo callinfo=%p\n", callinfo);

    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (!taskinfo)
    {
        return -1; /* no task data structure */
    }

    debugrefilevideo.printf("rtpstream_rtpecho_stopvideo reached...\n");

    return rtpstream_rtpecho_stop(taskinfo, true);
}

/* code checked */
int rtpstream_shutdown(std::unordered_map<pthread_t, std::string>& threadIDs)
{
    int            count = 0;
    void*          rtpresult;
    int            total_rtpresults;

    rtpresult = nullptr;
    total_rtpresults = 0;

    debugprint("rtpstream_shutdown\n");

    /* signal all playback threads that they should exit */
    if (ready_threads) {
        for (count = 0; count < num_ready_threads; count++) {
            ready_threads[count]->exit_flag = 1;
        }
        free(ready_threads);
        ready_threads = nullptr;
    }

    if (busy_threads) {
        for (count = 0; count < num_busy_threads; count++) {
            busy_threads[count]->exit_flag = 1;
        }
        free(busy_threads);
        busy_threads = nullptr;
    }

    /* first make sure no playback threads are accessing the file buffers */
    /* else small chance the playback thread tries to access freed memory */
    while (rtpstream_numthreads) {
        usleep(50000);
    }

    // PTHREAD JOIN HERE...
    for (std::unordered_map<pthread_t, std::string>::iterator iter = threadIDs.begin(); iter != threadIDs.end(); ++iter)
    {
        debugafile.printHex("EXISTING THREADID: ", "", 0, getThreadId(iter->first), 0);
        debugvfile.printHex("EXISTING THREADID: ", "", 0, getThreadId(iter->first), 0);
        if (pthread_join(iter->first, &rtpresult))
        {
            // error joining thread
            debugafile.printHex("ERROR RETURNED BY PTHREAD_JOIN!", "", 0, 0, 0);
            debugvfile.printHex("ERROR RETURNED BY PTHREAD_JOIN!", "", 0, 0, 0);
            return -2;
        }

        total_rtpresults |= (int)(long long)rtpresult;
        debugafile.printHex("JOINED THREAD: ", "", 0, (long long)rtpresult, total_rtpresults);
        debugvfile.printHex("JOINED THREAD: ", "", 0, (long long)rtpresult, total_rtpresults);
    }

    /* now free cached file bytes and structure */
    if (cached_files)
    {
        for (count = 0; count < num_cached_files; count++) {
            free(cached_files[count].bytes);
        }
        free(cached_files);
        cached_files = nullptr;
    }

    /* now free cached patterns bytes and structure */
    if (cached_patterns)
    {
        for (count = 0; count < num_cached_patterns; count++) {
            free(cached_patterns[count].bytes);
        }
        free(cached_patterns);
        cached_patterns = nullptr;
    }

    debugvfile.close();
    debugafile.close();
    debuglsrtpafile.close();
    debugrsrtpafile.close();
    debuglsrtpvfile.close();
    debugrsrtpvfile.close();
    debugrefileaudio.close();
    debugrefilevideo.close();

    return total_rtpresults;
}

#ifdef GTEST
#include "gtest/gtest.h"

TEST(RtpstreamCacheFile, PatternOncePerParameters) {
    char name[] = "apattern";
    int index = rtpstream_cache_file(name, 1, 1, 160, 0);
    ASSERT_GE(index, 0);
    int patterns = num_cached_patterns;
    for (int i = 0; i < 100; i++) {
        EXPECT_EQ(index, rtpstream_cache_file(name, 1, 1, 160, 0));
    }
    EXPECT_EQ(patterns, num_cached_patterns);
    EXPECT_NE(index, rtpstream_cache_file(name, 1, 2, 160, 0));
    EXPECT_NE(index, rtpstream_cache_file(name, 1, 1, 20, 0));
    EXPECT_EQ(patterns + 2, num_cached_patterns);
}

TEST(RtpstreamCacheFile, FileAndPattern) {
    char name[] = "/tmp/sipp_rtpstream_XXXXXX";
    int fd = mkstemp(name);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(3, write(fd, "abc", 3));
    close(fd);
    char pattern[] = "apattern";
    int file = rtpstream_cache_file(name, 0, 0, 160, 0);
    int apattern = rtpstream_cache_file(pattern, 1, 3, 160, 0);
    int vpattern = rtpstream_cache_file(pattern, 1, 4, 1280, 1);
    unlink(name);
    ASSERT_GE(file, 0);
    ASSERT_GE(apattern, 0);
    ASSERT_GE(vpattern, 0);
    EXPECT_EQ(file, rtpstream_cache_file(name, 0, 0, 160, 0));
    EXPECT_EQ(3, cached_files[file].filesize);
    EXPECT_EQ(0, memcmp(cached_files[file].bytes, "abc", 3));
    EXPECT_EQ(160, cached_patterns[apattern].filesize);
    EXPECT_EQ((char)PATTERN3, cached_patterns[apattern].bytes[159]);
    EXPECT_EQ(1280, cached_patterns[vpattern].filesize);
    EXPECT_EQ((char)PATTERN4, cached_patterns[vpattern].bytes[1279]);
}

#endif //GTEST
