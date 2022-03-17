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

/* stub to add extra debugging/logging... */
static void debugprint(const char* format, ...)
{
}

#define RTPSTREAM_FILESPERBLOCK       16
#define BIND_MAX_TRIES                100
#define RTPSTREAM_THREADBLOCKSIZE     16
#define MAX_UDP_RECV_BUFFER           8192

#define TI_NULL_AUDIOIP               0x01
#define TI_NULLIP                     (TI_NULL_AUDIOIP)
#define TI_PAUSERTP                   0x04
#define TI_ECHORTP                    0x08  /* Not currently implemented */
#define TI_KILLTASK                   0x10
#define TI_PLAYFILE                   0x40
#define TI_CONFIGFLAGS                (TI_KILLTASK|TI_PLAYFILE)

struct rtp_header_t
{
    uint16_t         flags;
    uint16_t         seq;
    uint32_t         timestamp;
    uint32_t         ssrc_id;
};

struct taskentry_t
{
    threaddata_t         *parent_thread;
    unsigned long        nextwake_ms;
    volatile int         flags;

    /* rtp stream information */
    unsigned long long   last_timestamp;
    unsigned short       seq;
    char                 payload_type;
    unsigned int         ssrc_id;

    /* current playback information */
    int                  loop_count;
    char                 *file_bytes_start;
    char                 *current_file_bytes;
    int                  file_num_bytes;
    int                  file_bytes_left;
    /* playback timing information */
    int                  ms_per_packet;
    int                  bytes_per_packet;
    int                  timeticks_per_packet;
    int                  timeticks_per_ms;

    /* new file playback information */
    char                 new_payload_type;
    int                  new_loop_count;
    int                  new_file_size;
    char                 *new_file_bytes;
    int                  new_ms_per_packet;
    int                  new_bytes_per_packet;
    int                  new_timeticks_per_packet;
    /* sockets for audio/video rtp_rtcp */
    int                  audio_rtp_socket;

    /* rtp peer address structures */
    struct sockaddr_storage    remote_audio_rtp_addr;

    /* we will have a mutex per call. should we consider refactoring to */
    /* share mutexes across calls? makes the per-call code more complex */

    /* thread mananagment structures */
    pthread_mutex_t      mutex;
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

cached_file_t  *cached_files = NULL;
int            num_cached_files = 0;
int            next_rtp_port = 0;

threaddata_t  **ready_threads = NULL;
threaddata_t  **busy_threads = NULL;
int           num_busy_threads = 0;
int           num_ready_threads = 0;
int           busy_threads_max = 0;
int           ready_threads_max = 0;

unsigned int  global_ssrc_id = 0xCA110000;

//===================================================================================================

/* code checked */
static void rtpstream_free_taskinfo(taskentry_t* taskinfo)
{
    if (taskinfo) {
        /* cleanup pthread library structure */
        pthread_mutex_destroy(&(taskinfo->mutex));
        free(taskinfo);
    }
}

/* code checked */
static void rtpstream_process_task_flags(taskentry_t* taskinfo)
{
    if (taskinfo->flags & TI_PLAYFILE) {
        /* copy playback information */
        taskinfo->loop_count = taskinfo->new_loop_count;
        taskinfo->file_bytes_start = taskinfo->new_file_bytes;
        taskinfo->current_file_bytes = taskinfo->new_file_bytes;
        taskinfo->file_num_bytes = taskinfo->new_file_size;
        taskinfo->file_bytes_left = taskinfo->new_file_size;
        taskinfo->payload_type = taskinfo->new_payload_type;

        taskinfo->ms_per_packet = taskinfo->new_ms_per_packet;
        taskinfo->bytes_per_packet = taskinfo->new_bytes_per_packet;
        taskinfo->timeticks_per_packet = taskinfo->new_timeticks_per_packet;
        taskinfo->timeticks_per_ms = taskinfo->timeticks_per_packet/taskinfo->ms_per_packet;

        taskinfo->last_timestamp = getmilliseconds()*taskinfo->timeticks_per_ms;
        taskinfo->flags &= ~TI_PLAYFILE;
    }
}

/**** todo - check code ****/
static unsigned long rtpstream_playrtptask(taskentry_t* taskinfo, unsigned long timenow_ms)
{
    int rc;
    unsigned long next_wake;
    unsigned long long target_timestamp;

    union {
        rtp_header_t hdr;
        char buffer[MAX_UDP_RECV_BUFFER];
    } udp;

    /* OK, now to play - sockets are supposed to be non-blocking */
    /* no support for video stream at this stage. will need some work */

    next_wake = timenow_ms + 100; /* default next wakeup time */

    if (taskinfo->audio_rtp_socket != -1) {
        /* if/when we include echo functionality, we'll have to read
         * from the audio_rtp_socket too, and check by peer address if
         * it is "our" traffic */

        /* are we playing back an audio file? */
        if (taskinfo->loop_count) {
            target_timestamp = timenow_ms * taskinfo->timeticks_per_ms;
            next_wake = timenow_ms + taskinfo->ms_per_packet - timenow_ms % taskinfo->ms_per_packet;
            if (taskinfo->flags & (TI_NULL_AUDIOIP | TI_PAUSERTP)) {
                /* when paused, set timestamp so stream appears to be up to date */
                taskinfo->last_timestamp = target_timestamp;
            }
            if (taskinfo->last_timestamp < target_timestamp) {

                /* need to send rtp payload - build rtp packet header... */
                udp.hdr.flags = htons(0x8000 | taskinfo->payload_type);
                udp.hdr.seq = htons(taskinfo->seq);
                udp.hdr.timestamp = htonl((uint32_t)(taskinfo->last_timestamp & 0xFFFFFFFF));
                udp.hdr.ssrc_id = htonl(taskinfo->ssrc_id);
                /* add payload data to the packet - handle buffer wraparound */
                if (taskinfo->file_bytes_left >= taskinfo->bytes_per_packet) {
                    /* no need for fancy acrobatics */
                    memcpy(udp.buffer + sizeof(rtp_header_t), taskinfo->current_file_bytes, taskinfo->bytes_per_packet);
                } else {
                    /* copy from end and then begining of file. does not handle the */
                    /* case where file is shorter than the packet length!! */
                    memcpy(udp.buffer + sizeof(rtp_header_t), taskinfo->current_file_bytes, taskinfo->file_bytes_left);
                    memcpy(udp.buffer + sizeof(rtp_header_t) + taskinfo->file_bytes_left,
                           taskinfo->file_bytes_start, taskinfo->bytes_per_packet - taskinfo->file_bytes_left);
                }

                /* now send the actual packet */
                size_t packet_len = taskinfo->bytes_per_packet + sizeof(rtp_header_t);
                socklen_t remote_addr_len = (media_ip_is_ipv6 ?
                                             sizeof(struct sockaddr_in6) :
                                             sizeof(struct sockaddr_in));
                rc = sendto(taskinfo->audio_rtp_socket, udp.buffer, packet_len, 0,
                            (struct sockaddr*)&taskinfo->remote_audio_rtp_addr, remote_addr_len);

                if (rc < 0) {
                    /* handle sending errors */
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        next_wake = timenow_ms + 2; /* retry after short sleep */
                    } else {
                        /* this looks like a permanent error  - should we ignore ENETUNREACH? */
                        debugprint("closing rtp socket %d due to error %d in rtpstream_new_call taskinfo=%p\n",
                                   taskinfo->audio_rtp_socket, errno, taskinfo);
                        close(taskinfo->audio_rtp_socket);
                        taskinfo->audio_rtp_socket = -1;
                    }
                } else {
                    /* statistics - only count successful sends */
                    rtpstream_bytes_out += taskinfo->bytes_per_packet + sizeof(rtp_header_t);
                    rtpstream_pckts++;
                    /* advance playback pointer to next packet */
                    taskinfo->seq++;
                    /* must change if timer ticks per packet can be fractional */
                    taskinfo->last_timestamp += taskinfo->timeticks_per_packet;
                    taskinfo->file_bytes_left -= taskinfo->bytes_per_packet;
                    if (taskinfo->file_bytes_left > 0) {
                        taskinfo->current_file_bytes += taskinfo->bytes_per_packet;
                    } else {
                        taskinfo->current_file_bytes = taskinfo->file_bytes_start - taskinfo->file_bytes_left;
                        taskinfo->file_bytes_left += taskinfo->file_num_bytes;
                        if (taskinfo->loop_count > 0) {
                            /* one less loop to play. -1 (infinite loops) will stay as is */
                            taskinfo->loop_count--;
                        }
                    }
                    if (taskinfo->last_timestamp < target_timestamp) {
                        /* no sleep if we are behind */
                        next_wake = timenow_ms;
                    }
                }
            }
        } else {
            /* not busy playing back a file -  put possible rtp echo code here. */
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
    taskentry_t    *taskinfo;
    int            taskindex;

    unsigned long  timenow_ms;
    unsigned long  waketime_ms;
    int            sleeptime_us;

    rtpstream_numthreads++; /* perhaps wrap this in a mutex? */

    while (!threaddata->exit_flag) {
        timenow_ms = getmilliseconds();
        waketime_ms = timenow_ms + 100; /* default sleep 100ms */

        /* iterate through tasks and handle playback and other actions */
        for (taskindex = 0; taskindex < threaddata->num_tasks; taskindex++) {
            taskinfo = (&threaddata->tasklist)[taskindex];
            if (taskinfo->flags & TI_CONFIGFLAGS) {
                if (taskinfo->flags & TI_KILLTASK) {
                    /* remove this task entry and release its resources */
                    pthread_mutex_lock (&(threaddata->tasklist_mutex));
                    (&threaddata->tasklist)[taskindex--] = (&threaddata->tasklist)[--threaddata->num_tasks];
                    threaddata->del_pending--;   /* must decrease del_pending after num_tasks */
                    pthread_mutex_unlock(&(threaddata->tasklist_mutex));
                    rtpstream_free_taskinfo(taskinfo);
                    continue;
                }
                /* handle any other config related flags */
                rtpstream_process_task_flags(taskinfo);
            }

            /* should we update current time inbetween tasks? */
            if (taskinfo->nextwake_ms <= timenow_ms) {
                /* task needs to execute now */
                taskinfo->nextwake_ms = rtpstream_playrtptask(taskinfo, timenow_ms);
            }
            if (waketime_ms > taskinfo->nextwake_ms) {
                waketime_ms = taskinfo->nextwake_ms;
            }
        }
        /* sleep until next iteration of playback loop */
        sleeptime_us = (waketime_ms - getmilliseconds()) * 1000;
        if (sleeptime_us > 0) {
            usleep(sleeptime_us);
        }
    }

    /* Free all task and thread resources and exit the thread */
    for (taskindex = 0; taskindex < threaddata->num_tasks; taskindex++) {
        /* check if we should delete this thread, else let owner call clear it */
        /* small chance of race condition in this code */
        taskinfo = (&threaddata->tasklist)[taskindex];
        if (taskinfo->flags & TI_KILLTASK) {
            rtpstream_free_taskinfo(taskinfo);
        } else {
            taskinfo->parent_thread = NULL; /* no longer associated with a thread */
        }
    }
    pthread_mutex_destroy(&(threaddata->tasklist_mutex));
    free(threaddata);
    rtpstream_numthreads--; /* perhaps wrap this in a mutex? */

    return NULL;
}

/* code checked */
static int rtpstream_start_task(rtpstream_callinfo_t* callinfo)
{
    int           ready_index;
    int           allocsize;
    threaddata_t  **threadlist;
    threaddata_t  *threaddata;
    pthread_t     newthread;

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
        allocsize = sizeof(*threaddata) + sizeof(threaddata->tasklist) * (rtp_tasks_per_thread - 1);
        threaddata = (threaddata_t *) malloc(allocsize);
        if (!threaddata) {
            return 0;
        }
        memset(threaddata, 0, allocsize);
        threaddata->max_tasks = rtp_tasks_per_thread;
        threaddata->busy_list_index = -1;
        pthread_mutex_init(&(threaddata->tasklist_mutex), NULL);
        /* create the thread itself */
        if (pthread_create(&newthread, NULL, rtpstream_playback_thread, threaddata)) {
            /* error creating the thread */
            free(threaddata);
            return 0;
        }
        /* Add thread to list of ready (spare capacity) threads */
        ready_threads[num_ready_threads++] = threaddata;
    }

    /* now add new task to a spare slot in our thread tasklist */
    threaddata = ready_threads[ready_index];
    callinfo->taskinfo->parent_thread = threaddata;
    pthread_mutex_lock(&(threaddata->tasklist_mutex));
    (&threaddata->tasklist)[threaddata->num_tasks++] = callinfo->taskinfo;
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

    if (taskinfo) {
        if (taskinfo->parent_thread) {
            /* this call's task is registered with an executing thread */
            /* first move owning thread to the ready list - will be ready soon */
            busy_index = taskinfo->parent_thread->busy_list_index;
            if (busy_index >= 0) {
                /* make sure we have enough entries in ready list */
                if (num_ready_threads >= ready_threads_max) {
                    /* need to allocate more memory for thread list */
                    ready_threads_max += RTPSTREAM_THREADBLOCKSIZE;
                    threadlist = (threaddata_t **) realloc(ready_threads, sizeof(*ready_threads) * ready_threads_max);
                    if (!threadlist) {
                        /* could not allocate bigger block... reset max threads */
                        /* this is a problem - ready thread gets "lost" on busy list */
                        ready_threads_max -= RTPSTREAM_THREADBLOCKSIZE;
                    } else {
                        ready_threads = threadlist;
                    }
                }

                if (num_ready_threads < ready_threads_max) {
                    /* OK, got space on ready list, move to ready list */
                    busy_threads[busy_index]->busy_list_index = -1;
                    ready_threads[num_ready_threads++] = busy_threads[busy_index];
                    num_busy_threads--;
                    /* fill up gap in the busy thread list */
                    if (busy_index != num_busy_threads) {
                        busy_threads[busy_index] = busy_threads[num_busy_threads];
                        busy_threads[busy_index]->busy_list_index = busy_index;
                    }
                }
            }
            /* then ask the thread to destory this task (and its memory) */
            pthread_mutex_lock(&(taskinfo->parent_thread->tasklist_mutex));
            taskinfo->parent_thread->del_pending++;
            taskinfo->flags |= TI_KILLTASK;
            pthread_mutex_unlock(&(taskinfo->parent_thread->tasklist_mutex));
        } else {
            /* no playback thread owner, just free it */
            rtpstream_free_taskinfo(taskinfo);
        }
        callinfo->taskinfo = NULL;
    }
}

/* code checked */
int rtpstream_new_call(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_new_call callinfo=%p\n", callinfo);

    taskentry_t* taskinfo;

    /* general init */
    memset(callinfo, 0, sizeof(*callinfo));

    taskinfo= (taskentry_t *) malloc(sizeof(*taskinfo));
    if (!taskinfo) {
        /* cannot allocate taskinfo memory - bubble error up */
        return 0;
    }
    callinfo->taskinfo = taskinfo;

    memset(taskinfo, 0, sizeof(*taskinfo));
    taskinfo->flags = TI_NULLIP;
    /* socket descriptors */
    taskinfo->audio_rtp_socket = -1;
    /* rtp stream members */
    taskinfo->ssrc_id = global_ssrc_id++;
    /* pthread mutexes */
    pthread_mutex_init(&(callinfo->taskinfo->mutex), NULL);

    return 1;
}

/* code checked */
void rtpstream_end_call(rtpstream_callinfo_t* callinfo)
{
    debugprint("rtpstream_end_call callinfo=%p\n", callinfo);

    /* stop playback thread(s) for this call */
    rtpstream_stop_task(callinfo);
}

/* code checked */
int rtpstream_cache_file(char* filename)
{
    int           count = 0;
    cached_file_t *newcachelist;
    char          *filecontents;
    struct stat   statbuffer;
    FILE          *f;

    debugprint ("rtpstream_cache_file filename=%s\n", filename);

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
        /* could not alloc mem */
        return -1;
    }
    if (!fread(filecontents, statbuffer.st_size, 1, f)) {
        /* could not read file */
        free(filecontents);
        return -1;
    }
    fclose(f);

    if (!(num_cached_files % RTPSTREAM_FILESPERBLOCK)) {
        /* Time to allocate more memory for the next block of files */
        newcachelist = (cached_file_t*) realloc(cached_files, sizeof(*cached_files) * (num_cached_files + RTPSTREAM_FILESPERBLOCK));
        if (!newcachelist) {
            /* out of memory */
            free(filecontents);
            return -1;
        }
        cached_files = newcachelist;
    }
    cached_files[num_cached_files].bytes = filecontents;
    strncpy(cached_files[num_cached_files].filename, filename,
            sizeof(cached_files[num_cached_files].filename) - 1);
    cached_files[num_cached_files].filesize = statbuffer.st_size;
    return num_cached_files++;
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

    /* observe that we rely on ip_ver being in sync with media_ip_is_ipv6 */
    /* we never alloc a socket here, we reuse the global media socket */
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

    /* Audio */
    if (audio_port) {
        sockaddr_update_port(&address, audio_port);
        memcpy(&(taskinfo->remote_audio_rtp_addr), &address, sizeof(address));
        taskinfo->flags &= ~TI_NULL_AUDIOIP;
    }

    /* ok, we are done with the shared memory objects. let go mutex */
    pthread_mutex_unlock (&(taskinfo->mutex));

    /* may want to start a playback (listen) task here if no task running? */
    /* only makes sense if we decide to send 0-filled packets on idle */
}

/* code checked */
void rtpstream_play(rtpstream_callinfo_t* callinfo, rtpstream_actinfo_t* actioninfo)
{
    debugprint("rtpstream_play callinfo=%p filename %s loop %d bytes %d payload %d ptime %d tick %d\n", callinfo, actioninfo->filename, actioninfo->loop_count, actioninfo->bytes_per_packet, actioninfo->payload_type, actioninfo->ms_per_packet, actioninfo->ticks_per_packet);

    int           file_index = rtpstream_cache_file(actioninfo->filename);
    taskentry_t   *taskinfo = callinfo->taskinfo;

    if (file_index < 0) {
        return; /* cannot find file to play */
    }

    if (!taskinfo) {
        return; /* no task data structure */
    }

    /* make sure we have an open socket from which to play the audio file */
    taskinfo->audio_rtp_socket = media_socket_audio;

    /* start playback task if not already started */
    if (!taskinfo->parent_thread) {
        if (!rtpstream_start_task(callinfo)) {
            /* error starting playback task */
            return;
        }
    }

    /* save file parameter in taskinfo structure */
    taskinfo->new_loop_count = actioninfo->loop_count;
    taskinfo->new_bytes_per_packet = actioninfo->bytes_per_packet;
    taskinfo->new_file_size = cached_files[file_index].filesize;
    taskinfo->new_file_bytes = cached_files[file_index].bytes;
    taskinfo->new_ms_per_packet = actioninfo->ms_per_packet;
    taskinfo->new_timeticks_per_packet = actioninfo->ticks_per_packet;
    taskinfo->new_payload_type = actioninfo->payload_type;

    /* set flag that we have a new file to play */
    taskinfo->flags |= TI_PLAYFILE;
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

/* code checked */
void rtpstream_shutdown(void)
{
    int            count = 0;

    debugprint("rtpstream_shutdown\n");

    /* signal all playback threads that they should exit */
    if (ready_threads) {
        for (count = 0; count < num_ready_threads; count++) {
            ready_threads[count]->exit_flag = 1;
        }
        free(ready_threads);
        ready_threads = NULL;
    }

    if (busy_threads) {
        for (count = 0; count < num_busy_threads; count++) {
            busy_threads[count]->exit_flag = 1;
        }
        free(busy_threads);
        busy_threads = NULL;
    }

    /* first make sure no playback threads are accessing the file buffers */
    /* else small chance the playback thread tries to access freed memory */
    while (rtpstream_numthreads) {
        usleep(50000);
    }

    /* now free cached file bytes and structure */
    for (count = 0; count < num_cached_files; count++) {
        free(cached_files[count].bytes);
    }
    if (cached_files) {
        free(cached_files);
        cached_files = NULL;
    }
}
