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

#define RTPSTREAM_MAX_FILENAMELEN 256

struct threaddata_t;
struct taskentry_t;

struct rtpstream_callinfo_t
{
  taskentry_t  *taskinfo;
  int          audioport;
  int          videoport;
};

struct rtpstream_actinfo_t
{
 char   filename[RTPSTREAM_MAX_FILENAMELEN];
 int	loop_count;
 int    bytes_per_packet;
 int    ms_per_packet;
 int    ticks_per_packet; /* need rework for 11.025 sample rate */
 int    payload_type;
};

int rtpstream_new_call (rtpstream_callinfo_t *callinfo);
void rtpstream_end_call (rtpstream_callinfo_t *callinfo);
void rtpstream_shutdown (void);

int rtpstream_get_audioport (rtpstream_callinfo_t *callinfo);
int rtpstream_get_videoport (rtpstream_callinfo_t *callinfo);
void rtpstream_set_remote (rtpstream_callinfo_t *callinfo, int ip_ver, char *ip_addr, int audio_port, int video_port);

int rtpstream_cache_file (char *filename);
void rtpstream_play (rtpstream_callinfo_t *callinfo, rtpstream_actinfo_t *actioninfo);
void rtpstream_pause (rtpstream_callinfo_t *callinfo);
void rtpstream_resume (rtpstream_callinfo_t *callinfo);

#endif
