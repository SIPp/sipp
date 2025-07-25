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
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           Olivier Jacques
 *           From Hewlett Packard Company.
 *           Shriram Natarajan
 *           Peter Higginson
 *           Eric Miller
 *           Venkatesh
 *           Enrico Hartung
 *           Nasir Khan
 *           Lee Ballard
 *           Guillaume Teissier from FTR&D
 *           Wolfgang Beck
 *           Venkatesh
 *           Vlad Troyanker
 *           Charles P Wright from IBM Research
 *           Amit On from Followap
 *           Jan Andres from Freenet
 *           Ben Evans from Open Cloud
 *           Marc Van Diest from Belgacom
 *           Michael Dwyer from Cibation
 *           Roland Meub
 *           Andy Aicken
 *           Martin H. VanLeeuwen
 */

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <vector>

#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string>

#ifdef PCAPPLAY
#include "send_packets.h"
#endif

#include "sipp.hpp"
#include "auth.hpp"
#include "urlcoder.hpp"
#include "deadcall.hpp"
#include "config.h"
#include "version.h"

template<typename Out>
void split(const std::string &s, char delim, Out result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

std::string join(const std::vector<std::string> &s, const char* delim) {
    std::ostringstream imploded;
    std::copy(s.begin(), s.end(), std::ostream_iterator<std::string>(imploded, delim));
    std::string ret = imploded.str();
    if (ret.length()) {
        ret.resize(ret.length() - strlen(delim));
    }
    return ret;
}

std::string trim(const std::string &s) {
    size_t first = s.find_first_not_of(' ');
    if (first == std::string::npos) {
        return s;
    }
    size_t last = s.find_last_not_of(' ');
    return s.substr(first, (last - first + 1));
}

#define callDebug(...) do { if (useCallDebugf) { _callDebug( __VA_ARGS__ ); } } while (0)

extern  std::map<std::string, SIPpSocket *>     map_perip_fd;

#ifdef PCAPPLAY
/* send_packets pthread wrapper */
void *send_wrapper(void *);
#endif
int call::dynamicId       = 0;
int call::maxDynamicId    = 10000+2000*4;      // FIXME both param to be in command line !!!!
int call::startDynamicId  = 10000;             // FIXME both param to be in command line !!!!
int call::stepDynamicId   = 4;                // FIXME both param to be in command line !!!!

/************** Call map and management routines **************/
static const int SM_UNUSED = -1;

static unsigned int next_number = 1;

static unsigned int get_tdm_map_number()
{
    unsigned int nb = 0;
    unsigned int i=0;
    unsigned int interval=0;
    unsigned int random=0;
    bool found = false;

    /* Find a number in the tdm_map which is not in use */
    interval = (tdm_map_a+1) * (tdm_map_b+1) * (tdm_map_c+1);
    random = rand() % interval;
    while ((i<interval) && (!found)) {
        if (tdm_map[(random + i - 1) % interval] == false) {
            nb = (random + i - 1) % interval;
            found = true;
        }
        i++;
    }

    if (!found) {
        return 0;
    } else {
        return nb+1;
    }
}

/* When should this call wake up? */
unsigned int call::wake()
{
    unsigned int wake = 0;

    if (zombie) {
        return wake;
    }

    if (paused_until) {
        wake = paused_until;
    }

    if (next_retrans && (!wake || (next_retrans < wake))) {
        wake = next_retrans;
    }

    if (recv_timeout && (!wake || (recv_timeout < wake))) {
        wake = recv_timeout;
    }

    return wake;
}

static std::string find_in_sdp(std::string const &pattern, std::string const &msg)
{
    std::string::size_type begin, end;

    begin = msg.find(pattern);
    if (begin == std::string::npos) {
        return "";
    }

    begin += pattern.size();
    end = msg.find_first_of(" \r\n", begin);
    if (end == std::string::npos || begin == end) {
        return "";
    }

    return msg.substr(begin, end - begin);
}

#ifdef PCAPPLAY
void call::get_remote_media_addr(std::string const &msg)
{
    std::string host = find_in_sdp(media_ip_is_ipv6 ? "c=IN IP6 " : "c=IN IP4 ", msg);
    if (host.empty()) {
        return;
    }

    hasMediaInformation = 1;
    const int family = media_ip_is_ipv6 ? AF_INET6 : AF_INET;

    std::string port = find_in_sdp("m=audio ", msg);
    if (!port.empty()) {
        gai_getsockaddr(&play_args_a.to, host.c_str(), port.c_str(),
                        AI_NUMERICHOST | AI_NUMERICSERV, family);
    }

    port = find_in_sdp("m=image ", msg);
    if (!port.empty()) {
        gai_getsockaddr(&play_args_i.to, host.c_str(), port.c_str(),
                        AI_NUMERICHOST | AI_NUMERICSERV, family);
    }

    port = find_in_sdp("m=video ", msg);
    if (!port.empty()) {
        gai_getsockaddr(&play_args_v.to, host.c_str(), port.c_str(),
                        AI_NUMERICHOST | AI_NUMERICSERV, family);
    }
}
#endif

/******* Extract RTP remote media infomartion from SDP  *******/
/***** Similar to the routines used by the PCAP play code *****/

#define SDP_AUDIOPORT_PREFIX "\nm=audio"
#define SDP_IMAGEPORT_PREFIX "\nm=image"
#define SDP_VIDEOPORT_PREFIX "\nm=video"
std::string call::extract_rtp_remote_addr(const char* msg, int &ip_ver, int &audio_port, int &video_port)
{
    const char* search;
    int image_port = 0;
    std::size_t pos1 = 0;
    std::size_t pos2 = 0;
    std::string msgstr;
    std::string sub;
    std::string host;

    if (msg) {
        msgstr = msg;
    }

    /* Look for start of message body */
    search = strstr(msg, "\r\n\r\n");
    if (!search) {
        ERROR("extract_rtp_remote_addr: SDP message body not found");
    }
    msg = search + 2; /* skip past header. point to blank line before body */

    /* Now search for IP address field */
    host = find_in_sdp("c=IN IP4 ", msg);
    if (host.empty()) {
        host = find_in_sdp("c=IN IP6 ", msg);
        if (host.empty()) {
            ERROR("extract_rtp_remote_addr: invalid IP version in SDP message body");
        }
        ip_ver = 6;
    } else {
        ip_ver = 4;
    }

    /* Find the port number for the image stream */
    pos1 = msgstr.find(SDP_IMAGEPORT_PREFIX, 0, 8);
    if (pos1 != std::string::npos)
    {
        pos1 += 8; /* skip SDP_IMAGEPORT_PREFIX */
        pos1 += 1; /* skip first whitespace */
        pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
        if (pos2 != std::string::npos)
        {
            sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
            sscanf(sub.c_str(), "%d", &image_port); /* parse port substring as integer */
        }
    }

    /* Now try to find the port number for the audio stream */
    pos1 = msgstr.find(SDP_AUDIOPORT_PREFIX, 0, 8);
    if (pos1 != std::string::npos)
    {
        pos1 += 8; /* skip SDP_AUDIOPORT_PREFIX */
        pos1 += 1; /* skip first whitespace */
        pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
        if (pos2 != std::string::npos)
        {
            sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
            sscanf(sub.c_str(), "%d", &audio_port); /* parse port substring as integer */
        }
    }

    /* first audio m-line had port of ZERO -- look for second audio m-line */
    if (audio_port == 0)
    {
        pos1 = msgstr.find(SDP_AUDIOPORT_PREFIX, pos2, 8);
        if (pos1 != std::string::npos)
        {
            pos1 += 8; /* skip SDP_AUDIOPORT_PREFIX  */
            pos1 += 1; /* skip first whitespace */
            pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
            if (pos2 != std::string::npos)
            {
                sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
                sscanf(sub.c_str(), "%d", &audio_port);
            }
        }
    }

    /* And find the port number for the video stream */
    pos1 = msgstr.find(SDP_VIDEOPORT_PREFIX, 0, 8);
    if (pos1 != std::string::npos)
    {
        pos1 += 8; /* skip SDP_VIDEOPORT_PREFIX */
        pos1 += 1; /* skip first whitespace */
        pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
        if (pos2 != std::string::npos)
        {
            sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
           sscanf(sub.c_str(), "%d", &video_port); /* parse port substring as integer */
        }
    }

    /* first video m-line had port of ZERO -- look for second video m-line */
    if (video_port == 0)
    {
        pos1 = msgstr.find(SDP_VIDEOPORT_PREFIX, pos2, 8);
        if (pos1 != std::string::npos)
        {
            pos1 += 8; /* skip SDP_VIDEOPORT_PREFIX  */
            pos1 += 1; /* skip first whitespace */
            pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
            if (pos2 != std::string::npos)
            {
                sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
                sscanf(sub.c_str(), "%d", &video_port);
            }
        }
    }

    return host;
}

#ifdef USE_TLS
int call::check_audio_ciphersuite_match(SrtpAudioInfoParams &pA)
{
    int audio_cs_len = 0;
    int audio_ciphersuite_match = 0;

    logSrtpInfo("call::check_audio_ciphersuite_match():  Preferred AUDIO cryptosuite: [%s]\n", _pref_audio_cs_out);

    if (pA.audio_found)
    {
        audio_cs_len = strlen(_pref_audio_cs_out);
        if (!strncmp(_pref_audio_cs_out, "AES_CM_128_HMAC_SHA1_80", audio_cs_len) ||
            !strncmp(_pref_audio_cs_out, "AES_CM_128_HMAC_SHA1_32", audio_cs_len) ||
            !strncmp(_pref_audio_cs_out, "NULL_HMAC_SHA1_80", audio_cs_len) ||
            !strncmp(_pref_audio_cs_out, "NULL_HMAC_SHA1_32", audio_cs_len))
        {
            if (!strncmp(pA.primary_audio_cryptosuite, _pref_audio_cs_out, audio_cs_len))
            {
                // PRIMARY AUDIO cryptosuite matches preferred AUDIO cryptosuite
                logSrtpInfo("call::check_audio_ciphersuite_match():  PRIMARY AUDIO cryptosuite matches preferred AUDIO cryptosuite...\n");
                audio_ciphersuite_match = 1;
            }
            else
            {
                // PRIMARY AUDIO cryptosuite does NOT match preferred AUDIO cryptosuite
                logSrtpInfo("call::check_audio_ciphersuite_match():  PRIMARY AUDIO cryptosuite [%s] does NOT match preferred AUDIO cryptosuite [%s]...\n", pA.primary_audio_cryptosuite, _pref_audio_cs_out);
                audio_ciphersuite_match = 0;
            }
        }
    }

    return audio_ciphersuite_match;
}

int call::check_video_ciphersuite_match(SrtpVideoInfoParams &pV)
{
    int video_cs_len = 0;
    int video_ciphersuite_match = 0;

    logSrtpInfo("call::check_video_ciphersuite_match():  Preferred VIDEO cryptosuite: [%s]\n", _pref_video_cs_out);

    if (pV.video_found)
    {
        video_cs_len = strlen(_pref_video_cs_out);
        if (!strncmp(_pref_video_cs_out, "AES_CM_128_HMAC_SHA1_80", video_cs_len) ||
            !strncmp(_pref_video_cs_out, "AES_CM_128_HMAC_SHA1_32", video_cs_len) ||
            !strncmp(_pref_video_cs_out, "NULL_HMAC_SHA1_80", video_cs_len) ||
            !strncmp(_pref_video_cs_out, "NULL_HMAC_SHA1_32", video_cs_len))
        {
            if (!strncmp(pV.primary_video_cryptosuite, _pref_video_cs_out, video_cs_len))
            {
                // PRIMARY VIDEO cryptosuite matches preferred VIDEO cryptosuite
                logSrtpInfo("call::check_video_ciphersuite_match():  PRIMARY VIDEO cryptosuite matches preferred VIDEO cryptosuite...\n");
                video_ciphersuite_match = 1;
            }
            else
            {
                // PRIMARY VIDEO cryptosuite does NOT match preferred VIDEO cryptosuite
                logSrtpInfo("call::check_video_ciphersuite_match():  PRIMARY VIDEO cryptosuite [%s] does NOT match preferred VIDEO cryptosuite [%s]...\n", pV.primary_video_cryptosuite, _pref_video_cs_out);
                video_ciphersuite_match = 0;
            }
        }
    }

    return video_ciphersuite_match;
}

/******* Extract SRTP remote media infomartion from SDP  *******/

#define SDP_AUDIOCRYPTO_PREFIX "\na=crypto:"
#define SDP_VIDEOCRYPTO_PREFIX "\na=crypto:"
int call::extract_srtp_remote_info(const char * msg, SrtpAudioInfoParams &pA, SrtpVideoInfoParams &pV)
{
    const char* ro_search = nullptr;
    const char* alt_search = nullptr;

    pA.audio_found = false;
    pV.video_found = false;

    pA.primary_audio_cryptotag = 0;
    pV.primary_video_cryptotag = 0;
    memset(pA.primary_audio_cryptosuite, 0, sizeof(pA.primary_audio_cryptosuite));
    memset(pV.primary_video_cryptosuite, 0, sizeof(pV.primary_video_cryptosuite));
    memset(pA.primary_audio_cryptokeyparams, 0, sizeof(pA.primary_audio_cryptokeyparams));
    memset(pV.primary_video_cryptokeyparams, 0, sizeof(pV.primary_video_cryptokeyparams));
    pA.primary_unencrypted_audio_srtp = false;
    pV.primary_unencrypted_video_srtp = false;

    pA.secondary_audio_cryptotag = 0;
    pV.secondary_video_cryptotag = 0;
    memset(pA.secondary_audio_cryptosuite, 0, sizeof(pA.secondary_audio_cryptosuite));
    memset(pV.secondary_video_cryptosuite, 0, sizeof(pV.secondary_video_cryptosuite));
    memset(pA.secondary_audio_cryptokeyparams, 0, sizeof(pA.secondary_audio_cryptokeyparams));
    memset(pV.secondary_video_cryptokeyparams, 0, sizeof(pV.secondary_video_cryptokeyparams));
    pA.secondary_unencrypted_audio_srtp = false;
    pV.secondary_unencrypted_video_srtp = false;

    char* sdp_body = nullptr;
    char* sdp_body_remember = nullptr;

    std::size_t mline_sol = 0; /* Start of m-line line */
    std::size_t mline_eol = 0; /* End of m-line line */
    std::string mline_contents = ""; /* Actual m-line contents */
    std::size_t msection_limit = 0; /* m-line media section limit */
    std::string msgstr; /* std::string representation of SDP body */

    char crypto_audio_sessionparams[64];
    char crypto_video_sessionparams[64];

    char* checkUESRTP = nullptr;
    bool audioExists = false;
    bool videoExists = false;
    std::size_t cur_pos = 0;
    int audio_port = 0;
    int video_port = 0;
    std::size_t pos1 = 0;
    std::size_t pos2 = 0;
    std::string sub;
    std::size_t amsection_limit = 0;
    std::size_t vmsection_limit = 0;

    /* Look for start of message body */
    ro_search= strstr(msg, "\n\n"); // UNIX line endings (LFLF) between header/body sections
    alt_search= strstr(msg, "\r\n\r\n"); // DOS line endings (CRLFCRLF) between header/body sections

    if (ro_search) {
        sdp_body = strdup(ro_search);
    } else if (alt_search) {
        sdp_body = strdup(alt_search);
    }

    if (sdp_body) {
        msgstr = sdp_body;
        sdp_body_remember = sdp_body;

        if (ro_search) {
            sdp_body += 2;  /* skip past header - point to blank line before body */
        } else if (alt_search) {
            sdp_body += 4;  /* skip past header - point to blank line before body */
        }

        /* --------------------------------------------------------------
         * Determine SDP m-line structure
         * -------------------------------------------------------------- */
        amsection_limit = msgstr.find("\nm=audio", 0, msgstr.size());
        vmsection_limit = msgstr.find("\nm=video", 0, msgstr.size());

        /* --------------------------------------------------------------
         * Try to find an AUDIO MLINE
         * -------------------------------------------------------------- */
        pos1 = msgstr.find(SDP_AUDIOPORT_PREFIX, 0, 8);
        if (pos1 != std::string::npos)
        {
            pos1 += 8; /* skip SDP_AUDIOPORT_PREFIX */
            pos1 += 1; /* skip first whitespace */
            pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
            if (pos2 != std::string::npos)
            {
                sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
                sscanf(sub.c_str(), "%d", &audio_port); /* parse port substring as integer */
                if (audio_port != 0)
                {
                    logSrtpInfo("found first ACTIVE audio m-line with NON-ZERO port [%d]...\n", audio_port);
                    audioExists = true;
                }
                else
                {
                    logSrtpInfo("found first INACTIVE audio m-line (e.g. with ZERO port)...\n");

                    pos1 = msgstr.find(SDP_AUDIOPORT_PREFIX, pos2, 8);
                    if (pos1 != std::string::npos)
                    {
                        pos1 += 8; /* skip SDP_AUDIOPORT_PREFIX  */
                        pos1 += 1; /* skip first whitespace */
                        pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
                        if (pos2 != std::string::npos)
                        {
                            sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
                            sscanf(sub.c_str(), "%d", &audio_port);
                            if (audio_port != 0)
                            {
                                logSrtpInfo("found second ACTIVE audio m-line with NON-ZERO port [%d]...\n", audio_port);
                                audioExists = true;
                            }
                            else
                            {
                                logSrtpInfo("found second INACTIVE audio m-line (e.g. with ZERO port)...\n");
                                audioExists = false;
                            }
                        }
                        else
                        {
                            logSrtpInfo("invalid formatting encountered:  missing whitespace after second audio m-line port...\n");
                            audioExists = false;
                        }
                    }
                    else
                    {
                        logSrtpInfo("NO second audio m-line found...\n");
                        audioExists = false;
                    }
                }
            }
            else
            {
                logSrtpInfo("invalid formatting encountered:  missing whitespace after first audio m-line port...\n");
                audioExists = false;
            }
        }
        else
        {
            logSrtpInfo("NO first audio m-line found...\n");
            audioExists = false;
        }

        cur_pos = pos2;

        if (audioExists &&
            (((amsection_limit != std::string::npos) && (cur_pos != std::string::npos) && (cur_pos < amsection_limit)) ||
             ((amsection_limit == std::string::npos) && (vmsection_limit == std::string::npos) && (cur_pos != std::string::npos))))
        {
            // AUDIO "m=audio" prefix found...
            pA.audio_found = true;

            mline_sol = msgstr.find(SDP_AUDIOCRYPTO_PREFIX, cur_pos/*0*/, 10);
            if (mline_sol != std::string::npos) {
                // PRIMARY AUDIO "a:crypto:" crypto prefix found
                mline_eol = msgstr.find("\n", mline_sol, 1);
                if (mline_eol != std::string::npos) {
                    mline_contents = msgstr.substr(mline_sol, mline_eol);
                    sscanf(mline_contents.c_str(), "\na=crypto:%d %s inline:%s %s", &pA.primary_audio_cryptotag,
                                                                                    pA.primary_audio_cryptosuite,
                                                                                    pA.primary_audio_cryptokeyparams,
                                                                                    crypto_audio_sessionparams);
                    checkUESRTP = strstr(crypto_audio_sessionparams, "UNENCRYPTED_SRTP");
                    if (checkUESRTP) {
                        logSrtpInfo("call::extract_srtp_remote_info():  Detected UNENCRYPTED_SRTP token for PRIMARY AUDIO\n");
                        pA.primary_unencrypted_audio_srtp = true;
                    } else {
                        logSrtpInfo("call::extract_srtp_remote_info():  No UNENCRYPTED_SRTP token detected for PRIMARY AUDIO\n");
                        pA.primary_unencrypted_audio_srtp = false;
                    }
                }
            }

            // Look for end-of-audio-media section
            msection_limit = msgstr.find("\nm=", mline_eol+1, 3);

            mline_sol = msgstr.find(SDP_AUDIOCRYPTO_PREFIX, mline_eol+1, 10);
            if (((msection_limit != std::string::npos) && (mline_sol != std::string::npos) && (mline_sol < msection_limit)) ||
                ((msection_limit == std::string::npos) && (mline_sol != std::string::npos))) {
                // SECONDARY AUDIO "a:crypto:" crypto prefix found
                mline_eol = msgstr.find("\n", mline_sol, 1);
                if (mline_eol != std::string::npos) {
                    mline_contents = msgstr.substr(mline_sol, mline_eol);
                    sscanf(mline_contents.c_str(), "\na=crypto:%d %s inline:%s %s", &pA.secondary_audio_cryptotag,
                                                                                    pA.secondary_audio_cryptosuite,
                                                                                    pA.secondary_audio_cryptokeyparams,
                                                                                    crypto_audio_sessionparams);
                    checkUESRTP = strstr(crypto_audio_sessionparams, "UNENCRYPTED_SRTP");
                    if (checkUESRTP) {
                        logSrtpInfo("call::extract_srtp_remote_info():  Detected UNENCRYPTED_SRTP token for SECONDARY AUDIO\n");
                        pA.secondary_unencrypted_audio_srtp = true;
                    } else {
                        logSrtpInfo("call::extract_srtp_remote_info():  No UNENCRYPTED_SRTP token detected for SECONDARY AUDIO\n");
                        pA.secondary_unencrypted_audio_srtp = false;
                    }
                }
            }
        }

        /* --------------------------------------------------------------
         * Try to find a VIDEO MLINE
         * -------------------------------------------------------------- */
        pos1 = msgstr.find(SDP_VIDEOPORT_PREFIX, 0, 8);
        if (pos1 != std::string::npos)
        {
            pos1 += 8; /* skip SDP_VIDEOPORT_PREFIX */
            pos1 += 1; /* skip first whitespace */
            pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
            if (pos2 != std::string::npos)
            {
                sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
                sscanf(sub.c_str(), "%d", &video_port); /* parse port substring as integer */
                if (video_port != 0)
                {
                    logSrtpInfo("found first ACTIVE video m-line with NON-ZERO port [%d]...\n", video_port);
                    videoExists = true;
                }
                else
                {
                    logSrtpInfo("found first INACTIVE video m-line (e.g. with ZERO port)...\n");

                    pos1 = msgstr.find(SDP_VIDEOPORT_PREFIX, pos2, 8);
                    if (pos1 != std::string::npos)
                    {
                        pos1 += 8; /* skip SDP_VIDEOPORT_PREFIX  */
                        pos1 += 1; /* skip first whitespace */
                        pos2 = msgstr.find(" ", pos1); /* find second whitespace AFTER port */
                        if (pos2 != std::string::npos)
                        {
                            sub = msgstr.substr(pos1, pos2-pos1); /* extract port substring */
                            sscanf(sub.c_str(), "%d", &video_port);
                            if (video_port != 0)
                            {
                                logSrtpInfo("found second ACTIVE video m-line with NON-ZERO port [%d]...\n", video_port);
                                videoExists = true;
                            }
                            else
                            {
                                logSrtpInfo("found second INACTIVE video m-line (e.g. with ZERO port)...\n");
                                videoExists = false;
                            }
                        }
                        else
                        {
                            logSrtpInfo("invalid formatting encountered:  missing whitespace after second video m-line port...\n");
                            videoExists = false;
                        }
                    }
                    else
                    {
                        logSrtpInfo("NO second video m-line found...\n");
                        videoExists = false;
                    }
                }
            }
            else
            {
                logSrtpInfo("invalid formatting encountered:  missing whitespace after first video m-line port...\n");
                videoExists = false;
            }
        }
        else
        {
            logSrtpInfo("NO first video m-line found...\n");
            videoExists = false;
        }

        cur_pos = pos2;

        if (videoExists &&
            (((vmsection_limit != std::string::npos) && (cur_pos != std::string::npos) && (cur_pos < vmsection_limit)) ||
             ((vmsection_limit == std::string::npos) && (amsection_limit == std::string::npos) && (cur_pos != std::string::npos))))
        {
            // VIDEO "m=video" prefix found...
            pV.video_found = true;

            mline_sol = msgstr.find(SDP_VIDEOCRYPTO_PREFIX, cur_pos/*mline_eol+1*/, 10);
            if (mline_sol != std::string::npos) {
                // PRIMARY VIDEO "a:crypto:" crypto prefix found
                mline_eol = msgstr.find("\n", mline_sol, 1);
                if (mline_eol != std::string::npos) {
                    mline_contents = msgstr.substr(mline_sol, mline_eol);
                    sscanf(mline_contents.c_str(), "\na=crypto:%d %s inline:%s %s", &pV.primary_video_cryptotag,
                                                                                    pV.primary_video_cryptosuite,
                                                                                    pV.primary_video_cryptokeyparams,
                                                                                    crypto_video_sessionparams);
                    checkUESRTP = strstr(crypto_video_sessionparams, "UNENCRYPTED_SRTP");
                    if (checkUESRTP) {
                        logSrtpInfo("call::extract_srtp_remote_info():  Detected UNENCRYPTED_SRTP token for PRIMARY VIDEO\n");
                        pV.primary_unencrypted_video_srtp = true;
                    } else {
                        logSrtpInfo("call::extract_srtp_remote_info():  No UNENCRYPTED_SRTP token detected for PRIMARY VIDEO\n");
                        pV.primary_unencrypted_video_srtp = false;
                    }
                }
            }

            // Look for end-of-video-media section
            msection_limit = msgstr.find("\nm=", mline_eol+1, 3);

            mline_sol = msgstr.find(SDP_VIDEOCRYPTO_PREFIX, mline_eol+1, 10);
            if (((msection_limit != std::string::npos) && (mline_sol != std::string::npos) && (mline_sol < msection_limit)) ||
                ((msection_limit == std::string::npos) && (mline_sol != std::string::npos))) {
                // SECONDARY VIDEO "a:crypto:" crypto prefix found
                mline_eol = msgstr.find("\n", mline_sol, 1);
                if (mline_eol != std::string::npos) {
                    mline_contents = msgstr.substr(mline_sol, mline_eol);
                    sscanf(mline_contents.c_str(), "\na=crypto:%d %s inline:%s %s", &pV.secondary_video_cryptotag,
                                                                                    pV.secondary_video_cryptosuite,
                                                                                    pV.secondary_video_cryptokeyparams,
                                                                                    crypto_video_sessionparams);
                    checkUESRTP = strstr(crypto_video_sessionparams, "UNENCRYPTED_SRTP");
                    if (checkUESRTP) {
                        logSrtpInfo("call::extract_srtp_remote_info():  Detected UNENCRYPTED_SRTP token for SECONDARY VIDEO\n");
                        pV.secondary_unencrypted_video_srtp = true;
                    } else {
                        logSrtpInfo("call::extract_srtp_remote_info():  No UNENCRYPTED_SRTP token detected for SECONDARY VIDEO\n");
                        pV.secondary_unencrypted_video_srtp = false;
                    }
                }
            }
        }

        free(sdp_body_remember);

        return 0; /* SUCCESS -- parsed SDP SRTP INFO */
    } else {
      return -1; /* FAILURE -- No SDP body found */
    }
}
#endif // USE_TLS

/******* Very simple hash for retransmission detection  *******/

unsigned long call::hash(const char * msg)
{
    unsigned long hash = 0;
    int c;

    if (rtcheck == RTCHECK_FULL) {
        while ((c = *msg++))
            hash = c + (hash << 6) + (hash << 16) - hash;
    } else if (rtcheck == RTCHECK_LOOSE) {
        /* Based on section 11.5 (bullet 2) of RFC2543 we only take into account
         * the To, From, Call-ID, and CSeq values. */
        const char *hdr = get_header_content(msg, "To:");
        while ((c = *hdr++))
            hash = c + (hash << 6) + (hash << 16) - hash;
        hdr = get_header_content(msg, "From:");
        while ((c = *hdr++))
            hash = c + (hash << 6) + (hash << 16) - hash;
        hdr = get_header_content(msg, "Call-ID:");
        while ((c = *hdr++))
            hash = c + (hash << 6) + (hash << 16) - hash;
        hdr = get_header_content(msg, "CSeq:");
        while ((c = *hdr++))
            hash = c + (hash << 6) + (hash << 16) - hash;
        /* For responses, we should also consider the code and body (if any),
         * because they are not nearly as well defined as the request retransmission. */
        if (!strncmp(msg, "SIP/2.0", strlen("SIP/2.0"))) {
            /* Add the first line into the hash. */
            hdr = msg + strlen("SIP/2.0");
            while ((c = *hdr++) && (c != '\r'))
                hash = c + (hash << 6) + (hash << 16) - hash;
            /* Add the body (if any) into the hash. */
            hdr = strstr(msg, "\r\n\r\n");
            if (hdr) {
                hdr += strlen("\r\n\r\n");
                while ((c = *hdr++))
                    hash = c + (hash << 6) + (hash << 16) - hash;
            }
        }
    } else {
        ERROR("Internal error: Invalid rtcheck %d", rtcheck);
    }

    return hash;
}

/******************* Call class implementation ****************/
call::call(const char *p_id, bool use_ipv6, int userId, struct sockaddr_storage *dest) : listener(p_id, true)
{
    init(main_scenario, nullptr, dest, p_id, userId, use_ipv6, false, false);
}

call::call(const char *p_id, SIPpSocket *socket, struct sockaddr_storage *dest) : listener(p_id, true)
{
    init(main_scenario, socket, dest, p_id, 0 /* No User. */, socket->ss_ipv6, false /* Not Auto. */, false);
}

call::call(scenario * call_scenario, SIPpSocket *socket, struct sockaddr_storage *dest, const char * p_id, int userId, bool ipv6, bool isAutomatic, bool isInitialization) : listener(p_id, true)
{
    init(call_scenario, socket, dest, p_id, userId, ipv6, isAutomatic, isInitialization);
}

call *call::add_call(int userId, bool ipv6, struct sockaddr_storage *dest)
{
    static char call_id[MAX_HEADER_LEN];

    const char * src = call_id_string;
    int count = 0;

    if(!next_number) {
        next_number ++;
    }

    while (*src && count < MAX_HEADER_LEN-1) {
        if (*src == '%') {
            ++src;
            switch(*src++) {
            case 'u':
                count += snprintf(&call_id[count], MAX_HEADER_LEN-count-1, "%u", next_number);
                break;
            case 'p':
                count += snprintf(&call_id[count], MAX_HEADER_LEN-count-1, "%u", pid);
                break;
            case 's':
                count += snprintf(&call_id[count], MAX_HEADER_LEN-count-1, "%s", local_ip);
                break;
            default:      // treat all unknown sequences as %%
                call_id[count++] = '%';
                break;
            }
        } else {
            call_id[count++] = *src++;
        }
    }
    call_id[count] = 0;

    return new call(main_scenario, nullptr, dest, call_id, userId, ipv6, false /* Not Auto. */, false);
}


void call::init(scenario * call_scenario, SIPpSocket *socket, struct sockaddr_storage *dest, const char * p_id, int userId, bool ipv6, bool isAutomatic, bool isInitCall)
{
#ifdef USE_TLS
    _srtpctxdebugfile = nullptr;

    if (srtpcheck_debug)
    {
        if (sendMode == MODE_CLIENT)
        {
            _srtpctxdebugfile = fopen("srtpctxdebugfile_uac", "w");
        }
        else if (sendMode == MODE_SERVER)
        {
            _srtpctxdebugfile = fopen("srtpctxdebugfile_uas", "w");
        }

        if (_srtpctxdebugfile == nullptr)
        {
            /* error encountered opening srtp ctx debug file */
            WARNING("Error encountered opening srtp ctx debug file");
        }
    }
#endif // USE_TLS

    _sessionStateCurrent = eNoSession;
    _sessionStateOld = eNoSession;

    this->call_scenario = call_scenario;
    zombie = false;

    debugBuffer = nullptr;
    debugLength = 0;

    msg_index = 0;
    last_send_index = 0;
    last_send_msg = nullptr;
    last_send_len = 0;

    last_recv_hash = 0;
    last_recv_index = -1;
    last_recv_msg = nullptr;

    last_recv_invite_cseq = 0;

    recv_retrans_hash = 0;
    recv_retrans_recv_index = -1;
    recv_retrans_send_index = -1;

    dialog_route_set = nullptr;
    next_req_url = nullptr;

    cseq = 0;

    next_retrans = 0;
    nb_retrans = 0;
    nb_last_delay = 0;

    paused_until = 0;

    call_port = 0;
    comp_state = nullptr;

    start_time = clock_tick;
    call_established=false ;
    ack_is_pending=false ;
    last_recv_msg = nullptr;
    cseq = base_cseq;
    nb_last_delay = 0;
    use_ipv6 = ipv6;
    queued_msg = nullptr;

    dialog_authentication = nullptr;
    dialog_challenge_type = 0;

    next_nonce_count = 1;

#ifdef USE_TLS
    //
    // JLSRTP CLIENT context constants
    //
    if (srtpcheck_debug)
    {
        if (sendMode == MODE_CLIENT)
        {
            logSrtpInfo("call::init():  (a) TX-UAC-AUDIO SRTP context - CLIENT setting SRTP header size to 12\n");
            _txUACAudio.setSrtpHeaderSize(12);
            logSrtpInfo("call::init():  (a) TX-UAC-VIDEO SRTP context - CLIENT setting SRTP header size to 12\n");
            _txUACVideo.setSrtpHeaderSize(12);
            logSrtpInfo("call::init():  (b) RX-UAC-AUDIO SRTP context - CLIENT setting SRTP header size to 12\n");
            _rxUACAudio.setSrtpHeaderSize(12);
            logSrtpInfo("call::init():  (b) RX-UAC-VIDEO SRTP context - CLIENT setting SRTP header size to 12\n");
            _rxUACVideo.setSrtpHeaderSize(12);
        }
    }

    //
    // JLSRTP SERVER context constants
    //
    if (srtpcheck_debug)
    {
        if (sendMode == MODE_SERVER)
        {
            logSrtpInfo("call::init():  (c) RX-UAS-AUDIO SRTP context - SERVER setting SRTP header size to 12\n");
            _rxUASAudio.setSrtpHeaderSize(12);
            logSrtpInfo("call::init():  (c) RX-UAS-VIDEO SRTP context - SERVER setting SRTP header size to 12\n");
            _rxUASVideo.setSrtpHeaderSize(12);
            logSrtpInfo("call::init():  (d) TX-UAS-AUDIO SRTP context - SERVER setting SRTP header size to 12\n");
            _txUASAudio.setSrtpHeaderSize(12);
            logSrtpInfo("call::init():  (d) TX-UAS-VIDEO SRTP context - SERVER setting SRTP header size to 12\n");
            _txUASVideo.setSrtpHeaderSize(12);
        }
    }

    memset(_pref_audio_cs_out, 0, sizeof(_pref_audio_cs_out));
    memset(_pref_video_cs_out, 0, sizeof(_pref_video_cs_out));
#endif // USE_TLS
    /* check and warn on rtpstream_new_call result? -> error alloc'ing mem */
    rtpstream_new_call(&rtpstream_callinfo);

#ifdef PCAPPLAY
    hasMediaInformation = 0;
    play_args_a.last_seq_no = 1200;
    play_args_v.last_seq_no = 2400;
#endif

    call_remote_socket = nullptr;
    if (socket) {
        associate_socket(socket);
        socket->ss_count++;
    } else {
        call_socket = nullptr;
    }
    if (dest) {
        memcpy(&call_peer, dest, sizeof(call_peer));
    } else {
        memset(&call_peer, 0, sizeof(call_peer));
    }

    // initialising the CallVariable with the Scenario variable
    int i;
    VariableTable *userVars = nullptr;
    bool putUserVars = false;
    if (userId) {
        int_vt_map::iterator it = userVarMap.find(userId);
        if (it != userVarMap.end()) {
            userVars = it->second;
        }
    } else {
        userVars = new VariableTable(userVariables);
        /* Creating this table creates a reference to it, but if it is really used,
         * then the refcount will be increased. */
        putUserVars = true;
    }
    if (call_scenario->allocVars->size > 0) {
        M_callVariableTable = new VariableTable(userVars, call_scenario->allocVars->size);
    } else if (userVars && userVars->size > 0) {
        M_callVariableTable = userVars->getTable();
    } else if (globalVariables->size > 0) {
        M_callVariableTable = globalVariables->getTable();
    } else {
        M_callVariableTable = nullptr;
    }
    if (putUserVars) {
        userVars->putTable();
    }

    if (call_scenario->transactions.size() > 0) {
        transactions = (struct txnInstanceInfo *)malloc(sizeof(txnInstanceInfo) * call_scenario->transactions.size());
        memset(transactions, 0, sizeof(struct txnInstanceInfo) * call_scenario->transactions.size());
    } else {
        transactions = nullptr;
    }

    // If not updated by a message we use the start time
    // information to compute rtd information
    start_time_rtd = (unsigned long long *)malloc(sizeof(unsigned long long) * call_scenario->stats->nRtds());
    if (!start_time_rtd) {
        ERROR("Could not allocate RTD times!");
    }
    rtd_done = (bool *)malloc(sizeof(bool) * call_scenario->stats->nRtds());
    if (!start_time_rtd) {
        ERROR("Could not allocate RTD done!");
    }
    for (i = 0; i < call_scenario->stats->nRtds(); i++) {
        start_time_rtd[i] = getmicroseconds();
        rtd_done[i] = false;
    }

    // by default, last action result is NO_ERROR
    last_action_result = call::E_AR_NO_ERROR;

    this->userId = userId;

    /* For automatic answer calls to an out of call request, we must not */
    /* increment the input files line numbers to not disturb */
    /* the input files read mechanism (otherwise some lines risk */
    /* to be systematically skipped */
    if (!isAutomatic) {
        m_lineNumber = new file_line_map();
        for (file_map::iterator file_it = inFiles.begin();
                file_it != inFiles.end();
                file_it++) {
            (*m_lineNumber)[file_it->first] = file_it->second->nextLine(userId);
        }
    } else {
        m_lineNumber = nullptr;
    }
    this->initCall = isInitCall;

#ifdef PCAPPLAY
    memset(&(play_args_a.to), 0, sizeof(struct sockaddr_storage));
    memset(&(play_args_i.to), 0, sizeof(struct sockaddr_storage));
    memset(&(play_args_v.to), 0, sizeof(struct sockaddr_storage));
    memset(&(play_args_a.from), 0, sizeof(struct sockaddr_storage));
    memset(&(play_args_i.from), 0, sizeof(struct sockaddr_storage));
    memset(&(play_args_v.from), 0, sizeof(struct sockaddr_storage));
    hasMediaInformation = 0;
    media_thread = 0;
#endif

    peer_tag = nullptr;
    recv_timeout = 0;
    send_timeout = 0;
    timewait = false;

    if (!isAutomatic) {
        /* Not advancing the number is safe, because for automatic calls we do not
         * assign the identifier,  the only other place it is used is for the auto
         * media port. */
        number = next_number++;

        if (use_tdmmap) {
            tdm_map_number = get_tdm_map_number();
            if (tdm_map_number == 0) {
                /* Can't create the new call */
                WARNING("Can't create new outgoing call: all tdm_map circuits busy");
                computeStat(CStat::E_CALL_FAILED);
                computeStat(CStat::E_FAILED_OUTBOUND_CONGESTION);
                this->zombie = true;
                return;
            }
            /* Mark the entry in the list as busy */
            tdm_map[tdm_map_number - 1] = true;
        } else {
            tdm_map_number = 0;
        }
    }

    callDebug("Starting call %s\n", id);

    setRunning();
}

bool call::checkAckCSeq(const char* msg)
{
    static char request[65];
    unsigned long int rcseq = 0;
    const char* ptr = nullptr;

    rcseq = get_cseq_value(msg);
    memset(request, 0, sizeof(request));

    if ((msg[0] == 'S') &&
        (msg[1] == 'I') &&
        (msg[2] == 'P') &&
        (msg[3] == '/') &&
        (msg[4] == '2') &&
        (msg[5] == '.') &&
        (msg[6] == '0')) {
        request[0]=0;
    } else if ((ptr = strchr(msg, ' '))) {
        if ((ptr - msg) < 64) {
            memcpy(request, msg, ptr - msg);
            request[ptr - msg] = 0;
        } else {
            ERROR("SIP method too long in received message '%s'", msg);
        }
    } else {
        ERROR("Invalid SIP message received '%s'", msg);
    }

    if ((default_behaviors & DEFAULT_BEHAVIOR_BADCSEQ) &&
        !strncmp(request, "ACK", 3) &&
        (rcseq != last_recv_invite_cseq)) {
        return false;
    } else {
        return true;
    }
}

int call::_callDebug(const char *fmt, ...)
{
    va_list ap;

    if (!useCallDebugf) {
        return 0;
    }

    /* First we figure out how much to allocate. */
    va_start(ap, fmt);
    int ret = vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);

    debugBuffer = (char *)realloc(debugBuffer, debugLength + ret + TIME_LENGTH + 2);
    if (!debugBuffer) {
        ERROR("Could not allocate buffer (%d bytes) for callDebug file!", debugLength + ret + TIME_LENGTH + 2);
    }

    struct timeval now;
    gettimeofday(&now, nullptr);
    debugLength += snprintf(debugBuffer + debugLength, TIME_LENGTH + 2, "%s ", CStat::formatTime(&now, rfc3339));

    va_start(ap, fmt);
    debugLength += vsnprintf(debugBuffer + debugLength, ret + 1, fmt, ap);
    va_end(ap);

    return ret;
}

call::~call()
{
    computeStat(CStat::E_ADD_CALL_DURATION, clock_tick - start_time);

    if(comp_state) {
        comp_free(&comp_state);
    }

    if (call_remote_socket && (call_remote_socket != main_remote_socket)) {
        call_remote_socket->close();
    }

    /* Deletion of the call variable */
    if(M_callVariableTable) {
        M_callVariableTable->putTable();
    }
    if (m_lineNumber) {
        delete m_lineNumber;
    }
    if (userId) {
        CallGenerationTask::free_user(userId);
    }

    if (transactions) {
        for (unsigned int i = 0; i < call_scenario->transactions.size(); i++) {
            free(transactions[i].txnID);
        }
        free(transactions);
    }

    if (last_recv_msg) {
        free(last_recv_msg);
    }
    if (last_send_msg) {
        free(last_send_msg);
    }
    if (peer_tag) {
        free(peer_tag);
    }

    if (dialog_route_set) {
        free(dialog_route_set);
    }

    if (next_req_url) {
        free(next_req_url);
    }

    rtpstream_end_call(&rtpstream_callinfo);

    if (dialog_authentication) {
        free(dialog_authentication);
    }

    if (use_tdmmap) {
        tdm_map[tdm_map_number] = false;
    }

# ifdef PCAPPLAY
    if (media_thread != 0) {
        pthread_cancel(media_thread);
        pthread_join(media_thread, nullptr);
    }
#endif

    free(start_time_rtd);
    free(rtd_done);
    free(debugBuffer);

#ifdef USE_TLS
    if (srtpcheck_debug)
    {
        fclose(_srtpctxdebugfile);
        _srtpctxdebugfile = nullptr;
    }
#endif // USE_TLS
}

void call::setRtpEchoErrors(int value)
{
    if (!initCall)
    {
        call_scenario->stats->setRtpEchoErrors(value);
    }
}

int call::getRtpEchoErrors()
{
    if (!initCall)
    {
        return call_scenario->stats->getRtpEchoErrors();
    }
    else
    {
        return 0;
    }
}

void call::computeStat (CStat::E_Action P_action)
{
    if (initCall) {
        return;
    }
    call_scenario->stats->computeStat(P_action);
}

void call::computeStat (CStat::E_Action P_action, unsigned long P_value)
{
    if (initCall) {
        return;
    }
    call_scenario->stats->computeStat(P_action, P_value);
}

void call::computeStat (CStat::E_Action P_action, unsigned long P_value, int which)
{
    if (initCall) {
        return;
    }
    call_scenario->stats->computeStat(P_action, P_value, which);
}

/* Dump call info to error log. */
void call::dump()
{
    char s[MAX_HEADER_LEN];
    int slen = sizeof(s);
    int written;

    written = snprintf(s, slen, "%s: State %d", id, msg_index);
    if (next_retrans) {
        written += snprintf(s + written, slen - written, " (next retrans %u)", next_retrans);
    }
    if (paused_until) {
        written += snprintf(s + written, slen - written, " (paused until %u)", paused_until);
    }
    if (recv_timeout) {
        written += snprintf(s + written, slen - written, " (recv timeout %u)", recv_timeout);
    }
    if (send_timeout) {
        written += snprintf(s + written, slen - written, " (send timeout %u)", send_timeout);
    }
    WARNING("%s", s);
}

bool call::connect_socket_if_needed()
{
    bool existing;

    if(call_socket) return true;
    if(!multisocket) return true;

    if(transport == T_UDP) {
        struct sockaddr_storage saddr;

        if(sendMode != MODE_CLIENT)
            return true;

        char peripaddr[256];
        if (!peripsocket) {
            if ((associate_socket(SIPpSocket::new_sipp_call_socket(use_ipv6, transport, &existing))) == nullptr) {
                ERROR_NO("Unable to get a UDP socket (1)");
            }
        } else {
            char *tmp = peripaddr;
            getFieldFromInputFile(ip_file, peripfield, nullptr, tmp);
            auto i = map_perip_fd.find(peripaddr);
            if (i == map_perip_fd.end()) {
                // Socket does not exist
                if ((associate_socket(SIPpSocket::new_sipp_call_socket(use_ipv6, transport, &existing))) == nullptr) {
                    ERROR_NO("Unable to get a UDP socket (2)");
                } else {
                    /* Ensure that it stays persistent, because it is recorded in the map. */
                    call_socket->ss_count++;
                    map_perip_fd[peripaddr] = call_socket;
                }
            } else {
                // Socket exists already
                associate_socket(i->second);
                existing = true;
                i->second->ss_count++;
            }
        }
        if (existing) {
            return true;
        }

        memcpy(&saddr, &local_addr_storage, sizeof(struct sockaddr_storage));
        if (use_ipv6) {
            saddr.ss_family       = AF_INET6;
        } else {
            saddr.ss_family       = AF_INET;
        }

        if (peripsocket) {
            gai_getsockaddr(&saddr, peripaddr, local_port, AI_PASSIVE, AF_UNSPEC);
        }

        if (sipp_bind_socket(call_socket, &saddr, &call_port)) {
            ERROR_NO("Unable to bind UDP socket");
        }
    } else { /* TCP, SCTP or TLS. */
        struct sockaddr_storage *L_dest = &remote_sockaddr;

        if ((associate_socket(SIPpSocket::new_sipp_call_socket(use_ipv6, transport, &existing))) == nullptr) {
            ERROR_NO("Unable to get a TCP/SCTP/TLS socket");
        }
        call_socket->ss_count++;

        if (existing) {
            return true;
        }

        sipp_customize_socket(call_socket);

        if (use_remote_sending_addr) {
            L_dest = &remote_sending_sockaddr;
        }

        if (call_socket->connect(L_dest)) {
            if (reconnect_allowed()) {
                if(errno == EINVAL) {
                    /* This occurs sometime on HPUX but is not a true INVAL */
                    WARNING("Unable to connect a TCP/SCTP/TLS socket, remote peer error");
                } else {
                    WARNING("Unable to connect a TCP/SCTP/TLS socket");
                }
                /* This connection failed.  We must be in multisocket mode, because
                     * otherwise we would already have a call_socket.  This call can not
                     * succeed, but does not affect any of our other calls. We do decrement
                 * the reconnection counter however. */
                if (reset_number != -1) {
                    reset_number--;
                }

                computeStat(CStat::E_CALL_FAILED);
                computeStat(CStat::E_FAILED_TCP_CONNECT);
                delete this;

                return false;
            } else {
                if(errno == EINVAL) {
                    /* This occurs sometime on HPUX but is not a true INVAL */
                    ERROR("Unable to connect a TCP/SCTP/TLS socket, remote peer error");
                } else {
                    ERROR_NO("Unable to connect a TCP/SCTP/TLS socket");
                }
            }
        }
        call_port = call_socket->ss_port;
    }
    return true;
}

bool call::lost(int index)
{
    static int inited = 0;
    double percent = global_lost;

    if(!lose_packets) return false;

    if (call_scenario->messages[index]->lost >= 0) {
        percent = call_scenario->messages[index]->lost;
    }

    if (percent == 0) {
        return false;
    }

    if(!inited) {
        srand((unsigned int) time(nullptr));
        inited = 1;
    }

    return (((double)rand() / (double)RAND_MAX) < (percent / 100.0));
}

int call::send_raw(const char * msg, int index, int len)
{
    SIPpSocket *sock;
    int rc;

    callDebug("Sending %s message for call %s (index %d, hash %lu):\n%s\n\n",
              TRANSPORT_TO_STRING(transport), id, index, hash(msg), msg);

    if((index!=-1) && (lost(index))) {
        TRACE_MSG("%s message voluntary lost (while sending).", TRANSPORT_TO_STRING(transport));
        callDebug("%s message voluntary lost (while sending) (index %d, hash %lu).\n",
                  TRANSPORT_TO_STRING(transport), index, hash(msg));

        if(comp_state) {
            comp_free(&comp_state);
        }
        call_scenario->messages[index] -> nb_lost++;
        return 0;
    }

    sock = call_socket;

    if ((use_remote_sending_addr) && (sendMode == MODE_SERVER)) {
        if (!call_remote_socket) {
            if (multisocket || !main_remote_socket) {
                struct sockaddr_storage *L_dest = &remote_sending_sockaddr;

                if((call_remote_socket= new_sipp_socket(use_ipv6, transport)) == nullptr) {
                    ERROR_NO("Unable to get a socket for rsa option");
                }

                sipp_customize_socket(call_remote_socket);

                if(transport != T_UDP) {
                    if (call_remote_socket->connect(L_dest)) {
                        if(errno == EINVAL) {
                            /* This occurs sometime on HPUX but is not a true INVAL */
                            ERROR("Unable to connect a %s socket for rsa option, remote peer error", TRANSPORT_TO_STRING(transport));
                        } else {
                            ERROR_NO("Unable to connect a socket for rsa option");
                        }
                    }
                }
                if (!multisocket) {
                    main_remote_socket = call_remote_socket;
                }
            }

            if (!multisocket) {
                call_remote_socket = main_remote_socket;
                main_remote_socket->ss_count++;
            }
        }
        sock=call_remote_socket ;
    }

    // If the length hasn't been explicitly specified, treat the message as a string
    if (len==0) {
        len = strlen(msg);
    }

    assert(sock);

    rc = sock->write(msg, len, WS_BUFFER, &call_peer);
    if(rc < 0 && errno == EWOULDBLOCK) {
        return rc;
    }

    if(rc < 0) {
        computeStat(CStat::E_CALL_FAILED);
        computeStat(CStat::E_FAILED_CANNOT_SEND_MSG);
        delete this;
    }

    return rc; /* OK */
}

/* This method is used to send messages that are not */
/* part of the XML scenario                          */
void call::sendBuffer(char * msg, int len)
{
    /* call send_raw but with a special scenario index */
    if (send_raw(msg, -1, len) < 0) {
        if (sendbuffer_warn) {
            ERROR_NO("Error sending raw message");
        } else {
            WARNING_NO("Error sending raw message");
        }
    }
}

char * call::get_header_field_code(const char *msg, const char * name)
{
    static char code[MAX_HEADER_LEN];
    const char * last_header;
    int i;

    last_header = nullptr;
    i = 0;
    /* If we find the field in msg */
    last_header = get_header_content(msg, name);
    if(last_header) {
        /* Extract the integer value of the field */
        while(isspace(*last_header)) last_header++;
        sscanf(last_header, "%d", &i);
        sprintf(code, "%s %d", name, i);
    }
    return code;
}

char * call::get_last_header(const char * name)
{
    int len;

    if((!last_recv_msg) || (!strlen(last_recv_msg))) {
        return nullptr;
    }

    len = strlen(name);

    /* Ideally this check should be moved to the XML parser so that it is not
     * along a critical path.  We could also handle lowercasing there. */
    if (len > MAX_HEADER_LEN) {
        ERROR("call::get_last_header: Header to parse bigger than %d (%zu)", MAX_HEADER_LEN, strlen(name));
    }

    if (name[len - 1] == ':') {
        return get_header(last_recv_msg, name, false);
    } else {
        char with_colon[MAX_HEADER_LEN+2];
        snprintf(with_colon, MAX_HEADER_LEN+2, "%s:", name);
        return get_header(last_recv_msg, with_colon, false);
    }
}

/* Return the last request URI from the To header. On any error returns the
 * empty string.  The caller must free the result. */
char * call::get_last_request_uri()
{
    char * tmp;
    char * tmp2;
    char * last_request_uri;
    int tmp_len;

    char * last_To = get_last_header("To:");
    if (!last_To) {
        return strdup("");
    }

    tmp = strchr(last_To, '<');
    if (!tmp) {
        return strdup("");
    }
    tmp++;

    tmp2 = strchr(last_To, '>');
    if (!tmp2) {
        return strdup("");
    }

    tmp_len = strlen(tmp) - strlen(tmp2);
    if (tmp_len < 0) {
        return strdup("");
    }

    if (!(last_request_uri = (char *)malloc(tmp_len + 1))) {
        ERROR("Cannot allocate!");
    }

    last_request_uri[0] = '\0';
    if (tmp_len > 0) {
        memcpy(last_request_uri, tmp, tmp_len);
    }
    last_request_uri[tmp_len] = '\0';

    return last_request_uri;
}

char * call::send_scene(int index, int *send_status, int *len)
{
#define MAX_MSG_NAME_SIZE 30
    static char msg_name[MAX_MSG_NAME_SIZE];
    char *L_ptr1 ;
    char *L_ptr2 ;
    int uselen = 0;

    assert(send_status);

    /* Socket port must be known before string substitution */
    if (!connect_socket_if_needed()) {
        *send_status = -2;
        return nullptr;
    }

    assert(call_socket);

    assert(call_scenario->messages[index]->send_scheme);

    if (!len) {
        len = &uselen;
    }

    char * dest;
    dest = createSendingMessage(call_scenario->messages[index]->send_scheme, index, len);

    if (!dest) {
        *send_status = -2;
        return nullptr;
    }

    L_ptr1=msg_name ;
    L_ptr2=dest ;
    while ((*L_ptr2 != ' ') && (*L_ptr2 != '\n') && (*L_ptr2 != '\t'))  {
        *L_ptr1 = *L_ptr2;
        L_ptr1 ++;
        L_ptr2 ++;
    }
    *L_ptr1 = '\0' ;

    if (strcmp(msg_name, "ACK") == 0) {
        call_established = true ;
        ack_is_pending = false ;
    }

    *send_status = send_raw(dest, index, *len);

    return dest;
}

void call::do_bookkeeping(message *curmsg)
{
    /* If this message increments a counter, do it now. */
    if (curmsg -> counter) {
        computeStat(CStat::E_ADD_GENERIC_COUNTER, 1, curmsg->counter - 1);
    }

    /* If this message can be used to compute RTD, do it now */
    if (curmsg->start_rtd) {
        start_time_rtd[curmsg->start_rtd - 1] = getmicroseconds();
    }

    if (curmsg->stop_rtd) {
        int rtd = curmsg->stop_rtd;
        if (!rtd_done[rtd - 1]) {
            unsigned long long start = start_time_rtd[rtd - 1];
            unsigned long long end = getmicroseconds();

            if (dumpInRtt) {
                call_scenario->stats->computeRtt(start, end, rtd);
            }

            computeStat(CStat::E_ADD_RESPONSE_TIME_DURATION,
                        (end - start) / 1000, rtd - 1);

            if (!curmsg->repeat_rtd) {
                rtd_done[rtd - 1] = true;
            }
        }
    }
}

void call::tcpClose()
{
    terminate(CStat::E_FAILED_TCP_CLOSED);
}

void call::terminate(CStat::E_Action reason)
{
    char reason_str[100];

    stopListening();

    // Call end -> was it successful?
    if(call::last_action_result != call::E_AR_NO_ERROR) {
        switch(call::last_action_result) {
        case call::E_AR_REGEXP_DOESNT_MATCH:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_REGEXP_DOESNT_MATCH);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "regexp match failure at index %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case call::E_AR_REGEXP_SHOULDNT_MATCH:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_REGEXP_SHOULDNT_MATCH);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "regexp matched, but shouldn't at index %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case call::E_AR_HDR_NOT_FOUND:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_REGEXP_HDR_NOT_FOUND);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "regexp header not found at index %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case E_AR_CONNECT_FAILED:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_TCP_CONNECT);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "connection failed %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case E_AR_RTPECHO_ERROR:
            computeStat(CStat::E_CALL_FAILED);
            setRtpEchoErrors(1);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "rtp echo error %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case call::E_AR_NO_ERROR:
        case call::E_AR_STOP_CALL:
            /* Do nothing. */
            break;
        case call::E_AR_TEST_DOESNT_MATCH:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_TEST_DOESNT_MATCH);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "test failure at index %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case call::E_AR_TEST_SHOULDNT_MATCH:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_TEST_SHOULDNT_MATCH);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "test succeeded, but shouldn't at index %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case call::E_AR_STRCMP_DOESNT_MATCH:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_STRCMP_DOESNT_MATCH);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "test failure at index %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        case call::E_AR_STRCMP_SHOULDNT_MATCH:
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_STRCMP_SHOULDNT_MATCH);
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "test succeeded, but shouldn't at index %d", msg_index);
                new deadcall(id, reason_str);
            }
            break;
        }
    } else {
        if (reason == CStat::E_CALL_SUCCESSFULLY_ENDED || timewait) {
            computeStat(CStat::E_CALL_SUCCESSFULLY_ENDED);
            if (deadcall_wait && !initCall) {
                new deadcall(id, "successful");
            }
        } else {
            computeStat(CStat::E_CALL_FAILED);
            if (reason != CStat::E_NO_ACTION) {
                computeStat(reason);
            }
            if (deadcall_wait && !initCall) {
                sprintf(reason_str, "failed at index %d", msg_index);
                new deadcall(id, reason_str);
            }
        }
    }
    delete this;
}

bool call::next()
{
    msgvec * msgs = &call_scenario->messages;
    if (initCall) {
        msgs = &call_scenario->initmessages;
    }

    int test;
    /* What is the next message index? */
    /* Default without branching: use the next message */
    int new_msg_index = msg_index + 1;
    /* If branch needed, overwrite this default */
    if (msg_index >= 0 && ((*msgs)[msg_index]->next >= 0) &&
            (((test = ((*msgs)[msg_index]->test)) == -1) ||
             M_callVariableTable->getVar(test)->isSet())) {
        /* Branching possible, check the probability */
        int chance = (*msgs)[msg_index]->chance;
        if ((chance <= 0) || (rand() > chance )) {
            /* Branch == overwrite with the 'next' attribute value */
            new_msg_index = (*msgs)[msg_index]->next;
        }
    }
    msg_index = new_msg_index;
    recv_timeout = 0;
    if (msg_index >= (int)((*msgs).size())) {
        terminate(CStat::E_CALL_SUCCESSFULLY_ENDED);
        return false;
    }

    return true;
}

bool call::executeMessage(message *curmsg)
{
    T_ActionResult actionResult = E_AR_NO_ERROR;

    if (curmsg->pause_distribution || curmsg->pause_variable != -1) {
        unsigned int pause;
        if (curmsg->pause_distribution) {
            double actualpause = curmsg->pause_distribution->sample();
            if (actualpause < 1) {
                // Protect against distribution samples that give
                // negative results (and so pause for ~50 hours when
                // cast to a unsigned int).
                pause = 0;
            } else {
                pause  = (unsigned int)actualpause;
            };
        } else {
            int varId = curmsg->pause_variable;
            pause = (int) M_callVariableTable->getVar(varId)->getDouble();
        }
        if (pause > INT_MAX) {
            pause = INT_MAX;
        }
        paused_until = clock_tick + pause;

        /* This state is used as the last message of a scenario, just for handling
         * final retransmissions. If the connection closes, we do not mark it is
         * failed. */
        this->timewait = curmsg->timewait;

        /* Increment the number of sessions in pause state */
        curmsg->sessions++;
        do_bookkeeping(curmsg);
        executeAction(nullptr, curmsg);
        callDebug("Pausing call until %d (is now %ld).\n", paused_until, clock_tick);
        setPaused();
        return true;
    } else if(curmsg -> M_type == MSG_TYPE_SENDCMD) {
        int send_status;

        if(next_retrans) {
            return true;
        }

        send_status = sendCmdMessage(curmsg);

        if(send_status != 0) { /* Send error */
            return false; /* call deleted */
        }
        curmsg -> M_nbCmdSent++;
        next_retrans = 0;

        do_bookkeeping(curmsg);
        executeAction(nullptr, curmsg);
        return(next());
    } else if(curmsg -> M_type == MSG_TYPE_NOP) {
        callDebug("Executing NOP at index %d.\n", curmsg->index);
        do_bookkeeping(curmsg);
        actionResult = executeAction(nullptr, curmsg);
        if (actionResult != call::E_AR_NO_ERROR) {
            // Store last action result if it is an error
            // and go on with the scenario
            call::last_action_result = actionResult;
        }
        if (actionResult == E_AR_RTPECHO_ERROR)
        {
            terminate(CStat::E_CALL_FAILED);
            return false;
        }
        else
        {
            return next();
        }
    }

    else if(curmsg -> send_scheme) {
        char * msg_snd;
        int msgLen;
        int send_status;

        /* Do not send a new message until the previous one which had
         * retransmission enabled is acknowledged */

        if(next_retrans) {
            setPaused();
            return true;
        }

        /* Handle counters and RTDs for this message. */
        do_bookkeeping(curmsg);

        /* decide whether to increment cseq or not
         * basically increment for anything except response, ACK or CANCEL
         * Note that cseq is only used by the [cseq] keyword, and
         * not by default
         */

        int incr_cseq = 0;
        if (!curmsg->send_scheme->isAck() &&
                !curmsg->send_scheme->isCancel() &&
                !curmsg->send_scheme->isResponse()) {
            ++cseq;
            incr_cseq = 1;
        }

        msg_snd = send_scene(msg_index, &send_status, &msgLen);
        if (!msg_snd) {
            /* This will hit connect_if_needed, and if it fails, the
               entire call is deleted... */
            ERROR("Call failed, cannot continue safely...");
        }

        if(send_status < 0 && errno == EWOULDBLOCK) {
            if (incr_cseq) --cseq;
            /* Have we set the timeout yet? */
            if (send_timeout) {
                /* If we have actually timed out. */
                if (clock_tick > send_timeout) {
                    WARNING("Call-Id: %s, send timeout on message %s:%d: aborting call",
                            id, curmsg->desc, curmsg->index);
                    computeStat(CStat::E_CALL_FAILED);
                    computeStat(CStat::E_FAILED_TIMEOUT_ON_SEND);
                    if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                        return (abortCall(true));
                    } else {
                        delete this;
                        return false;
                    }
                }
            } else if (curmsg->timeout) {
                /* Initialize the send timeout to the per message timeout. */
                send_timeout = clock_tick + curmsg->timeout;
            } else if (defl_send_timeout) {
                /* Initialize the send timeout to the global timeout. */
                send_timeout = clock_tick + defl_send_timeout;
            }
            return true; /* No step, nothing done, retry later */
        } else if(send_status < 0) { /* Send error */
            /* The call was already deleted by connect_socket_if_needed or send_raw,
             * so we should no longer access members. */
            return false;
        }
        /* We have sent the message, so the timeout is no longer needed. */
        send_timeout = 0;

        last_send_index = curmsg->index;
        last_send_len = msgLen;
        realloc_ptr = (char *) realloc(last_send_msg, msgLen+1);
        if (realloc_ptr) {
            last_send_msg = realloc_ptr;
        } else {
            free(last_send_msg);
            ERROR("Out of memory!");
            return false;
        }
        memcpy(last_send_msg, msg_snd, msgLen);
        last_send_msg[msgLen] = '\0';

        if (curmsg->start_txn) {
            transactions[curmsg->start_txn - 1].txnID = (char *)realloc(transactions[curmsg->start_txn - 1].txnID, MAX_HEADER_LEN);
            extract_transaction(transactions[curmsg->start_txn - 1].txnID, last_send_msg);
        }
        if (curmsg->ack_txn) {
            transactions[curmsg->ack_txn - 1].ackIndex = curmsg->index;
        }

        if(last_recv_index >= 0) {
            /* We are sending just after msg reception. There is a great
             * chance that we will be asked to retransmit this message */
            recv_retrans_hash       = last_recv_hash;
            recv_retrans_recv_index = last_recv_index;
            recv_retrans_send_index = curmsg->index;

            callDebug("Set Retransmission Hash: %lu (recv index %d, send index %d)\n",
                      recv_retrans_hash, recv_retrans_recv_index, recv_retrans_send_index);

            /* Prevent from detecting the cause relation between send and recv
             * in the next valid send */
            last_recv_hash = 0;
        }

        /* Update retransmission information */
        if(curmsg -> retrans_delay) {
            if((transport == T_UDP) && (retrans_enabled)) {
                next_retrans = clock_tick + curmsg -> retrans_delay;
                nb_retrans = 0;
                nb_last_delay = curmsg->retrans_delay;
            }
        } else {
            next_retrans = 0;
        }

        executeAction(msg_snd, curmsg);

        /* Update scenario statistics */
        curmsg -> nb_sent++;

        return next();
    } else if (curmsg->M_type == MSG_TYPE_RECV
               || curmsg->M_type == MSG_TYPE_RECVCMD
              ) {
        if (queued_msg) {
            char *msg = queued_msg;
            queued_msg = nullptr;
            bool ret = process_incoming(msg);
            free(msg);
            return ret;
        } else if (recv_timeout) {
            if(recv_timeout > getmilliseconds()) {
                setPaused();
                return true;
            }
            recv_timeout = 0;
            curmsg->nb_timeout++;
            if (curmsg->on_timeout < 0) {
                // if you set a timeout but not a label, the call is aborted
                WARNING("Call-Id: %s, receive timeout on message %s:%d without label to jump to (ontimeout attribute): aborting call",
                        id, curmsg->desc, curmsg->index);
                computeStat(CStat::E_CALL_FAILED);
                computeStat(CStat::E_FAILED_TIMEOUT_ON_RECV);
                if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                    return (abortCall(true));
                } else {
                    delete this;
                    return false;
                }
            }
            WARNING("Call-Id: %s, receive timeout on message %s:%d, jumping to label %d",
                    id, curmsg->desc, curmsg->index, curmsg->on_timeout);
            /* FIXME: We should do something like set index here, but it probably
             * does not matter too much as only nops are allowed in the init stanza. */
            msg_index = curmsg->on_timeout;
            recv_timeout = 0;
            if (msg_index < (int)call_scenario->messages.size()) return true;
            // special case - the label points to the end - finish the call
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_TIMEOUT_ON_RECV);
            if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                return (abortCall(true));
            } else {
                delete this;
                return false;
            }
        } else if (curmsg->timeout || defl_recv_timeout) {
            if (curmsg->timeout)
                // If timeout is specified on message receive, use it
                recv_timeout = getmilliseconds() + curmsg->timeout;
            else
                // Else use the default timeout if specified
                recv_timeout = getmilliseconds() + defl_recv_timeout;
            return true;
        } else {
            /* We are going to wait forever. */
            setPaused();
        }
    } else {
        WARNING("Unknown message type at %s:%d: %d", curmsg->desc, curmsg->index, curmsg->M_type);
    }
    return true;
}

bool call::run()
{
    bool            bInviteTransaction = false;

    assert(running);

    if (zombie) {
        delete this;
        return false;
    }

    update_clock_tick();

    message *curmsg;
    if (initCall) {
        if(msg_index >= (int)call_scenario->initmessages.size()) {
            ERROR("Scenario initialization overrun for call %s (%p) (index = %d)", id, _RCAST(void*, this), msg_index);
        }
        curmsg = call_scenario->initmessages[msg_index];
    } else {
        if(msg_index >= (int)call_scenario->messages.size()) {
            ERROR("Scenario overrun for call %s (%p) (index = %d)", id, _RCAST(void*, this), msg_index);
        }
        curmsg = call_scenario->messages[msg_index];
    }

    callDebug("Processing message %d of type %d for call %s at %lu.\n", msg_index, curmsg->M_type, id, clock_tick);

    if (curmsg->condexec != -1) {
        bool exec = M_callVariableTable->getVar(curmsg->condexec)->isSet();
        if (curmsg->condexec_inverse) {
            exec = !exec;
        }
        if (!exec) {
            callDebug("Conditional variable %s %s set, so skipping message %d.\n", call_scenario->allocVars->getName(curmsg->condexec), curmsg->condexec_inverse ? "" : "not", msg_index);
            return next();
        }
    }

    /* Manages retransmissions or delete if max retrans reached */
    if(next_retrans && (next_retrans < clock_tick)) {
        nb_retrans++;

        if ( (0 == strncmp (last_send_msg, "INVITE", 6)) ) {
            bInviteTransaction = true;
        }

        int rtAllowed = std::min(bInviteTransaction ? max_invite_retrans : max_non_invite_retrans, max_udp_retrans);

        callDebug("Retransmisison required (%d retransmissions, max %d)\n", nb_retrans, rtAllowed);

        if(nb_retrans > rtAllowed) {
            call_scenario->messages[last_send_index] -> nb_timeout ++;
            if (call_scenario->messages[last_send_index]->on_timeout >= 0) {  // action on timeout
                WARNING("Call-Id: %s, timeout on max UDP retrans for message %d, jumping to label %d ",
                        id, msg_index, call_scenario->messages[last_send_index]->on_timeout);
                msg_index = call_scenario->messages[last_send_index]->on_timeout;
                next_retrans = 0;
                recv_timeout = 0;
                if (msg_index < (int)call_scenario->messages.size()) {
                    return true;
                }

                // here if asked to go to the last label  delete the call
                computeStat(CStat::E_CALL_FAILED);
                computeStat(CStat::E_FAILED_MAX_UDP_RETRANS);
                if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                    // Abort the call by sending proper SIP message
                    return(abortCall(true));
                } else {
                    // Just delete existing call
                    delete this;
                    return false;
                }
            }
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_MAX_UDP_RETRANS);
            if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                // Abort the call by sending proper SIP message
                WARNING("Aborting call on UDP retransmission timeout for Call-ID '%s'", id);
                return(abortCall(true));
            } else {
                // Just delete existing call
                delete this;
                return false;
            }
        } else {
            nb_last_delay *= 2;
            if (global_t2 < nb_last_delay) {
                if (!bInviteTransaction) {
                    nb_last_delay = global_t2;
                }
            }
            if(send_raw(last_send_msg, last_send_index, last_send_len) < -1) {
                return false;
            }
            call_scenario->messages[last_send_index] -> nb_sent_retrans++;
            computeStat(CStat::E_RETRANSMISSION);
            next_retrans = clock_tick + nb_last_delay;
        }
    }

    if(paused_until) {
        /* Process a pending pause instruction until delay expiration */
        if(paused_until > clock_tick) {
            callDebug("Call is paused until %d (now %ld).\n", paused_until, clock_tick);
            setPaused();
            callDebug("Running: %d (wake %d).\n", running, wake());
            return true;
        }
        /* Our pause is over. */
        callDebug("Pause complete, waking up.\n");
        paused_until = 0;
        return next();
    }
    return executeMessage(curmsg);
}

const char *default_message_names[] = {
    "3pcc_abort",
    "ack",
    "ack2",
    "bye",
    "cancel",
    "200",
};
const char *default_message_strings[] = {
    /* 3pcc_abort */
    "call-id: [call_id]\ninternal-cmd: abort_call\n\n",
    /* ack */
    "ACK [last_Request_URI] SIP/2.0\n"
    "[last_Via]\n"
    "[last_From]\n"
    "[last_To]\n"
    "Call-ID: [call_id]\n"
    "CSeq: [last_cseq_number] ACK\n"
    "Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n"
    "Max-Forwards: 70\n"
    "Subject: Performance Test\n"
    "Content-Length: 0\n\n",
    /* ack2, the only difference is Via, I don't quite know why. */
    "ACK [last_Request_URI] SIP/2.0\n"
    "Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "[last_From]\n"
    "[last_To]\n"
    "Call-ID: [call_id]\n"
    "CSeq: [last_cseq_number] ACK\n"
    "Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n"
    "Max-Forwards: 70\n"
    "Subject: Performance Test\n"
    "Content-Length: 0\n\n",
    /* bye */
    "BYE [last_Request_URI] SIP/2.0\n"
    "Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
    "[last_From]\n"
    "[last_To]\n"
    "Call-ID: [call_id]\n"
    "CSeq: [last_cseq_number+1] BYE\n"
    "Max-Forwards: 70\n"
    "Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n"
    "Content-Length: 0\n\n",
    /* cancel */
    "CANCEL [last_Request_URI] SIP/2.0\n"
    "[last_Via]\n"
    "[last_From]\n"
    "[last_To]\n"
    "Call-ID: [call_id]\n"
    "CSeq: [last_cseq_number] CANCEL\n"
    "Max-Forwards: 70\n"
    "Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n"
    "Content-Length: 0\n\n",
    /* 200 */
    "SIP/2.0 200 OK\n"
    "[last_Via:]\n"
    "[last_From:]\n"
    "[last_To:]\n"
    "[last_Call-ID:]\n"
    "[last_CSeq:]\n"
    "Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
    "Content-Length: 0\n\n"
};

SendingMessage **default_messages;

void init_default_messages()
{
    int messages = sizeof(default_message_strings)/sizeof(default_message_strings[0]);
    default_messages = new SendingMessage* [messages];
    for (int i = 0; i < messages; i++) {
        default_messages[i] = new SendingMessage(main_scenario, const_cast<char*>(default_message_strings[i]));
    }
}

void free_default_messages()
{
    int messages = sizeof(default_message_strings)/sizeof(default_message_strings[0]);
    if (!default_messages) {
        return;
    }
    for (int i = 0; i < messages; i++) {
        delete default_messages[i];
    }
    delete [] default_messages;
}

SendingMessage *get_default_message(const char *which)
{
    int messages = sizeof(default_message_names)/sizeof(default_message_names[0]);
    for (int i = 0; i < messages; i++) {
        if (!strcmp(which, default_message_names[i])) {
            return default_messages[i];
        }
    }
    ERROR("Internal Error: Unknown default message: %s!", which);
}

void set_default_message(const char *which, char *msg)
{
    int messages = sizeof(default_message_names)/sizeof(default_message_names[0]);
    for (int i = 0; i < messages; i++) {
        if (!strcmp(which, default_message_names[i])) {
            default_message_strings[i] = msg;
            return;
        }
    }
    ERROR("Internal Error: Unknown default message: %s!", which);
}

bool call::process_unexpected(const char* msg)
{
    char buffer[MAX_HEADER_LEN];
    char *desc = buffer;
    int res = 0;

    message *curmsg = call_scenario->messages[msg_index];

    curmsg->nb_unexp++;

    if (default_behaviors & DEFAULT_BEHAVIOR_ABORTUNEXP) {
        desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "Aborting ");
    } else {
        desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "Continuing ");
    }
    desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "call on unexpected message for Call-Id '%s': ", id);

    if (curmsg -> M_type == MSG_TYPE_RECV) {
        if (curmsg -> recv_request) {
            desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while expecting '%s' ", curmsg -> recv_request);
        } else {
            desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while expecting '%s' ", curmsg -> recv_response);
        }
    } else if (curmsg -> M_type == MSG_TYPE_SEND) {
        desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while sending ");
    } else if (curmsg -> M_type == MSG_TYPE_PAUSE) {
        desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while pausing ");
    } else if (curmsg -> M_type == MSG_TYPE_SENDCMD) {
        desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while sending command ");
    } else if (curmsg -> M_type == MSG_TYPE_RECVCMD) {
        desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while expecting command ");
    } else {
        desc += snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "while in message type %d ", curmsg->M_type);
    }
    snprintf(desc, MAX_HEADER_LEN - (desc - buffer), "(index %d)", msg_index);

    WARNING("%s, received '%s'", buffer, msg);

    TRACE_MSG("-----------------------------------------------\n"
              "Unexpected %s message received:\n\n%s\n",
              TRANSPORT_TO_STRING(transport),
              msg);

    callDebug("Unexpected %s message received (index %d, hash %lu):\n\n%s\n",
              TRANSPORT_TO_STRING(transport), msg_index, hash(msg), msg);

    if (get_reply_code(msg)) {
        this->call_scenario->stats->error_codes.push_back(get_reply_code(msg));
    }

    if (default_behaviors & DEFAULT_BEHAVIOR_ABORTUNEXP) {
        // if twin socket call => reset the other part here
        if (twinSippSocket && (msg_index > 0)) {
            res = sendCmdBuffer(createSendingMessage(get_default_message("3pcc_abort")));
            if (res < 0) {
                WARNING("sendCmdBuffer returned %d", res);
                return false;
            }
        }

        // usage of last_ keywords => for call aborting
        realloc_ptr = (char *) realloc(last_recv_msg, strlen(msg) + 1);
        if (realloc_ptr) {
            last_recv_msg = realloc_ptr;
        } else {
            free(last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }

        strcpy(last_recv_msg, msg);

        computeStat(CStat::E_CALL_FAILED);
        computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
        if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
            return (abortCall(true));
        } else {
            delete this;
            return false;
        }
    } else {
        // Do not abort call nor send anything in reply if default behavior is disabled
        return false;
    }
}

void call::abort()
{
    computeStat(CStat::E_CALL_FAILED);
    WARNING("Aborted call with Call-ID '%s'", id);
    abortCall(false);
}

bool call::abortCall(bool writeLog)
{
    int is_inv;

    char * src_recv = nullptr ;

    callDebug("Aborting call %s (index %d).\n", id, msg_index);

    if (last_send_msg != nullptr) {
        is_inv = !strncmp(last_send_msg, "INVITE", 6);
    } else {
        is_inv = false;
    }
    if ((creationMode != MODE_SERVER) && (msg_index > 0)) {
        if ((call_established == false) && (is_inv)) {
            src_recv = last_recv_msg ;

            // Answer unexpected errors (4XX, 5XX and beyond) with an ACK
            // Contributed by F. Tarek Rogers
            if((src_recv) && (get_reply_code(src_recv) >= 400)) {
                sendBuffer(createSendingMessage(get_default_message("ack")));
            } else if (src_recv) {
                /* Call is not established and the reply is not a 4XX, 5XX */
                /* And we already received a message. */
                if (ack_is_pending == true) {
                    /* If an ACK is expected from the other side, send it
                     * and send a BYE afterwards. */
                    ack_is_pending = false;
                    sendBuffer(createSendingMessage(get_default_message("ack")));

                    /* Send the BYE */
                    sendBuffer(createSendingMessage(get_default_message("bye")));
                } else {
                    /* Send a CANCEL */
                    sendBuffer(createSendingMessage(get_default_message("cancel")));
                }
            } else {
                /* Call is not established and the reply is not a 4XX, 5XX */
                /* and we didn't received any message. This is the case when */
                /* we are aborting after having send an INVITE and not received */
                /* any answer. */
                /* Do nothing ! */
            }
        } else if (last_recv_msg) {
            /* The call may not be established, if we haven't yet received a message,
             * because the earlier check depends on the first message being an INVITE
             * (although it could be something like a message message, therefore we
             * check that we received a message. */
            sendBuffer(createSendingMessage(get_default_message("bye")));
        }
    }

    if (writeLog && useCallDebugf) {
        TRACE_CALLDEBUG ("-------------------------------------------------------------------------------\n");
        TRACE_CALLDEBUG ("Call debugging information for call %s:\n", id);
        TRACE_CALLDEBUG("%s", debugBuffer);
    }

    stopListening();
    if (deadcall_wait && !initCall) {
        char reason[100];
        sprintf(reason, "aborted at index %d", msg_index);
        new deadcall(id, reason);
    }
    delete this;

    return false;
}

bool call::rejectCall()
{
    computeStat(CStat::E_CALL_FAILED);
    computeStat(CStat::E_FAILED_CALL_REJECTED);
    delete this;
    return false;
}


int call::sendCmdMessage(message *curmsg)
{
    char * dest;
    char delimitor[2];
    delimitor[0]=27;
    delimitor[1]=0;

    /* 3pcc extended mode */
    char * peer_dest;
    SIPpSocket **peer_socket;

    if(curmsg -> M_sendCmdData) {
        // WARNING("---PREPARING_TWIN_CMD---%s---", scenario[index] -> M_sendCmdData);
        dest = createSendingMessage(curmsg->M_sendCmdData);
        strcat(dest, delimitor);
        //WARNING("---SEND_TWIN_CMD---%s---", dest);

        int rc;

        /* 3pcc extended mode */
        peer_dest = curmsg->peer_dest;
        if(peer_dest) {
            peer_socket = get_peer_socket(peer_dest);
            rc = (*peer_socket)->write(dest, strlen(dest), WS_BUFFER, &call_peer);
        } else {
            rc = twinSippSocket->write(dest, strlen(dest), WS_BUFFER, &call_peer);
        }
        if(rc <  0) {
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_CMD_NOT_SENT);
            delete this;
            return(-1);
        }

        return(0);
    } else
        return(-1);
}


int call::sendCmdBuffer(char* cmd)
{
    char * dest;
    char delimitor[2];
    int  rc;

    delimitor[0]=27;
    delimitor[1]=0;

    dest = cmd ;

    strcat(dest, delimitor);

    rc = twinSippSocket->write(dest, strlen(dest), WS_BUFFER, &twinSippSocket->ss_dest);
    if(rc <  0) {
        computeStat(CStat::E_CALL_FAILED);
        computeStat(CStat::E_FAILED_CMD_NOT_SENT);
        delete this;
        return(-1);
    }

    return(0);
}


char* call::createSendingMessage(SendingMessage *src, int P_index, int *msgLen)
{
    static char msg_buffer[SIPP_MAX_MSG_SIZE+2];
    return createSendingMessage(src, P_index, msg_buffer, sizeof(msg_buffer), msgLen);
}

char* call::createSendingMessage(SendingMessage *src, int P_index, char *msg_buffer, int buf_len, int *msgLen)
{
    char * length_marker = nullptr;
    char * auth_marker = nullptr;
    MessageComponent *auth_comp = nullptr;
    bool auth_comp_allocated = false;
    int    len_offset = 0;
    char *dest = msg_buffer;
    bool suppresscrlf = false;

#ifdef USE_TLS
    bool srtp_audio_updated = false;
    bool srtp_video_updated = false;

    // OUTGOING SRTP PARAM CONTEXT
    SrtpAudioInfoParams pA;
    SrtpVideoInfoParams pV;

    pA.audio_found = false;
    pA.primary_audio_cryptotag = 0;
    memset(pA.primary_audio_cryptosuite, 0, sizeof(pA.primary_audio_cryptosuite));
    memset(pA.primary_audio_cryptokeyparams, 0, sizeof(pA.primary_audio_cryptokeyparams));
    pA.secondary_audio_cryptotag = 0;
    memset(pA.secondary_audio_cryptosuite, 0, sizeof(pA.secondary_audio_cryptosuite));
    memset(pA.secondary_audio_cryptokeyparams, 0, sizeof(pA.secondary_audio_cryptokeyparams));
    pA.primary_unencrypted_audio_srtp = false;
    pA.secondary_unencrypted_audio_srtp = false;

    pV.video_found = false;
    pV.primary_video_cryptotag = 0;
    memset(pV.primary_video_cryptosuite, 0, sizeof(pV.primary_video_cryptosuite));
    memset(pV.primary_video_cryptokeyparams, 0, sizeof(pV.primary_video_cryptokeyparams));
    pV.secondary_video_cryptotag = 0;
    memset(pV.secondary_video_cryptosuite, 0, sizeof(pV.secondary_video_cryptosuite));
    memset(pV.secondary_video_cryptokeyparams, 0, sizeof(pV.secondary_video_cryptokeyparams));
    pV.primary_unencrypted_video_srtp = false;
    pV.secondary_unencrypted_video_srtp = false;
#endif // USE_TLS

    msg_buffer[0] = '\0';

    for (int i = 0; i < src->numComponents(); i++) {
        MessageComponent *comp = src->getComponent(i);
        int left = buf_len - (dest - msg_buffer);
        if (left <= 0) {
            break;
        }
        switch(comp->type) {
        case E_Message_Literal:
            if (suppresscrlf) {
                char *ptr = comp->literal;
                while (isspace(*ptr)) ptr++;
                dest += snprintf(dest, left, "%s", ptr);
                suppresscrlf = false;
            } else {
                memcpy(dest, comp->literal, comp->literalLen);
                dest += comp->literalLen;
                *dest = '\0';
            }
            break;
        case E_Message_Remote_IP:
            dest += snprintf(dest, left, "%s", remote_ip_w_brackets);
            break;
        case E_Message_Remote_Host:
            dest += snprintf(dest, left, "%s", remote_host);
            break;
        case E_Message_Remote_Port:
            dest += snprintf(dest, left, "%d", remote_port + comp->offset);
            break;
        case E_Message_Local_IP:
            dest += snprintf(dest, left, "%s", local_ip_w_brackets);
            break;
        case E_Message_Local_Port:
            int port;
            if((multisocket) && (sendMode != MODE_SERVER)) {
                port = call_port;
            } else {
                port =  local_port;
            }
            dest += snprintf(dest, left, "%d", port + comp->offset);
            break;
        case E_Message_Transport:
            dest += snprintf(dest, left, "%s", TRANSPORT_TO_STRING(transport));
            break;
        case E_Message_Local_IP_Type:
            dest += snprintf(dest, left, "%s", (local_ip_is_ipv6 ? "6" : "4"));
            break;
        case E_Message_Server_IP: {
            /* We should do this conversion once per socket creation, rather than
             * repeating it every single time. */
            struct sockaddr_storage server_sockaddr;

            sipp_socklen_t len = sizeof(server_sockaddr);
            getsockname(call_socket->ss_fd,
                        (sockaddr *)(void *)&server_sockaddr, &len);

            char address[INET6_ADDRSTRLEN];
            if (getnameinfo(_RCAST(sockaddr*, &server_sockaddr), len, address, sizeof(address),
                            nullptr, 0, NI_NUMERICHOST) < 0) {
                ERROR_NO("Unable to get socket name information");
            }

            dest += snprintf(dest, left, "%s", address);
        }
        break;
        case E_Message_Media_IP:
            dest += snprintf(dest, left, "%s", media_ip);
            break;
        case E_Message_Auto_Media_Port:
        case E_Message_Media_Port: {
            int port = media_port + comp->offset;
            if (comp->type == E_Message_Auto_Media_Port) {
                port += (4 * (number - 1)) % 10000;
            }
#ifdef PCAPPLAY
            char *begin = dest;
            while (begin > msg_buffer) {
                if (*begin == '\n') {
                    break;
                }
                begin--;
            }
            if (begin == msg_buffer) {
                ERROR("Can not find beginning of a line for the media port!");
            }
            play_args_t* play_args = nullptr;
            if (strstr(begin, "audio")) {
                play_args = &play_args_a;
            } else if (strstr(begin, "image")) {
                play_args = &play_args_i;
            } else if (strstr(begin, "video")) {
                play_args = &play_args_v;
            } else {
                // This check will not do, as we use the media_port in other places too.
                //ERROR("media_port keyword with no audio or video on the current line (%s)", begin);
            }
            if (play_args != nullptr) {
                if (media_ip_is_ipv6) {
                    (_RCAST(struct sockaddr_in6 *, &(play_args->from)))->sin6_port = htons(port);
                } else {
                    (_RCAST(struct sockaddr_in *, &(play_args->from)))->sin_port = htons(port);
                }
            }
#endif
            dest += snprintf(dest, left, "%u", port);
            break;
        }
        case E_Message_RTPStream_Audio_Port:
        {
          int temp_audio_port = 0;
          // Only obtain port for RTP ([rtpstream_audio_port+0]) *BUT NOT* RTCP ([rtpstream_audio_port+1])
          if (comp->offset == 0) {
              temp_audio_port = rtpstream_get_local_audioport(&rtpstream_callinfo);
              if (!temp_audio_port) {
                  /* Make this a warning instead? */
                  ERROR("cannot assign a free audio port to this call - using 0 for [rtpstream_audio_port]");
              }
          } else if (comp->offset >= 1) {
              temp_audio_port = rtpstream_callinfo.local_audioport + comp->offset;
          }
#ifdef USE_TLS
          logSrtpInfo("call::createSendingMessage():  E_Message_RTPStream_Audio_Port: %d\n", temp_audio_port);
#endif // USE_TLS
          dest += snprintf(dest, left, "%d", temp_audio_port);
        }
        break;
        case E_Message_RTPStream_Video_Port:
        {
          int temp_video_port = 0;
          // Only obtain port for RTP ([rtpstream_video_port+0]) *BUT NOT* RTCP ([rtpstream_video_port+1])
          if (comp->offset == 0) {
              temp_video_port = rtpstream_get_local_videoport(&rtpstream_callinfo);
              if (!temp_video_port) {
                /* Make this a warning instead? */
                ERROR("cannot assign a free video port to this call - using 0 for [rtpstream_video_port]");
              }
          } else if (comp->offset >= 1) {
              temp_video_port = rtpstream_callinfo.local_videoport + comp->offset;
          }
#ifdef USE_TLS
          logSrtpInfo("call::createSendingMessage():  E_Message_RTPStream_Video_Port: %d\n", temp_video_port);
#endif // USE_TLS
          dest += snprintf(dest, left, "%d", temp_video_port);
        }
        break;
#ifdef USE_TLS
        case E_Message_CryptoTag1Audio:
        {
            pA.audio_found = true;
            pA.primary_audio_cryptotag = 1;
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag1Audio() - PRIMARY - CLIENT: %d\n", pA.primary_audio_cryptotag);
                _txUACAudio.setCryptoTag(pA.primary_audio_cryptotag, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag1Audio() - PRIMARY - SERVER: %d\n", pA.primary_audio_cryptotag);
                _txUASAudio.setCryptoTag(pA.primary_audio_cryptotag, PRIMARY_CRYPTO);
            }
            dest += snprintf(dest, left, "%d", pA.primary_audio_cryptotag);
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoTag2Audio:
        {
            pA.audio_found = true;
            pA.secondary_audio_cryptotag = 2;
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag2Audio() - SECONDARY - CLIENT: %d\n", pA.secondary_audio_cryptotag);
                _txUACAudio.setCryptoTag(pA.secondary_audio_cryptotag, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag2Audio() - SECONDARY - SERVER: %d\n", pA.secondary_audio_cryptotag);
                _txUASAudio.setCryptoTag(pA.secondary_audio_cryptotag, SECONDARY_CRYPTO);
            }
            dest += snprintf(dest, left, "%d", pA.secondary_audio_cryptotag);
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1801Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1801Audio() - PRIMARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1801Audio() - PRIMARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_audio_cs_out, "AES_CM_128_HMAC_SHA1_80", sizeof(_pref_audio_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACAudio.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_80", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACAudio.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASAudio.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_80", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASAudio.swapCrypto();
                    }
                }
            }

            pA.audio_found = true;
            strncat(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pA.primary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_80");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1802Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1802Audio() - SECONDARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1802Audio() - SECONDARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            pA.audio_found = true;
            strncat(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pA.secondary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_80");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1321Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1321Audio() - PRIMARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1321Audio() - PRIMARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_audio_cs_out, "AES_CM_128_HMAC_SHA1_32", sizeof(_pref_audio_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACAudio.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_32", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACAudio.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASAudio.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_32", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASAudio.swapCrypto();
                    }
                }
            }

            pA.audio_found = true;
            strncat(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pA.primary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_32");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1322Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1322Audio() - SECONDARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1322Audio() - SECONDARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            pA.audio_found = true;
            strncat(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pA.secondary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_32");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1801Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1801Audio() - PRIMARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1801Audio() - PRIMARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_audio_cs_out, "NULL_HMAC_SHA1_80", sizeof(_pref_audio_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACAudio.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_80", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACAudio.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASAudio.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_80", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASAudio.swapCrypto();
                    }
                }
            }

            pA.audio_found = true;
            strncat(pA.primary_audio_cryptosuite, "NULL_HMAC_SHA1_80", sizeof(pA.primary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_80");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1802Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1802Audio() - SECONDARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1802Audio() - SECONDARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            pA.audio_found = true;
            strncat(pA.secondary_audio_cryptosuite, "NULL_HMAC_SHA1_80", sizeof(pA.secondary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_80");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1321Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1321Audio() - PRIMARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1321Audio() - PRIMARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_audio_cs_out, "NULL_HMAC_SHA1_32", sizeof(_pref_audio_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACAudio.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_32", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACAudio.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASAudio.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_32", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASAudio.swapCrypto();
                    }
                }
            }

            pA.audio_found = true;
            strncat(pA.primary_audio_cryptosuite, "NULL_HMAC_SHA1_32", sizeof(pA.primary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_32");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1322Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1322Audio() - SECONDARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1322Audio() - SECONDARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            pA.audio_found = true;
            strncat(pA.secondary_audio_cryptosuite, "NULL_HMAC_SHA1_32", sizeof(pA.secondary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_32");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoKeyParams1Audio:
        {
            std::string mks;

            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Audio() - PRIMARY - CLIENT - component offset:%d\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUACAudio.generateMasterKey(PRIMARY_CRYPTO);
                    _txUACAudio.generateMasterSalt(PRIMARY_CRYPTO);
                    _txUACAudio.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Audio() - PRIMARY - CLIENT - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUACAudio.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Audio() - PRIMARY - CLIENT - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Audio() - PRIMARY - SERVER - component offset:%d\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUASAudio.generateMasterKey(PRIMARY_CRYPTO);
                    _txUASAudio.generateMasterSalt(PRIMARY_CRYPTO);
                    _txUASAudio.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Audio() - PRIMARY - SERVER - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUASAudio.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Audio() - PRIMARY - SERVER - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            pA.audio_found = true;
            strncpy(pA.primary_audio_cryptokeyparams, mks.c_str(), 40);
            dest += snprintf(dest, left, "%s", pA.primary_audio_cryptokeyparams);
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoKeyParams2Audio:
        {
            std::string mks;

            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Audio() - SECONDARY - CLIENT - component offset:%d\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUACAudio.generateMasterKey(SECONDARY_CRYPTO);
                    _txUACAudio.generateMasterSalt(SECONDARY_CRYPTO);
                    _txUACAudio.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Audio() - SECONDARY - CLIENT - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUACAudio.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Audio() - SECONDARY - CLIENT - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Audio() - SECONDARY - SERVER - component offset:%d\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUASAudio.generateMasterKey(SECONDARY_CRYPTO);
                    _txUASAudio.generateMasterSalt(SECONDARY_CRYPTO);
                    _txUASAudio.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Audio() - SECONDARY - SERVER - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUASAudio.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Audio() - SECONDARY - SERVER - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            pA.audio_found = true;
            strncpy(pA.secondary_audio_cryptokeyparams, mks.c_str(), 40);
            dest += snprintf(dest, left, "%s", pA.secondary_audio_cryptokeyparams);
            srtp_audio_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1801Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1801Audio() - PRIMARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1801Audio() - PRIMARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            pA.audio_found = true;
            pA.primary_unencrypted_audio_srtp = true;
            strncat(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pA.primary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1802Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1802Audio() - SECONDARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1802Audio() - SECONDARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            pA.audio_found = true;
            pA.secondary_unencrypted_audio_srtp = true;
            strncat(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pA.secondary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1321Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1321Audio() - PRIMARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1321Audio() - PRIMARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            pA.audio_found = true;
            pA.primary_unencrypted_audio_srtp = true;
            strncat(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pA.primary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1322Audio:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1322Audio() - SECONDARY - CLIENT\n");
                _txUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1322Audio() - SECONDARY - SERVER\n");
                _txUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            pA.audio_found = true;
            pA.secondary_unencrypted_audio_srtp = true;
            strncat(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pA.secondary_audio_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_audio_updated = true;
        }
        break;
        case E_Message_CryptoTag1Video:
        {
            pV.video_found = true;
            pV.primary_video_cryptotag = 1;
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag1Video() - PRIMARY - CLIENT: %d\n", pV.primary_video_cryptotag);
                _txUACVideo.setCryptoTag(pV.primary_video_cryptotag, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag1Video() - PRIMARY - SERVER: %d\n", pV.primary_video_cryptotag);
                _txUASVideo.setCryptoTag(pV.primary_video_cryptotag, PRIMARY_CRYPTO);
            }
            dest += snprintf(dest, left, "%d", pV.primary_video_cryptotag);
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoTag2Video:
        {
            pV.video_found = true;
            pV.secondary_video_cryptotag = 2;
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag2Video() - SECONDARY - CLIENT: %d\n", pV.secondary_video_cryptotag);
                _txUACVideo.setCryptoTag(pV.secondary_video_cryptotag, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoTag2Video() - SECONDARY - SERVER: %d\n", pV.secondary_video_cryptotag);
                _txUASVideo.setCryptoTag(pV.secondary_video_cryptotag, SECONDARY_CRYPTO);
            }
            dest += snprintf(dest, left, "%d", pV.secondary_video_cryptotag);
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1801Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1801Video() - PRIMARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1801Video() - PRIMARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_video_cs_out, "AES_CM_128_HMAC_SHA1_80", sizeof(_pref_video_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACVideo.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_80", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACVideo.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASVideo.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_80", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASVideo.swapCrypto();
                    }
                }
            }

            pV.video_found = true;
            strncat(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pV.primary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_80");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1802Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1802Video() - SECONDARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1802Video() - SECONDARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            pV.video_found = true;
            strncat(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pV.secondary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_80");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1321Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1321Video() - PRIMARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1321Video() - PRIMARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_video_cs_out, "AES_CM_128_HMAC_SHA1_32", sizeof(_pref_video_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACVideo.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_32", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACVideo.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASVideo.getCryptoSuite().c_str(), "AES_CM_128_HMAC_SHA1_32", 23))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASVideo.swapCrypto();
                    }
                }
            }

            pV.video_found = true;
            strncat(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pV.primary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_32");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteAesCm128Sha1322Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1322Video() - SECONDARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteAesCm128Sha1322Video() - SECONDARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            pV.video_found = true;
            strncat(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pV.secondary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "AES_CM_128_HMAC_SHA1_32");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1801Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1801Video() - PRIMARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1801Video() - PRIMARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_video_cs_out, "NULL_HMAC_SHA1_80", sizeof(_pref_video_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACVideo.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_80", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACVideo.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASVideo.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_80", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASVideo.swapCrypto();
                    }
                }
            }

            pV.video_found = true;
            strncat(pV.primary_video_cryptosuite, "NULL_HMAC_SHA1_80", sizeof(pV.primary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_80");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1802Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1802Video() - SECONDARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1802Video() - SECONDARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            pV.video_found = true;
            strncat(pV.secondary_video_cryptosuite, "NULL_HMAC_SHA1_80", sizeof(pV.secondary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_80");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1321Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1321Video() - PRIMARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1321Video() - PRIMARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }

            if ((getSessionStateCurrent() == eNoSession) || (getSessionStateCurrent() == eCompleted))
            {
                logSrtpInfo("call::createSendingMessage():  Marking preferred OFFER cryptosuite...\n");
                strncat(_pref_video_cs_out, "NULL_HMAC_SHA1_32", sizeof(_pref_video_cs_out) - 1);
            }
            else if (getSessionStateCurrent() == eOfferReceived)
            {
                if (sendMode == MODE_CLIENT)
                {
                    if (!strncmp(_rxUACVideo.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_32", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- CLIENT -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- CLIENT -- SWAPPING...\n");
                        _rxUACVideo.swapCrypto();
                    }
                }
                else if (sendMode == MODE_SERVER)
                {
                    if (!strncmp(_rxUASVideo.getCryptoSuite().c_str(), "NULL_HMAC_SHA1_32", 17))
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite match -- SERVER -- NO-OP...\n");
                    }
                    else
                    {
                        logSrtpInfo("call::createSendingMessage():  Preferred ANSWER cryptosuite mismatch -- SERVER -- SWAPPING...\n");
                        _rxUASVideo.swapCrypto();
                    }
                }
            }

            pV.video_found = true;
            strncat(pV.primary_video_cryptosuite, "NULL_HMAC_SHA1_32", sizeof(pV.primary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_32");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoSuiteNullSha1322Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1322Video() - SECONDARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoSuiteNullSha1322Video() - SECONDARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            pV.video_found = true;
            strncat(pV.secondary_video_cryptosuite, "NULL_HMAC_SHA1_32", sizeof(pV.secondary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "NULL_HMAC_SHA1_32");
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoKeyParams1Video:
        {
            std::string mks;

            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Video() - PRIMARY - CLIENT - component offset:%d\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUACVideo.generateMasterKey(PRIMARY_CRYPTO);
                    _txUACVideo.generateMasterSalt(PRIMARY_CRYPTO);
                    _txUACVideo.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Video() - PRIMARY - CLIENT - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUACVideo.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Video() - PRIMARY - CLIENT - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Video() - PRIMARY - SERVER - component offset:\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUASVideo.generateMasterKey(PRIMARY_CRYPTO);
                    _txUASVideo.generateMasterSalt(PRIMARY_CRYPTO);
                    _txUASVideo.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Video() - PRIMARY - SERVER - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUASVideo.encodeMasterKeySalt(mks, PRIMARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams1Video() - PRIMARY - SERVER - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            pV.video_found = true;
            strncpy(pV.primary_video_cryptokeyparams, mks.c_str(), 40);
            dest += snprintf(dest, left, "%s", pV.primary_video_cryptokeyparams);
            srtp_video_updated = true;
        }
        break;
        case E_Message_CryptoKeyParams2Video:
        {
            std::string mks;

            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Video() - SECONDARY - CLIENT - component offset:%d\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUACVideo.generateMasterKey(SECONDARY_CRYPTO);
                    _txUACVideo.generateMasterSalt(SECONDARY_CRYPTO);
                    _txUACVideo.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Video() - SECONDARY - CLIENT - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUACVideo.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Video() - SECONDARY - CLIENT - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Video() - SECONDARY - SERVER - component offset:%d\n", comp->offset);
                if (comp->offset >= 0)
                {
                    _txUASVideo.generateMasterKey(SECONDARY_CRYPTO);
                    _txUASVideo.generateMasterSalt(SECONDARY_CRYPTO);
                    _txUASVideo.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Video() - SECONDARY - SERVER - generating new concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
                else
                {
                    _txUASVideo.encodeMasterKeySalt(mks, SECONDARY_CRYPTO);
                    logSrtpInfo("call::createSendingMessage():  E_Message_CryptoKeyParams2Video() - SECONDARY - SERVER - reusing old concatenated base64-encoded master key/salt:%s\n", mks.c_str());
                }
            }
            pV.video_found = true;
            strncpy(pV.secondary_video_cryptokeyparams, mks.c_str(), 40);
            dest += snprintf(dest, left, "%s", pV.secondary_video_cryptokeyparams);
            srtp_video_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1801Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1801Video() - PRIMARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1801Video() - PRIMARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
            }
            pV.video_found = true;
            pV.primary_unencrypted_video_srtp = true;
            strncat(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pV.primary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_video_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1802Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1802Video() - SECONDARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1802Video() - SECONDARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
            }
            pV.video_found = true;
            pV.secondary_unencrypted_video_srtp = true;
            strncat(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80", sizeof(pV.secondary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_video_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1321Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1321Video() - PRIMARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1321Video() - PRIMARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
            }
            pV.video_found = true;
            pV.primary_unencrypted_video_srtp = true;
            strncat(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pV.primary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_video_updated = true;
        }
        break;
        case E_Message_UEAesCm128Sha1322Video:
        {
            if (sendMode == MODE_CLIENT)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1322Video() - SECONDARY - CLIENT\n");
                _txUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUACVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            else if (sendMode == MODE_SERVER)
            {
                logSrtpInfo("call::createSendingMessage():  E_Message_UEAesCm128Sha1322Video() - SECONDARY - SERVER\n");
                _txUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to encrypt */
                _txUASVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
            }
            pV.video_found = true;
            pV.secondary_unencrypted_video_srtp = true;
            strncat(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32", sizeof(pV.secondary_video_cryptosuite) - 1);
            dest += snprintf(dest, left, "%s", "UNENCRYPTED_SRTP");
            srtp_video_updated = true;
        }
        break;
#endif // USE_TLS
        case E_Message_Media_IP_Type:
            dest += snprintf(dest, left, "%s", (media_ip_is_ipv6 ? "6" : "4"));
            break;
        case E_Message_Call_Number:
            dest += snprintf(dest, left, "%u", number);
            break;
        case E_Message_DynamicId:
            dest += snprintf(dest, left, "%u", call::dynamicId);
            // increment at each request
            dynamicId += stepDynamicId;
            if ( this->dynamicId > maxDynamicId ) {
                call::dynamicId = call::startDynamicId;
            } ;
            break;
        case E_Message_Call_ID:
            dest += snprintf(dest, left, "%s", id);
            break;
        case E_Message_CSEQ:
            dest += snprintf(dest, left, "%u", cseq + comp->offset);
            break;
        case E_Message_PID:
            dest += snprintf(dest, left, "%d", pid);
            break;
        case E_Message_Service:
            dest += snprintf(dest, left, "%s", service);
            break;
        case E_Message_Branch:
            /* Branch is magic cookie + call number + message index in scenario */
            if (P_index == -1) {
                dest += snprintf(dest, left, "z9hG4bK-%u-%u-%d", pid, number, msg_index - 1 + comp->offset);
            } else {
                dest += snprintf(dest, left, "z9hG4bK-%u-%u-%d", pid, number, P_index + comp->offset);
            }
            break;
        case E_Message_Index:
            dest += snprintf(dest, left, "%d", P_index);
            break;
        case E_Message_Next_Url:
            if (next_req_url) {
                dest += sprintf(dest, "%s", next_req_url);
            }
            break;
        case E_Message_Len:
            length_marker = dest;
            dest += snprintf(dest, left, "     ");
            len_offset = comp->offset;
            break;
        case E_Message_Authentication:
            if (auth_marker) {
                ERROR("Only one [authentication] keyword is currently supported!");
            }
            auth_marker = dest;
            dest += snprintf(dest, left, "[authentication place holder]");
            auth_comp = comp;
            break;
        case E_Message_Peer_Tag_Param:
            if (peer_tag) {
                dest += snprintf(dest, left, ";tag=%s", peer_tag);
            }
            break;
        case E_Message_Routes:
            if (dialog_route_set) {
                dest += sprintf(dest, "Route: %s", dialog_route_set);
            } else if (*(dest - 1) == '\n') {
                suppresscrlf = true;
            }
            break;
        case E_Message_ClockTick:
            dest += snprintf(dest, left, "%lu", clock_tick);
            break;
        case E_Message_Timestamp:
            struct timeval currentTime;
            gettimeofday(&currentTime, nullptr);
            dest += snprintf(dest, left, "%s", CStat::formatTime(&currentTime, rfc3339));
            break;
        case E_Message_Date:
            char buf[256];
            time_t t;
            struct tm *tm;

            t = time(nullptr);
            tm = gmtime(&t);
            /* changed %Z to hardcoded GMT since in some OS like FreeBSD it could return UTC instead, see issue #535 */
            strftime(buf, 256, "%a, %d %b %Y %T GMT", tm);
            dest += snprintf(dest, left, "%s", buf);
            break;
        case E_Message_Users:
            dest += snprintf(dest, left, "%d", users);
            break;
        case E_Message_UserID:
            dest += snprintf(dest, left, "%d", userId);
            break;
        case E_Message_SippVersion:
            /* Drop the initial "v" from the SIPP_VERSION string for legacy reasons. */
            dest += snprintf(dest, left, "%s", (const char*)SIPP_VERSION + 1);
            break;
        case E_Message_Variable: {
            int varId = comp->varId;
            CCallVariable *var = M_callVariableTable->getVar(varId);
            if(var->isSet()) {
                if (var->isRegExp()) {
                    dest += sprintf(dest, "%s", var->getMatchingValue());
                } else if (var->isDouble()) {
                    dest += sprintf(dest, "%lf", var->getDouble());
                } else if (var->isString()) {
                    dest += sprintf(dest, "%s", var->getString());
                } else if (var->isBool()) {
                    dest += sprintf(dest, "true");
                }
            } else if (var->isBool()) {
                dest += sprintf(dest, "false");
            }
            if (*(dest - 1) == '\n') {
                suppresscrlf = true;
            }
            break;
        }
        case E_Message_Fill: {
            int varId = comp->varId;
            int length = (int) M_callVariableTable->getVar(varId)->getDouble();
            if (length < 0) {
                length = 0;
            }
            char *filltext = comp->literal;
            int filllen = strlen(filltext);
            if (filllen == 0) {
                ERROR("Internal error: [fill] keyword has zero-length text.");
            }
            for (int i = 0, j = 0; i < length; i++, j++) {
                *dest++ = filltext[j % filllen];
            }
            *dest = '\0';
            break;
        }
        case E_Message_File: {
            char buffer[MAX_HEADER_LEN];
            createSendingMessage(comp->comp_param.filename, SM_UNUSED, buffer, sizeof(buffer));
            FILE *f = fopen(buffer, "r");
            if (!f) {
                ERROR("Could not open '%s': %s", buffer, strerror(errno));
            }
            int ret;
            while ((ret = fread(dest, 1, left, f)) > 0) {
                left -= ret;
                dest += ret;
            }
            if (ret < 0) {
                ERROR("Error reading '%s': %s", buffer, strerror(errno));
            }
            fclose(f);
            break;
        }
        case E_Message_Injection: {
            char *orig_dest = dest;
            getFieldFromInputFile(comp->comp_param.field_param.filename, comp->comp_param.field_param.field, comp->comp_param.field_param.line, dest);
            /* We are injecting an authentication line. */
            if (char *tmp = strstr(orig_dest, "[authentication")) {
                if (auth_marker) {
                    ERROR("Only one [authentication] keyword is currently supported!");
                }
                auth_marker = tmp;
                auth_comp = (struct MessageComponent *)calloc(1, sizeof(struct MessageComponent));
                if (!auth_comp) {
                    ERROR("Out of memory!");
                }
                auth_comp_allocated = true;

                tmp = strchr(auth_marker, ']');
                char c = *tmp;
                *tmp = '\0';
                SendingMessage::parseAuthenticationKeyword(call_scenario, auth_comp, auth_marker);
                *tmp = c;
            }
            if (*(dest - 1) == '\n') {
                suppresscrlf = true;
            }
            break;
        }
        case E_Message_Last_Header: {
            char * last_header = get_last_header(comp->literal);
            if(last_header) {
                dest += sprintf(dest, "%s", last_header);
            }
            if (*(dest - 1) == '\n') {
                suppresscrlf = true;
            }
            break;
        }
        case E_Message_Custom: {
            dest += comp->comp_param.fxn(this, comp, dest, left);
            break;
        }
        case E_Message_Last_Message:
            if(last_recv_msg && strlen(last_recv_msg)) {
                dest += sprintf(dest, "%s", last_recv_msg);
            }
            break;
        case E_Message_Last_Request_URI: {
            char * last_request_uri = get_last_request_uri();
            dest += sprintf(dest, "%s", last_request_uri);
            free(last_request_uri);
            break;
        }
        case E_Message_Last_CSeq_Number: {
            int last_cseq = 0;

            char *last_header = get_last_header("CSeq:");
            if(last_header) {
                last_header += 5;
                /* Extract the integer value of the field */
                while(isspace(*last_header)) last_header++;
                sscanf(last_header, "%d", &last_cseq);
            }
            dest += sprintf(dest, "%d", last_cseq + comp->offset);
            break;
        }
        case E_Message_TDM_Map:
            if (!use_tdmmap)
                ERROR("[tdmmap] keyword without -tdmmap parameter on command line");
            dest += snprintf(dest, left, "%d.%d.%d/%d",
                             tdm_map_x+(int((tdm_map_number)/((tdm_map_b+1)*(tdm_map_c+1))))%(tdm_map_a+1),
                             tdm_map_h,
                             tdm_map_y+(int((tdm_map_number)/(tdm_map_c+1)))%(tdm_map_b+1),
                             tdm_map_z+(tdm_map_number)%(tdm_map_c+1)
                            );
            break;
        }
    }
    /* Need the body for length and auth-int calculation */
    char *body = nullptr;
    const char *auth_body = nullptr;
    if (length_marker || auth_marker) {
        body = strstr(msg_buffer, "\r\n\r\n");
        if (body) {
            auth_body = body;
            auth_body += strlen("\r\n\r\n");
        }
    }
    if (!auth_body) {
        auth_body = "";
    }

    /* Fix up the length. */
    if (length_marker) {
        if (auth_marker > body) {
            ERROR("The authentication keyword should appear in the message header, not the body!");
        }

        if (body && dest - body > 4 && dest - body < 100004) {
            char tmp = length_marker[5];
            sprintf(length_marker, "%5u", (unsigned)(dest - body - 4 + len_offset));
            length_marker[5] = tmp;
        } else {
            // Other cases: Content-Length is 0
            sprintf(length_marker, "    0\r\n\r\n");
        }
    }

    if (msgLen) {
        *msgLen = dest - msg_buffer;
    }

    /*
     * The authentication substitution must be done outside the above
     * loop because auth-int will use the body (which must have already
     * been keyword substituted) to build the md5 hash
     */
    if (auth_marker) {
        if (!dialog_authentication) {
            ERROR("Authentication keyword without dialog_authentication!");
        }

        int  auth_marker_len;
        int  authlen;

        auth_marker_len = (strchr(auth_marker, ']') + 1) - auth_marker;

        /* Determine the type of credentials. */
        char result[MAX_HEADER_LEN];
        if (dialog_challenge_type == 401) {
            /* Registrars use Authorization */
            authlen = sprintf(result, "Authorization: ");
        } else {
            /* Proxies use Proxy-Authorization */
            authlen = sprintf(result, "Proxy-Authorization: ");
        }

        /* Build the auth credenticals */
        char uri[MAX_HEADER_LEN];
        sprintf (uri, "%s:%d", remote_ip, remote_port);
        char my_auth_user[MAX_HEADER_LEN + 2];
        char my_auth_pass[MAX_HEADER_LEN + 2];
        char my_aka_OP[MAX_HEADER_LEN + 2];
        char my_aka_AMF[MAX_HEADER_LEN + 2];
        char my_aka_K[MAX_HEADER_LEN + 2];

        createSendingMessage(auth_comp->comp_param.auth_param.auth_user, SM_UNUSED, my_auth_user, sizeof(my_auth_user));
        createSendingMessage(auth_comp->comp_param.auth_param.auth_pass, SM_UNUSED, my_auth_pass, sizeof(my_auth_pass));
        createSendingMessage(auth_comp->comp_param.auth_param.aka_K, SM_UNUSED, my_aka_K, sizeof(my_aka_K));
        createSendingMessage(auth_comp->comp_param.auth_param.aka_AMF, SM_UNUSED, my_aka_AMF, sizeof(my_aka_AMF));
        createSendingMessage(auth_comp->comp_param.auth_param.aka_OP, SM_UNUSED, my_aka_OP, sizeof(my_aka_OP));

        if (createAuthHeader(
                my_auth_user, my_auth_pass, src->getMethod(), uri,
                auth_body, dialog_authentication, my_aka_OP, my_aka_AMF,
                my_aka_K, next_nonce_count++, result + authlen,
                MAX_HEADER_LEN - authlen) == 0) {
            ERROR("%s", result + authlen);
        }
        authlen = strlen(result);

        /* Shift the end of the message to its rightful place. */
        memmove(auth_marker + authlen, auth_marker + auth_marker_len, strlen(auth_marker + auth_marker_len) + 1);
        /* Copy our result into the hole. */
        memcpy(auth_marker, result, authlen);
        if (msgLen) {
            *msgLen += (authlen -  auth_marker_len);
        }
    }

    if (auth_comp_allocated) {
        SendingMessage::freeMessageComponent(auth_comp);
    }

#ifdef USE_TLS
    // PASS OUTGOING SRTP PARAMETERS...
    if (srtp_audio_updated && (pA.primary_audio_cryptotag != 0))
    {
        rtpstream_set_srtp_audio_local(&rtpstream_callinfo, pA);
        if (sendMode == MODE_CLIENT)
        {
            //
            // RX-UAC-AUDIO SRTP context (b) -- SSRC/IPADDRESS/PORT
            //
            CryptoContextID rxUACA;
            rxUACA.ssrc = rtpstream_callinfo.taskinfo->audio_ssrc_id;
            rxUACA.address = media_ip;
            rxUACA.port = rtpstream_callinfo.local_audioport;
            logSrtpInfo("call::createSendingMessage():  (b) RX-UAC-AUDIO SRTP context - ssrc:0x%08x address:%s port:%d\n", rxUACA.ssrc, rxUACA.address.c_str(), rxUACA.port);
            _rxUACAudio.setID(rxUACA);
        }
    }
    if (srtp_video_updated && (pV.primary_video_cryptotag != 0))
    {
        rtpstream_set_srtp_video_local(&rtpstream_callinfo, pV);
        if (sendMode == MODE_CLIENT)
        {
            //
            // RX-UAC-VIDEO SRTP context (b) -- SSRC/IPADDRESS/PORT
            //
            CryptoContextID rxUACV;
            rxUACV.ssrc = rtpstream_callinfo.taskinfo->video_ssrc_id;
            rxUACV.address = media_ip;
            rxUACV.port = rtpstream_callinfo.local_videoport;
            logSrtpInfo("call::createSendingMessage():  (b) RX-UAC-VIDEO SRTP context - ssrc:0x%08x address:%s port:%d\n", rxUACV.ssrc, rxUACV.address.c_str(), rxUACV.port);
            _rxUACVideo.setID(rxUACV);
        }
    }
#endif // USE_TLS

    if (body &&
        !strcmp(get_header_content(msg_buffer, (char*)"Content-Type:"), "application/sdp"))
    {
        if (getSessionStateCurrent() == eNoSession)
        {
#ifdef USE_TLS
            logSrtpInfo("call::createSendingMessage():  Switching session state:  eNoSession --> eOfferSent\n");
#endif // USE_TLS
            setSessionState(eOfferSent);
        }
        else if (getSessionStateCurrent() == eCompleted)
        {
#ifdef USE_TLS
            logSrtpInfo("call::createSendingMessage():  Switching session state:  eCompleted --> eOfferSent\n");
#endif // USE_TLS
            setSessionState(eOfferSent);
        }
        else if (getSessionStateCurrent() == eOfferReceived)
        {
#ifdef USE_TLS
            logSrtpInfo("call::createSendingMessage():  Switching session state:  eOfferReceived --> eAnswerSent\n");
#endif // USE_TLS
            setSessionState(eAnswerSent);
#ifdef USE_TLS
            logSrtpInfo("call::createSendingMessage():  Switching session state:  eAnswerSent --> eCompleted\n");
#endif // USE_TLS
            setSessionState(eCompleted);
        }
    }

    return msg_buffer;
}

bool call::process_twinSippCom(char * msg)
{
    int             search_index;
    bool            found = false;
    T_ActionResult  actionResult;

    callDebug("Processing incoming command for call-ID %s:\n%s\n\n", id, msg);

    setRunning();

    if (checkInternalCmd(msg) == false) {

        for(search_index = msg_index;
                search_index < (int)call_scenario->messages.size();
                search_index++) {
            if(call_scenario->messages[search_index] -> M_type != MSG_TYPE_RECVCMD) {
                if ((call_scenario->messages[search_index] -> optional) ||
                    (call_scenario->messages[search_index] -> M_type == MSG_TYPE_NOP)) {
                    continue;
                }
                /* The received message is different from the expected one */
                TRACE_MSG("Unexpected control message received (I was expecting a different type of message):\n%s\n", msg);
                callDebug("Unexpected control message received (I was expecting a different type of message):\n%s\n\n", msg);
                return rejectCall();
            } else {
                if(extendedTwinSippMode) {                  // 3pcc extended mode
                    if(check_peer_src(msg, search_index)) {
                        found = true;
                        break;
                    } else {
                        WARNING("Unexpected sender for the received peer message\n%s\n", msg);
                        return rejectCall();
                    }
                } else {
                    found = true;
                    break;
                }
            }
        }

        if (found) {
            call_scenario->messages[search_index]->M_nbCmdRecv ++;
            do_bookkeeping(call_scenario->messages[search_index]);

            // variable treatment
            // Remove \r, \n at the end of a received command
            // (necessary for transport, to be removed for usage)
            while ( (msg[strlen(msg)-1] == '\n') &&
                    (msg[strlen(msg)-2] == '\r') ) {
                msg[strlen(msg)-2] = 0;
            }
            actionResult = executeAction(msg, call_scenario->messages[search_index]);

            if(actionResult != call::E_AR_NO_ERROR) {
                // Store last action result if it is an error
                // and go on with the scenario
                call::last_action_result = actionResult;
                if (actionResult == E_AR_STOP_CALL) {
                    return rejectCall();
                } else if (actionResult == E_AR_CONNECT_FAILED) {
                    terminate(CStat::E_FAILED_TCP_CONNECT);
                    return false;
                }
            }
        } else {
            TRACE_MSG("Unexpected control message received (no such message found):\n%s\n", msg);
            callDebug("Unexpected control message received (no such message found):\n%s\n\n", msg);
            return rejectCall();
        }
        msg_index = search_index; //update the state machine
        return(next());
    } else {
        return (false);
    }
}

bool call::checkInternalCmd(char * cmd)
{

    char * L_ptr1, * L_ptr2, L_backup;

    L_ptr1 = strstr(cmd, "internal-cmd:");
    if (!L_ptr1) {
        return (false);
    }
    L_ptr1 += 13 ;
    while((*L_ptr1 == ' ') || (*L_ptr1 == '\t')) {
        L_ptr1++;
    }
    if (!(*L_ptr1)) {
        return (false);
    }
    L_ptr2 = L_ptr1;
    while((*L_ptr2) &&
            (*L_ptr2 != ' ') &&
            (*L_ptr2 != '\t') &&
            (*L_ptr2 != '\r') &&
            (*L_ptr2 != '\n')) {
        L_ptr2 ++;
    }
    if(!*L_ptr2) {
        return (false);
    }
    L_backup = *L_ptr2;
    *L_ptr2 = 0;

    if (strcmp(L_ptr1, "abort_call") == 0) {
        *L_ptr2 = L_backup;
        computeStat(CStat::E_CALL_FAILED);
        abortCall(true);
        return (true);
    }

    *L_ptr2 = L_backup;
    return (false);
}

bool call::check_peer_src(char * msg, int search_index)
{
    char * L_ptr1, * L_ptr2, L_backup ;

    L_ptr1 = strstr(msg, "From:");
    if (!L_ptr1) {
        return (false);
    }
    L_ptr1 += 5 ;
    while((*L_ptr1 == ' ') || (*L_ptr1 == '\t')) {
        L_ptr1++;
    }
    if (!(*L_ptr1)) {
        return (false);
    }
    L_ptr2 = L_ptr1;
    while((*L_ptr2) &&
            (*L_ptr2 != ' ') &&
            (*L_ptr2 != '\t') &&
            (*L_ptr2 != '\r') &&
            (*L_ptr2 != '\n')) {
        L_ptr2 ++;
    }
    if(!*L_ptr2) {
        return (false);
    }
    L_backup = *L_ptr2;
    *L_ptr2 = 0;
    if (strcmp(L_ptr1, call_scenario->messages[search_index] -> peer_src) == 0) {
        *L_ptr2 = L_backup;
        return(true);
    }

    *L_ptr2 = L_backup;
    return (false);
}


void call::extract_cseq_method(char* method, const char* msg)
{
    const char* cseq;
    if ((cseq = strstr (msg, "CSeq"))) {
        const char* value;
        if ((value = strchr(cseq, ':'))) {
            value++;
            while (isspace(*value)) value++;  // ignore any white spaces after the :
            while (!isspace(*value)) value++;  // ignore the CSEQ number
            while (isspace(*value)) value++;  // ignore spaces after CSEQ number
            const char* end = value;
            int nbytes = 0;
            /* A '\r' terminates the line, so we want to catch that too. */
            while ((*end != '\r') && (*end != '\n')) {
                end++;
                nbytes++;
            }
            if (nbytes > 0) strncpy (method, value, nbytes);
            method[nbytes] = '\0';
        }
    }
}

void call::extract_transaction(char* txn, const char* msg)
{
    char *via = get_header_content(msg, "via:");
    if (!via) {
        txn[0] = '\0';
        return;
    }

    char *branch = strstr(via, ";branch=");
    if (!branch) {
        txn[0] = '\0';
        return;
    }

    branch += strlen(";branch=");
    while (*branch && *branch != ';' && *branch != ',' && !isspace(*branch)) {
        *txn++ = *branch++;
    }
    *txn = '\0';
}

void call::formatNextReqUrl(const char* contact)
{
    /* clean up the next_req_url */
    while (*contact != '\0' && (*contact == ' ' || *contact == '\t')) {
        ++contact;
    }
    const char* start = strchr(contact, '<');
    const char* end = strchr(contact, '>');
    if ((start && end)  && (start < end)) {
        contact = start;
        contact++;
        next_req_url[0] = '\0';
        strncat(next_req_url, contact,
                std::min(MAX_HEADER_LEN - 1, (int)(end - contact))); /* fits MAX_HEADER_LEN */
    } else {
        next_req_url[0] = '\0';
        strncat(next_req_url, contact, MAX_HEADER_LEN - 1);
    }
}

void call::computeRouteSetAndRemoteTargetUri(const char* rr, const char* contact, bool bRequestIncoming)
{
    if (!*contact) {
        WARNING("Cannot record route set if there is no Contact");
        return;
    }

    if (!*rr) {
        /* There are no RR headers. Simply set up the contact as our
         * target uri.  Note that this is only called if there was no
         * dialog_route_set at the moment.  And in either case, we
         * wouldn't want to clear the dialog_route_set because changing
         * RR mid-dialog is not allowed. */
        formatNextReqUrl(contact);
        return;
    }

    std::vector<std::string> headers = split(rr, ',');
    std::vector<std::string>::iterator it;
    std::vector<std::string>::iterator end;
    int direction;

    if (bRequestIncoming) {
        it = headers.begin();
        end = headers.end();
        direction = 1;
    } else {
        it = headers.end() - 1;
        end = headers.begin() - 1;
        direction = -1;
    }

    std::vector<std::string> routes;
    std::string targetUri;
    bool first = true;

    for (; it != end; it += direction) {
        const std::string& header = *it;

        if (first && header.find(";lr") == std::string::npos) {
            /* If the next hop is a static router, set target URI to
             * that router. We'll push the original contact onto the end
             * of the route set. We won't need to record this route,
             * because we've set the target to it. */
            targetUri = header;
        } else {
            first = false;
            routes.push_back(trim(header));
        }
    }

    /* If target URI is set, the first hop is a strict router.  Add the
     * Contact as tailing route. */
    if (targetUri.length()) {
        routes.push_back(trim(contact));
    } else {
        targetUri = contact;
    }

    if (routes.size()) {
        dialog_route_set = strdup(join(routes, ", ").c_str());
    }

    formatNextReqUrl(targetUri.c_str());
}

bool call::matches_scenario(unsigned int index, int reply_code, char * request, char * responsecseqmethod, char *txn)
{
    message *curmsg = call_scenario->messages[index];

    if ((curmsg->recv_request)) {
        if (curmsg->regexp_match) {
            if (curmsg->regexp_compile == nullptr) {
                regex_t *re = new regex_t;
                /* No regex match position needed (NOSUB), we're simply
                 * looking for the <request method="INVITE|REGISTER"../>
                 * regex. */
                if (regcomp(re, curmsg->recv_request, REGCOMP_PARAMS|REG_NOSUB)) {
                    ERROR("Invalid regular expression for index %d: %s", index, curmsg->recv_request);
                }
                curmsg->regexp_compile = re;
            }
            return !regexec(curmsg->regexp_compile, request, (size_t)0, nullptr, REGEXEC_PARAMS);
        } else {
            return !strcmp(curmsg->recv_request, request);
        }
    } else if (curmsg->recv_response) {
        if (curmsg->regexp_match) { // Match response code using regex
            char reply_code_str[8];
           snprintf(reply_code_str, 8, "%u", reply_code); // Convert the response code to string
            if (curmsg->regexp_compile == nullptr) {
                regex_t *re = new regex_t;
                /* No regex match position needed (NOSUB), we're simply
                 * looking for the <request method="INVITE|REGISTER"../>
                 * regex. */
                if (regcomp(re, curmsg->recv_response, REGCOMP_PARAMS|REG_NOSUB)) {
                    ERROR("Invalid regular expression for index %d: %s", index, curmsg->recv_response);
                }
                curmsg->regexp_compile = re;
            }
            if (regexec(curmsg->regexp_compile, reply_code_str, (size_t)0, nullptr, REGEXEC_PARAMS)) {
               return false;
           }
        } else { // Exact numerical match
            if (atoi(curmsg->recv_response) != reply_code) {
               return false;
           }
        }
       /* This is a potential candidate, we need to match transactions. */
       if (curmsg->response_txn) {
           if (transactions[curmsg->response_txn - 1].txnID && !strcmp(transactions[curmsg->response_txn - 1].txnID, txn)) {
               return true;
           } else {
               return false;
           }
       } else if (index == 0) {
           /* Always true for the first message. */
           return true;
       } else if (curmsg->recv_response_for_cseq_method_list &&
                  strstr(curmsg->recv_response_for_cseq_method_list, responsecseqmethod)) {
           /* If we do not have a transaction defined, we just check the CSEQ method. */
           return true;
       } else {
           return false;
       }
    }

    return false;
}

void call::queue_up(const char* msg)
{
    free(queued_msg);
    queued_msg = strdup(msg);
}

bool call::process_incoming(const char* msg, const struct sockaddr_storage* src)
{
    int             reply_code = 0;
    static char     request[65];
    char            responsecseqmethod[65];
    char            txn[MAX_HEADER_LEN];
    unsigned long   cookie = 0;
    const char*     ptr;
    int             search_index;
    bool            found = false;
    T_ActionResult  actionResult;
    unsigned long int invite_cseq = 0;

    update_clock_tick();
    callDebug("Processing %zu byte incoming message for call-ID %s (hash %lu):\n%s\n\n",
              strlen(msg), id, hash(msg), msg);

    setRunning();
    message *curmsg = call_scenario->messages[msg_index];

    /* Ignore the messages received during a pause if -pause_msg_ign is set */
    if (curmsg->M_type == MSG_TYPE_PAUSE && pause_msg_ign) {
        return true;
    }

    /* Get our destination if we have none. */
    if (call_peer.ss_family == AF_UNSPEC && src) {
        memcpy(&call_peer, src, sizeof(call_peer));
    }

    /* Authorize nop as a first command, even in server mode */
    if (msg_index == 0 && curmsg->M_type == MSG_TYPE_NOP) {
        queue_up(msg);
        paused_until = 0;
        return run();
    }
    responsecseqmethod[0] = '\0';
    txn[0] = '\0';

    if (!checkAckCSeq(msg)) {
        WARNING("ACK CSeq value does NOT match value of related INVITE CSeq -- aborting call\n");
        computeStat(CStat::E_CALL_FAILED);
        delete this;
        return false;
    }

    /* Check that we have a To:-header */
    if (!get_header(msg, "To:", false)[0] && !process_unexpected(msg)) {
        return false;
    }

    if ((transport == T_UDP) && (retrans_enabled)) {
        /* Detects retransmissions from peer and retransmit the
         * message which was sent just after this one was received */
        cookie = hash(msg);
        if((recv_retrans_recv_index >= 0) && (recv_retrans_hash == cookie)) {

            int status;

            if(lost(recv_retrans_recv_index)) {
                TRACE_MSG("%s message (retrans) lost (recv).",
                          TRANSPORT_TO_STRING(transport));
                callDebug("%s message (retrans) lost (recv) (hash %lu)\n", TRANSPORT_TO_STRING(transport), hash(msg));

                if(comp_state) {
                    comp_free(&comp_state);
                }
                call_scenario->messages[recv_retrans_recv_index] -> nb_lost++;
                return true;
            }

            call_scenario->messages[recv_retrans_recv_index] -> nb_recv_retrans++;

            send_scene(recv_retrans_send_index, &status, nullptr);

            if(status >= 0) {
                call_scenario->messages[recv_retrans_send_index] -> nb_sent_retrans++;
                computeStat(CStat::E_RETRANSMISSION);
            } else if(status < 0) {
                return false;
            }

            return true;
        }

        if((last_recv_index >= 0) && (last_recv_hash == cookie)) {
            /* This one has already been received, but not processed
             * yet => (has not triggered something yet) so we can discard.
             *
             * This case appears when the UAS has send a 200 but not received
             * a ACK yet. Thus, the UAS retransmit the 200 (invite transaction)
             * until it receives a ACK. In this case, it never sends the 200
             * from the  BYE, until it has reveiced the previous 200. Thus,
             * the UAC retransmit the BYE, and this BYE is considered as an
             * unexpected.
             *
             * This case can also appear in case of message duplication by
             * the network. This should not be considered as an unexpected.
             */
            call_scenario->messages[last_recv_index]->nb_recv_retrans++;
            return true;
        }
    }

    /* Check if message has a SDP in it; and extract media information. */
    if (!strcmp(get_header_content(msg, "Content-Type:"), "application/sdp") &&
          (hasMedia == 1) &&
          (!curmsg->ignoresdp))
    {
        const char* ptr = 0;
        int ip_ver = 0;
        int audio_port = 0;
        int video_port = 0;
        std::string host;

#ifdef USE_TLS
        int audio_answer_ciphersuite_match = -1;
        int video_answer_ciphersuite_match = -1;
#endif // USE_TLS

        ptr = get_header_content(msg, "Content-Length:");

        if (ptr && atoll(ptr) > 0)
        {
            if (getSessionStateCurrent() == eNoSession)
            {
#ifdef USE_TLS
                logSrtpInfo("call::process_incoming():  Switching session state:  eNoSession --> eOfferReceived\n");
#endif // USE_TLS
                setSessionState(eOfferReceived);
            }
            else if (getSessionStateCurrent() == eCompleted)
            {
#ifdef USE_TLS
                logSrtpInfo("call::process_incoming():  Switching session state:  eCompleted --> eOfferReceived\n");
#endif // USE_TLS
                setSessionState(eOfferReceived);
            }
            else if (getSessionStateCurrent() == eOfferSent)
            {
#ifdef USE_TLS
                logSrtpInfo("call::process_incoming():  Switching session state:  eOfferSent --> eAnswerReceived\n");
#endif // USE_TLS
                setSessionState(eAnswerReceived);
#ifdef USE_TLS
                logSrtpInfo("call::process_incoming();  Switching session state:  eAnswerReceived --> eCompleted\n");
#endif // USE_TLS
                setSessionState(eCompleted);
            }

#ifdef USE_TLS
            // INCOMING SRTP PARAM CONTEXT
            SrtpAudioInfoParams pA;
            SrtpVideoInfoParams pV;

            pA.audio_found = false;
            pA.primary_audio_cryptotag = 0;
            memset(pA.primary_audio_cryptosuite, 0, sizeof(pA.primary_audio_cryptosuite));
            memset(pA.primary_audio_cryptokeyparams, 0, sizeof(pA.primary_audio_cryptokeyparams));
            pA.secondary_audio_cryptotag = 0;
            memset(pA.secondary_audio_cryptosuite, 0, sizeof(pA.secondary_audio_cryptosuite));
            memset(pA.secondary_audio_cryptokeyparams, 0, sizeof(pA.secondary_audio_cryptokeyparams));
            pA.primary_unencrypted_audio_srtp = false;
            pA.secondary_unencrypted_audio_srtp = false;

            pV.video_found = false;
            pV.primary_video_cryptotag = 0;
            memset(pV.primary_video_cryptosuite, 0, sizeof(pV.primary_video_cryptosuite));
            memset(pV.primary_video_cryptokeyparams, 0, sizeof(pV.primary_video_cryptokeyparams));
            pV.secondary_video_cryptotag = 0;
            memset(pV.secondary_video_cryptosuite, 0, sizeof(pV.secondary_video_cryptosuite));
            memset(pV.secondary_video_cryptokeyparams, 0, sizeof(pV.secondary_video_cryptokeyparams));
            pV.primary_unencrypted_video_srtp = false;
            pV.secondary_unencrypted_video_srtp = false;
#endif // USE_TLS

            host = extract_rtp_remote_addr(msg, ip_ver, audio_port, video_port);

#ifdef USE_TLS
            extract_srtp_remote_info(msg, pA, pV);
#endif // USE_TLS

            if ((audio_port==0) && (video_port==0)) {
                WARNING("extract_rtp_remote_addr: no m=audio or m=video or m=image line found in SDP message body");
            } else {
                rtpstream_set_remote(&rtpstream_callinfo, ip_ver, host.c_str(), audio_port, video_port);
            }

#ifdef USE_TLS
            // PASS INCOMING SRTP PARAMETERS...
            if (pA.audio_found && (pA.primary_audio_cryptotag != 0))
            {
                //
                // INCOMING OFFER -- PERFORM PRIMARY/SECONDARY AUDIO SWAPS IF NEEDED/APPLICABLE
                //
                if ((getSessionStateCurrent() == eOfferReceived) && ((getSessionStateOld() == eNoSession || getSessionStateOld() == eCompleted)))
                {
                    // NO-OP...
                }
                //
                // INCOMING ANSWER -- PERFORM PRIMARY/SECONDARY AUDIO SWAPS IF NEEDED/APPLICABLE
                //
                else if ((getSessionStateCurrent() == eCompleted) && (getSessionStateOld() == eAnswerReceived))
                {
                    audio_answer_ciphersuite_match = check_audio_ciphersuite_match(pA);
                }

                rtpstream_set_srtp_audio_remote(&rtpstream_callinfo, pA);
                if (sendMode == MODE_CLIENT)
                {
                    //
                    // TX-UAC-AUDIO SRTP context (a) -- SSRC/IPADDRESS/PORT
                    //
                    CryptoContextID txUACA;
                    txUACA.ssrc = rtpstream_callinfo.taskinfo->audio_ssrc_id;
                    txUACA.address = host;
                    txUACA.port = audio_port;
                    logSrtpInfo("call::process_incoming():  (a) TX-UAC-AUDIO SRTP context - ssrc:0x%08x address:%s port:%d\n", txUACA.ssrc, txUACA.address.c_str(), txUACA.port);
                    _txUACAudio.setID(txUACA);

                    if (audio_answer_ciphersuite_match == 0)
                    {
                        logSrtpInfo("call::process_incoming():  (a) TX-UAC_AUDIO SRTP context -- CLIENT -- CIPHERSUITE SWAP...\n");
                        _txUACAudio.swapCrypto();
                    }

                    //
                    // RX-UAC-AUDIO SRTP context (b) -- MASTER KEY/SALT PARSE + CRYPTO TAG + CRYPTOSUITE
                    //
                    std::string mks1;
                    mks1 = pA.primary_audio_cryptokeyparams;
                    if (!mks1.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- primary master key/salt: %s\n", mks1.c_str());
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- primary crypto tag: %d\n", pA.primary_audio_cryptotag);
                        _rxUACAudio.decodeMasterKeySalt(mks1, PRIMARY_CRYPTO);
                        _rxUACAudio.setCryptoTag(pA.primary_audio_cryptotag, PRIMARY_CRYPTO);

                        if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "NULL_HMAC_SHA1_80") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "NULL_HMAC_SHA1_32") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                    }

                    std::string mks2;
                    mks2 = pA.secondary_audio_cryptokeyparams;
                    if (!mks2.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- secondary master key/salt: %s\n", mks2.c_str());
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- secondary crypto tag: %d\n", pA.secondary_audio_cryptotag);
                        _rxUACAudio.decodeMasterKeySalt(mks2, SECONDARY_CRYPTO);
                        _rxUACAudio.setCryptoTag(pA.secondary_audio_cryptotag, SECONDARY_CRYPTO);

                        if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pA.secondary_unencrypted_audio_srtp)
                        {
                             logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "NULL_HMAC_SHA1_80") && !pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "NULL_HMAC_SHA1_32") && !pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pA.secondary_unencrypted_audio_srtp)
                        {
                             logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-AUDIO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUACAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                    }
                }
                if (sendMode == MODE_SERVER)
                {
                    //
                    // TX-UAS-AUDIO SRTP context (d) -- SSRC/IPADDRESS/PORT
                    //
                    CryptoContextID txUASA;
                    txUASA.ssrc = rtpstream_callinfo.taskinfo->audio_ssrc_id;
                    txUASA.address = host;
                    txUASA.port = audio_port;
                    logSrtpInfo("call::process_incoming():  (d) TX-UAS-AUDIO SRTP context - ssrc:0x%08x address:%s port:%d\n", txUASA.ssrc, txUASA.address.c_str(), txUASA.port);
                    _txUASAudio.setID(txUASA);

                    if (audio_answer_ciphersuite_match == 0)
                    {
                        logSrtpInfo("call::process_incoming():  (d) TX-UAS_AUDIO SRTP context -- SERVER -- CIPHERSUITE SWAP...\n");
                        _txUASAudio.swapCrypto();
                    }

                    //
                    // RX-UAS-AUDIO SRTP context (c) -- MASTER KEY/SALT PARSE + CRYPTO TAG + CRYPTOSUITE
                    //
                    std::string mks1;
                    mks1 = pA.primary_audio_cryptokeyparams;
                    if (!mks1.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- primary master key/salt: %s\n", mks1.c_str());
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- primary crypto tag: %d\n", pA.primary_audio_cryptotag);
                        _rxUASAudio.decodeMasterKeySalt(mks1, PRIMARY_CRYPTO);
                        _rxUASAudio.setCryptoTag(pA.primary_audio_cryptotag, PRIMARY_CRYPTO);

                        if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "NULL_HMAC_SHA1_80") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "NULL_HMAC_SHA1_32") && !pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pA.primary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pA.primary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pA.primary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                    }

                    std::string mks2;
                    mks2 = pA.secondary_audio_cryptokeyparams;
                    if (!mks2.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- secondary master key/salt: %s\n", mks2.c_str());
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- secondary crypto tag: %d\n", pA.secondary_audio_cryptotag);
                        _rxUASAudio.decodeMasterKeySalt(mks2, SECONDARY_CRYPTO);
                        _rxUASAudio.setCryptoTag(pA.secondary_audio_cryptotag, SECONDARY_CRYPTO);

                        if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "NULL_HMAC_SHA1_80") && !pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "NULL_HMAC_SHA1_32") && !pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pA.secondary_audio_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pA.secondary_unencrypted_audio_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-AUDIO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pA.secondary_audio_cryptosuite);
                            _rxUASAudio.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASAudio.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                    }
                }
            }
            if (pV.video_found && (pV.primary_video_cryptotag != 0))
            {
                //
                // INCOMING OFFER -- PERFORM PRIMARY/SECONDARY VIDEO SWAPS IF NEEDED/APPLICABLE
                //
                if ((getSessionStateCurrent() == eOfferReceived) && ((getSessionStateOld() == eNoSession || getSessionStateOld() == eCompleted)))
                {
                    // NO-OP...
                }
                //
                // INCOMING ANSWER -- PERFORM PRIMARY/SECONDARY VIDEO SWAPS IF NEEDED/APPLICABLE
                //
                else if ((getSessionStateCurrent() == eCompleted) && (getSessionStateOld() == eAnswerReceived))
                {
                    video_answer_ciphersuite_match = check_video_ciphersuite_match(pV);
                }

                rtpstream_set_srtp_video_remote(&rtpstream_callinfo, pV);
                if (sendMode == MODE_CLIENT)
                {
                    //
                    // TX-UAC-VIDEO SRTP context (a) -- SSRC/IPADDRESS/PORT
                    //
                    CryptoContextID txUACV;
                    txUACV.ssrc = rtpstream_callinfo.taskinfo->video_ssrc_id;
                    txUACV.address = host;
                    txUACV.port = video_port;
                    logSrtpInfo("call::process_incoming():  (a) TX-UAC-VIDEO SRTP context - ssrc:0x%08x address:%s port:%d\n", txUACV.ssrc, txUACV.address.c_str(), txUACV.port);
                    _txUACVideo.setID(txUACV);

                    if (video_answer_ciphersuite_match == 0)
                    {
                        logSrtpInfo("call::process_incoming():  (a) TX-UAC_VIDEO SRTP context -- CLIENT -- CIPHERSUITE SWAP...\n");
                        _txUACVideo.swapCrypto();
                    }

                    //
                    // RX-UAC-VIDEO SRTP context (b) -- MASTER KEY/SALT PARSE + CRYPTO TAG + CRYPTOSUITE
                    //
                    std::string mks1;
                    mks1 = pV.primary_video_cryptokeyparams;
                    if (!mks1.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- primary master key/salt: %s\n", mks1.c_str());
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- primary crypto tag: %d\n", pV.primary_video_cryptotag);
                        _rxUACVideo.decodeMasterKeySalt(mks1, PRIMARY_CRYPTO);
                        _rxUACVideo.setCryptoTag(pV.primary_video_cryptotag, PRIMARY_CRYPTO);

                        if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "NULL_HMAC_SHA1_80") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "NULL_HMAC_SHA1_32") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                    }

                    std::string mks2;
                    mks2 = pV.secondary_video_cryptokeyparams;
                    if (!mks2.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- secondary master key/salt: %s\n", mks2.c_str());
                        logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- secondary crypto tag: %d\n", pV.secondary_video_cryptotag);
                        _rxUACVideo.decodeMasterKeySalt(mks2, SECONDARY_CRYPTO);
                        _rxUACVideo.setCryptoTag(pV.secondary_video_cryptotag, SECONDARY_CRYPTO);

                        if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "NULL_HMAC_SHA1_80") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "NULL_HMAC_SHA1_32") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (b) RX-UAC-VIDEO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUACVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUACVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                    }
                }
                if (sendMode == MODE_SERVER)
                {
                    //
                    // TX-UAS-VIDEO SRTP context (d) -- SSRC/IPADDRESS/PORT
                    //
                    CryptoContextID txUASV;
                    txUASV.ssrc = rtpstream_callinfo.taskinfo->video_ssrc_id;
                    txUASV.address = host;
                    txUASV.port = video_port;
                    logSrtpInfo("call::process_incoming():  (d) TX-UAS-VIDEO SRTP context - ssrc:0x%08x address:%s port:%d\n", txUASV.ssrc, txUASV.address.c_str(), txUASV.port);
                    _txUASVideo.setID(txUASV);

                    if (video_answer_ciphersuite_match == 0)
                    {
                        logSrtpInfo("call::process_incoming():  (d) TX-UAS_VIDEO SRTP context -- SERVER -- CIPHERSUITE SWAP...\n");
                        _txUASVideo.swapCrypto();
                    }

                    //
                    // RX-UAS-VIDEO SRTP context (c) -- MASTER KEY/SALT PARSE + CRYPTO TAG + CRYPTOSUITE
                    //
                    std::string mks1;
                    mks1 = pV.primary_video_cryptokeyparams;
                    if (!mks1.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- primary master key/salt: %s\n", mks1.c_str());
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- primary crypto tag: %d\n", pV.primary_video_cryptotag);
                        _rxUASVideo.decodeMasterKeySalt(mks1, PRIMARY_CRYPTO);
                        _rxUASVideo.setCryptoTag(pV.primary_video_cryptotag, PRIMARY_CRYPTO);

                        if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(AES_CM_128, PRIMARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "NULL_HMAC_SHA1_80") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "NULL_HMAC_SHA1_32") && !pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_80, PRIMARY_CRYPTO);
                        }
                        else if (!strcmp(pV.primary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pV.primary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- NOENCRYPTION -- primary cryptosuite: [%s]\n", pV.primary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, PRIMARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_32, PRIMARY_CRYPTO);
                        }
                    }

                    std::string mks2;
                    mks2 = pV.secondary_video_cryptokeyparams;
                    if (!mks2.empty())
                    {
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- secondary master key/salt: %s\n", mks2.c_str());
                        logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- secondary crypto tag: %d\n", pV.secondary_video_cryptotag);
                        _rxUASVideo.decodeMasterKeySalt(mks2, SECONDARY_CRYPTO);
                        _rxUASVideo.setCryptoTag(pV.secondary_video_cryptotag, SECONDARY_CRYPTO);

                        if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(AES_CM_128, SECONDARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "NULL_HMAC_SHA1_80") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "NULL_HMAC_SHA1_32") && !pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- ENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO);
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_80") && pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_80, SECONDARY_CRYPTO);
                        }
                        else if (!strcmp(pV.secondary_video_cryptosuite, "AES_CM_128_HMAC_SHA1_32") && pV.secondary_unencrypted_video_srtp)
                        {
                            logSrtpInfo("call::process_incoming():  (c) RX-UAS-VIDEO SRTP context -- NOENCRYPTION -- secondary cryptosuite: [%s]\n", pV.secondary_video_cryptosuite);
                            _rxUASVideo.selectCipherAlgorithm(NULL_CIPHER, SECONDARY_CRYPTO); /* Request JLSRTP NOT to decrypt */
                            _rxUASVideo.selectHashAlgorithm(HMAC_SHA1_32, SECONDARY_CRYPTO);
                        }
                    }
                }
            }
#endif // USE_TLS
        } // ptr
    } // Content-Type

    /* Is it a response ? */
    if ((msg[0] == 'S') &&
            (msg[1] == 'I') &&
            (msg[2] == 'P') &&
            (msg[3] == '/') &&
            (msg[4] == '2') &&
            (msg[5] == '.') &&
            (msg[6] == '0')) {

        reply_code = get_reply_code(msg);
        if (!reply_code) {
            if (!process_unexpected(msg)) {
                return false; // Call aborted by unexpected message handling
            }
#ifdef PCAPPLAY
        } else if (hasMedia == 1 && !curmsg->ignoresdp && *(strstr(msg, "\r\n\r\n") + 4) != '\0') {
            /* Get media info if we find something like an SDP */
            get_remote_media_addr(msg);
#endif
        }
        /* It is a response: update peer_tag */
        ptr = get_peer_tag(msg);
        if (ptr) {
            if(strlen(ptr) > (MAX_HEADER_LEN - 1)) {
                ERROR("Peer tag too long. Change MAX_HEADER_LEN and recompile sipp");
            }
            if(peer_tag) {
                free(peer_tag);
            }
            peer_tag = strdup(ptr);
            if (!peer_tag) {
                ERROR("Out of memory allocating peer tag.");
            }
        }
        request[0] = 0;
        // extract the cseq method from the response
        extract_cseq_method(responsecseqmethod, msg);
        extract_transaction(txn, msg);
    } else if ((ptr = strchr(msg, ' '))) {
        if ((ptr - msg) < 64) {
            memcpy(request, msg, ptr - msg);
            request[ptr - msg] = 0;
            // Check if we received an ACK => call established
            if (strcmp(request, "ACK") == 0) {
                call_established = true;
            }
#ifdef PCAPPLAY
            /* In case of INVITE or re-INVITE, ACK or PRACK
               get the media info if needed (= we got a pcap
               play action) */
            if (((strncmp(request, "INVITE", 6) == 0)
                    || (strncmp(request, "ACK", 3) == 0)
                    || (strncmp(request, "PRACK", 5) == 0))
                    && hasMedia == 1 && !curmsg->ignoresdp) {
                get_remote_media_addr(msg);
            }
#endif
            if (!strncmp(request, "INVITE", 6)) {
                invite_cseq = get_cseq_value(msg);
                last_recv_invite_cseq = invite_cseq;
            }
            reply_code = 0;
        } else {
            ERROR("SIP method too long in received message '%s'",
                  msg);
        }
    } else {
        ERROR("Invalid sip message received '%s'",
              msg);
    }

    /* Try to find it in the expected non mandatory responses
     * until the first mandatory response in the scenario */
    for (search_index = msg_index;
            search_index < (int)call_scenario->messages.size();
            search_index++) {
        if (!matches_scenario(search_index, reply_code, request, responsecseqmethod, txn)) {
            if (call_scenario->messages[search_index]->optional) {
                continue;
            }
            /* The received message is different for the expected one */
            break;
        }

        found = true;
        /* TODO : this is a little buggy: If a 100 trying from an INVITE
         * is delayed by the network until the BYE is sent, it may
         * stop BYE transmission erroneously, if the BYE also expects
         * a 100 trying. */
        break;
    }

    /* Try to find it in the old non-mandatory receptions */
    if (!found) {
        bool contig = true;
        for(search_index = msg_index - 1;
                search_index >= 0;
                search_index--) {
            if (call_scenario->messages[search_index]->optional == OPTIONAL_FALSE) {
                contig = false;
            }
            if (matches_scenario(search_index, reply_code, request, responsecseqmethod, txn)) {
                if (contig || call_scenario->messages[search_index]->optional == OPTIONAL_GLOBAL) {
                    found = true;
                    break;
                } else {
                    if (int checkTxn = call_scenario->messages[search_index]->response_txn) {
                        /* This is a reply to an old transaction. */
                        if (!strcmp(transactions[checkTxn - 1].txnID, txn)) {
                            /* This reply is provisional, so it should have no effect if we receive it out-of-order. */
                            if (reply_code >= 100 && reply_code <= 199) {
                                TRACE_MSG("-----------------------------------------------\n"
                                          "Ignoring provisional %s message for transaction %s:\n\n%s\n",
                                          TRANSPORT_TO_STRING(transport), call_scenario->transactions[checkTxn - 1].name, msg);
                                callDebug("Ignoring provisional %s message for transaction %s (hash %lu):\n\n%s\n",
                                          TRANSPORT_TO_STRING(transport), call_scenario->transactions[checkTxn - 1].name, hash(msg), msg);
                                return true;
                            } else if (int ackIndex = transactions[checkTxn - 1].ackIndex) {
                                /* This is the message before an ACK, so verify that this is an invite transaction. */
                                assert (call_scenario->transactions[checkTxn - 1].isInvite);
                                sendBuffer(createSendingMessage(call_scenario->messages[ackIndex]->send_scheme, ackIndex));
                                return true;
                            } else {
                                assert (!call_scenario->transactions[checkTxn - 1].isInvite);
                                /* This is a non-provisional message for the transaction, and
                                 * we have already gotten our allowable response.  Just make sure
                                 * that it is not a retransmission of the final response. */
                                if (transactions[checkTxn - 1].txnResp == hash(msg)) {
                                    /* We have gotten this retransmission out-of-order, let's just ignore it. */
                                    TRACE_MSG("-----------------------------------------------\n"
                                              "Ignoring final %s message for transaction %s:\n\n%s\n",
                                              TRANSPORT_TO_STRING(transport), call_scenario->transactions[checkTxn - 1].name, msg);
                                    callDebug("Ignoring final %s message for transaction %s (hash %lu):\n\n%s\n",
                                              TRANSPORT_TO_STRING(transport), call_scenario->transactions[checkTxn - 1].name, hash(msg), msg);
                                    WARNING("Ignoring final %s message for transaction %s (hash %lu):\n\n%s",
                                            TRANSPORT_TO_STRING(transport), call_scenario->transactions[checkTxn - 1].name, hash(msg), msg);
                                    return true;
                                }
                            }
                        }
                    } else {
                        /*
                         * we received a non mandatory msg for an old transaction (this could be due to a retransmit.
                         * If this response is for an INVITE transaction, retransmit the ACK to quench retransmits.
                         */
                        if ( (reply_code) &&
                                (0 == strncmp (responsecseqmethod, "INVITE", strlen(responsecseqmethod)) ) &&
                                (call_scenario->messages[search_index+1]->M_type == MSG_TYPE_SEND) &&
                                (call_scenario->messages[search_index+1]->send_scheme->isAck()) ) {
                            sendBuffer(createSendingMessage(call_scenario->messages[search_index+1]->send_scheme, search_index + 1));
                            return true;
                        }
                    }
                }
            }
        }
    }

    /* If it is still not found, process an unexpected message */
    if(!found) {
        if (call_scenario->unexpected_jump >= 0) {
            bool recursive = false;
            if (call_scenario->retaddr >= 0) {
                if (M_callVariableTable->getVar(call_scenario->retaddr)->getDouble() != 0) {
                    /* We are already in a jump! */
                    recursive = true;
                } else {
                    M_callVariableTable->getVar(call_scenario->retaddr)->setDouble(msg_index);
                }
            }
            if (!recursive) {
                if (call_scenario->pausedaddr >= 0) {
                    M_callVariableTable->getVar(call_scenario->pausedaddr)->setDouble(paused_until);
                }
                msg_index = call_scenario->unexpected_jump;
                queue_up(msg);
                paused_until = 0;
                return run();
            } else {
                if (!process_unexpected(msg)) {
                    return false; // Call aborted by unexpected message handling
                }
            }
        } else {
            T_AutoMode L_case;
            if ((L_case = checkAutomaticResponseMode(request)) == 0) {
                if (!process_unexpected(msg)) {
                    return false; // Call aborted by unexpected message handling
                }
            } else {
                // call aborted by automatic response mode if needed
                return automaticResponseMode(L_case, msg);
            }
        }
    }

    int test = (!found) ? -1 : call_scenario->messages[search_index]->test;
    /* test==0: No branching"
     * test==-1 branching without testing"
     * test>0   branching with testing
     */

    /* Simulate loss of messages */
    if(lost(search_index)) {
        TRACE_MSG("%s message lost (recv).",
                  TRANSPORT_TO_STRING(transport));
        callDebug("%s message lost (recv) (hash %lu).\n",
                  TRANSPORT_TO_STRING(transport), hash(msg));
        if(comp_state) {
            comp_free(&comp_state);
        }
        call_scenario->messages[search_index] -> nb_lost++;
        return true;
    }

    /* If we are part of a transaction, mark this as the final response. */
    if (int checkTxn = call_scenario->messages[search_index]->response_txn) {
        transactions[checkTxn - 1].txnResp = hash(msg);
    }


    /* Handle counters and RTDs for this message. */
    do_bookkeeping(call_scenario->messages[search_index]);

    /* Increment the recv counter */
    call_scenario->messages[search_index] -> nb_recv++;

    // Action treatment
    if (found) {
        //WARNING("---EXECUTE_ACTION_ON_MSG---%s---", msg);

        actionResult = executeAction(msg, call_scenario->messages[search_index]);

        if(actionResult != call::E_AR_NO_ERROR) {
            // Store last action result if it is an error
            // and go on with the scenario
            call::last_action_result = actionResult;
            if (actionResult == E_AR_STOP_CALL) {
                return rejectCall();
            } else if (actionResult == E_AR_CONNECT_FAILED) {
                terminate(CStat::E_FAILED_TCP_CONNECT);
                return false;
            }
        }
    }

    if (*request) { // update [cseq] with received CSeq
        unsigned long int rcseq = get_cseq_value(msg);
        if (rcseq > cseq) cseq = rcseq;
    }

    /* This is an ACK/PRACK or a response, and its index is greater than the
     * current active retransmission message, so we stop the retrans timer.
     * True also for CANCEL and BYE that we also want to answer to */
    if(((reply_code) ||
            ((!strcmp(request, "ACK")) ||
             (!strcmp(request, "CANCEL")) || (!strcmp(request, "BYE")) ||
             (!strcmp(request, "PRACK"))))  &&
            (search_index > last_send_index)) {
        /*
         * We should stop any retransmission timers on receipt of a provisional response only for INVITE
         * transactions. Non INVITE transactions continue to retransmit at T2 until a final response is
         * received
         */
        if ( (0 == reply_code) || // means this is a request.
                (200 <= reply_code) ||  // final response
                ((0 != reply_code) && (0 == strncmp (responsecseqmethod, "INVITE", strlen(responsecseqmethod)))) ) { // prov for INVITE
            next_retrans = 0;
        } else {
            /*
             * We are here due to a provisional response for non INVITE. Update our next retransmit.
             */
            next_retrans = clock_tick + global_t2;
            nb_last_delay = global_t2;

        }
    }

    /* This is a response with 200 so set the flag indicating that an
     * ACK is pending (used to prevent from release a call with CANCEL
     * when an ACK+BYE should be sent instead)                         */
    if (reply_code == 200) {
        ack_is_pending = true;
    }

    /* store the route set only once. TODO: does not support target refreshes!! */
    if (call_scenario->messages[search_index]->bShouldRecordRoutes &&
            dialog_route_set == nullptr) {
        realloc_ptr = (char*)realloc(next_req_url, MAX_HEADER_LEN);
        if (realloc_ptr) {
            next_req_url = realloc_ptr;
            /* Ensure next_req_url has an empty value in case contact is missing */
            next_req_url[0] = '\0';
        } else {
            free(next_req_url);
            ERROR("Out of memory!");
            return false;
        }

        /* cache the route set and the contact */
        char rr[MAX_HEADER_LEN], contact[MAX_HEADER_LEN];
        rr[0] = contact[0] = '\0';
        /* yuck, get_header_content returns a static buffer :( */
        strncat(rr, get_header_content(msg, "Record-Route:"), MAX_HEADER_LEN - 1);
        strncat(contact, get_header_content(msg, "Contact:"), MAX_HEADER_LEN - 1);
        computeRouteSetAndRemoteTargetUri(rr, contact, !reply_code);
        // WARNING("next_req_url is [%s]", next_req_url);
    }

    /* store the authentication info */
    if ((call_scenario->messages[search_index] -> bShouldAuthenticate) &&
            (reply_code == 401 || reply_code == 407)) {

        /* is a challenge */
        char auth[MAX_HEADER_LEN];
        memset(auth, 0, sizeof(auth));
        strncpy(auth, get_header_content(msg, (char*)"Proxy-Authenticate:"), sizeof(auth) - 1);
        if (auth[0] == 0) {
            strncpy(auth, get_header_content(msg, (char*)"WWW-Authenticate:"), sizeof(auth) - 1);
        }
        if (auth[0] == 0) {
            ERROR("Couldn't find 'Proxy-Authenticate' or 'WWW-Authenticate' in 401 or 407!");
        }

        realloc_ptr = (char *) realloc(dialog_authentication, strlen(auth) + 2);
        if (realloc_ptr) {
            dialog_authentication = realloc_ptr;
        } else {
            free(dialog_authentication);
            ERROR("Out of memory!");
            return false;
        }


        sprintf(dialog_authentication, "%s", auth);

        /* Store the code of the challenge for building the proper header */
        dialog_challenge_type = reply_code;

        next_nonce_count = 1;
    }

    /* If we are not advancing state, we should quite before we change this stuff. */
    if (!call_scenario->messages[search_index]->advance_state) {
        return true;
    }

    /* Store last received message information for all messages so that we can
     * correctly identify retransmissions, and use its body for inclusion
     * in our messages. */
    last_recv_index = search_index;
    last_recv_hash = cookie;
    callDebug("Set Last Recv Hash: %lu (recv index %d)\n", last_recv_hash, last_recv_index);
    realloc_ptr = (char *) realloc(last_recv_msg, strlen(msg) + 1);
    if (realloc_ptr) {
        last_recv_msg = realloc_ptr;
    } else {
        free(last_recv_msg);
        ERROR("Out of memory!");
        return false;
    }


    strcpy(last_recv_msg, msg);

    /* If this was a mandatory message, or if there is an explicit next label set
     * we must update our state machine.  */
    if (!call_scenario->messages[search_index]->optional ||
            (call_scenario->messages[search_index]->next &&
             (test == -1 || M_callVariableTable->getVar(test)->isSet()))) {
        /* If we are paused, then we need to wake up so that we properly go through the state machine. */
        paused_until = 0;
        msg_index = search_index;
        return next();
    } else {
        unsigned int timeout = wake();
        unsigned int candidate;

        if (call_scenario->messages[search_index]->next && M_callVariableTable->getVar(test)->isSet()) {
            WARNING("Last message generates an error and will not be used for next sends (for last_ variables):\n%s\n", msg);
        }

        /* We are just waiting for a message to be received, if any of the
         * potential messages have a timeout we set it as our timeout. We
         * start from the next message and go until any non-receives. */
        for(search_index++; search_index < (int)call_scenario->messages.size(); search_index++) {
            if(call_scenario->messages[search_index] -> M_type != MSG_TYPE_RECV) {
                break;
            }
            candidate = call_scenario->messages[search_index] -> timeout;
            if (candidate == 0) {
                if (defl_recv_timeout == 0) {
                    continue;
                }
                candidate = defl_recv_timeout;
            }
            if (!timeout || (clock_tick + candidate < timeout)) {
                timeout = clock_tick + candidate;
            }
        }

        setPaused();
    }
    return true;
}

double call::get_rhs(CAction *currentAction)
{
    if (currentAction->getVarInId()) {
        return M_callVariableTable->getVar(currentAction->getVarInId())->getDouble();
    } else {
        return currentAction->getDoubleValue();
    }
}

call::T_ActionResult call::executeAction(const char* msg, message* curmsg)
{
    CActions*  actions;
    CAction*   currentAction;
    int rc = 0;

    actions = curmsg->M_actions;
    // looking for action to do on this message
    if (actions == nullptr) {
        return(call::E_AR_NO_ERROR);
    }

    for (int i = 0; i < actions->getActionSize(); i++) {
        currentAction = actions->getAction(i);
        if(currentAction == nullptr) {
            continue;
        }

        if(currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_REGEXP) {
            char msgPart[MAX_SUB_MESSAGE_LENGTH];

            /* Where to look. */
            const char* haystack = nullptr;

            if(currentAction->getLookingPlace() == CAction::E_LP_HDR) {
                extractSubMessage (msg,
                                   currentAction->getLookingChar(),
                                   msgPart,
                                   currentAction->getCaseIndep(),
                                   currentAction->getOccurrence(),
                                   currentAction->getHeadersOnly());
                if(currentAction->getCheckIt() == true && (strlen(msgPart) == 0)) {
                    // the sub message is not found and the checking action say it
                    // MUST match --> Call will be marked as failed but will go on
                    WARNING("Failed regexp match: header %s not found in message\n%s\n", currentAction->getLookingChar(), msg);
                    return(call::E_AR_HDR_NOT_FOUND);
                }
                haystack = msgPart;
            } else if(currentAction->getLookingPlace() == CAction::E_LP_BODY) {
                haystack = strstr(msg, "\r\n\r\n");
                if (!haystack) {
                    if (currentAction->getCheckIt() == true) {
                        WARNING("Failed regexp match: body not found in message\n%s\n", msg);
                        return(call::E_AR_HDR_NOT_FOUND);
                    }
                    msgPart[0] = '\0';
                    haystack = msgPart;
                }
                haystack += strlen("\r\n\r\n");
            } else if(currentAction->getLookingPlace() == CAction::E_LP_MSG) {
                haystack = msg;
            } else if(currentAction->getLookingPlace() == CAction::E_LP_VAR) {
                /* Get the input variable. */
                haystack = M_callVariableTable->getVar(currentAction->getVarInId())->getString();
                if (!haystack) {
                    if (currentAction->getCheckIt() == true) {
                        WARNING("Failed regexp match: variable $%d not set", currentAction->getVarInId());
                        return(call::E_AR_HDR_NOT_FOUND);
                    }
                }
            } else {
                ERROR("Invalid looking place: %d", currentAction->getLookingPlace());
            }
            bool did_match = (currentAction->executeRegExp(haystack, M_callVariableTable) > 0);

            if (!did_match && currentAction->getCheckIt()) {
                // the message doesn't match and the checkit action say it MUST match
                // Allow easier regexp debugging
                WARNING("Failed regexp match: looking in '%s', with regexp '%s'",
                        haystack, currentAction->getRegularExpression());
                return(call::E_AR_REGEXP_DOESNT_MATCH);
            } else if (did_match && currentAction->getCheckItInverse()) {
                // The inverse of the above
                WARNING("Regexp matched but should not: looking in '%s', with regexp '%s'",
                        haystack, currentAction->getRegularExpression());
                return(call::E_AR_REGEXP_SHOULDNT_MATCH);
            }
        } else if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_VALUE) {
            double operand = get_rhs(currentAction);
            M_callVariableTable->getVar(currentAction->getVarId())->setDouble(operand);
        } else if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_INDEX) {
            M_callVariableTable->getVar(currentAction->getVarId())->setDouble(msg_index);
        } else if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_GETTIMEOFDAY) {
            struct timeval tv;
            gettimeofday(&tv, nullptr);
            M_callVariableTable->getVar(currentAction->getVarId())->setDouble((double)tv.tv_sec);
            M_callVariableTable->getVar(currentAction->getSubVarId(0))->setDouble((double)tv.tv_usec);
        } else if (currentAction->getActionType() == CAction::E_AT_LOOKUP) {
            /* Create strings from the sending messages. */
            char *file = strdup(createSendingMessage(currentAction->getMessage(0)));
            char *key = strdup(createSendingMessage(currentAction->getMessage(1)));

            if (inFiles.find(file) == inFiles.end()) {
                ERROR("Invalid injection file for insert: %s", file);
            }

            double value = inFiles[file]->lookup(key);

            M_callVariableTable->getVar(currentAction->getVarId())->setDouble(value);
            free(file);
            free(key);
        } else if (currentAction->getActionType() == CAction::E_AT_INSERT) {
            /* Create strings from the sending messages. */
            char *file = strdup(createSendingMessage(currentAction->getMessage(0)));
            char *value = strdup(createSendingMessage(currentAction->getMessage(1)));

            if (inFiles.find(file) == inFiles.end()) {
                ERROR("Invalid injection file for insert: %s", file);
            }

            inFiles[file]->insert(value);

            free(file);
            free(value);
        } else if (currentAction->getActionType() == CAction::E_AT_REPLACE) {
            /* Create strings from the sending messages. */
            char *file = strdup(createSendingMessage(currentAction->getMessage(0)));
            char *line = strdup(createSendingMessage(currentAction->getMessage(1)));
            char *value = strdup(createSendingMessage(currentAction->getMessage(2)));

            if (inFiles.find(file) == inFiles.end()) {
                ERROR("Invalid injection file for replace: %s", file);
            }

            char *endptr;
            int lineNum = (int)strtod(line, &endptr);
            if (*endptr) {
                ERROR("Invalid line number for replace: %s", line);
            }

            inFiles[file]->replace(lineNum, value);

            free(file);
            free(line);
            free(value);
        } else if (currentAction->getActionType() == CAction::E_AT_CLOSE_CON) {
            if (call_socket) {
                call_socket->close();
                call_socket = nullptr;
            }
        } else if (currentAction->getActionType() == CAction::E_AT_SET_DEST) {
            /* Change the destination for this call. */
            char *str_host = strdup(createSendingMessage(currentAction->getMessage(0)));
            char *str_port = strdup(createSendingMessage(currentAction->getMessage(1)));
            char *str_protocol = strdup(createSendingMessage(currentAction->getMessage(2)));

            char *endptr;
            int port = (int)strtod(str_port, &endptr);
            if (*endptr) {
                ERROR("Invalid port for setdest: %s", str_port);
            }

            int protocol = 0;
            if (!strcmp(str_protocol, "udp") || !strcmp(str_protocol, "UDP")) {
                protocol = T_UDP;
            } else if (!strcmp(str_protocol, "tcp") || !strcmp(str_protocol, "TCP")) {
                protocol = T_TCP;
            } else if (!strcmp(str_protocol, "tls") || !strcmp(str_protocol, "TLS")) {
                protocol = T_TLS;
            } else if (!strcmp(str_protocol, "sctp") || !strcmp(str_protocol, "SCTP")) {
                protocol = T_SCTP;
            } else {
                ERROR("Unknown transport for setdest: '%s'", str_protocol);
            }

            if (!call_socket && ((protocol == T_TCP && transport == T_TCP) ||
                                 (protocol == T_SCTP && transport == T_SCTP))) {
                bool existing;
                if ((associate_socket(SIPpSocket::new_sipp_call_socket(use_ipv6, transport, &existing))) == nullptr) {
                    switch (protocol) {
                    case T_SCTP:
                        ERROR_NO("Unable to get a SCTP socket");
                        break;
                    default:
                        ERROR_NO("Unable to get a TCP socket");
                    }
                }

                if (!existing) {
                    sipp_customize_socket(call_socket);
                }
            }

            if (!call_socket) {
                ERROR("Unable to get a socket");
            }

            if (protocol != call_socket->ss_transport) {
                ERROR("Can not switch protocols during setdest.");
            }

            if (protocol == T_UDP) {
                /* Nothing to do. */
            } else if (protocol == T_TLS) {
                ERROR("Changing destinations is not supported for TLS.");
            } else if (protocol == T_TCP || protocol == T_SCTP) {
                if (!multisocket) {
                    ERROR("Changing destinations for TCP or SCTP requires multisocket mode.");
                }
                if (call_socket->ss_count > 1) {
                    ERROR("Can not change destinations for a TCP/SCTP socket that has more than one user.");
                }
            }

            if (gai_getsockaddr(&call_peer, str_host, port,
                                AI_PASSIVE, AF_UNSPEC) != 0) {
                ERROR("Unknown host '%s' for setdest", str_host);
            }
            memcpy(&call_socket->ss_dest, &call_peer, sizeof(call_peer));

            free(str_host);
            free(str_port);
            free(str_protocol);

            if (protocol == T_TCP || protocol == T_SCTP) {
                close(call_socket->ss_fd);
                call_socket->ss_fd = -1;
                call_socket->ss_changed_dest = true;
                if (call_socket->reconnect()) {
                    if (reconnect_allowed()) {
                        if(errno == EINVAL) {
                            /* This occurs sometime on HPUX but is not a true INVAL */
                            WARNING("Unable to connect a TCP/SCTP/TLS socket, remote peer error");
                        } else {
                            WARNING("Unable to connect a TCP/SCTP/TLS socket");
                        }
                        /* This connection failed.  We must be in multisocket mode, because
                         * otherwise we would already have a call_socket.  This call can not
                         * succeed, but does not affect any of our other calls. We do decrement
                         * the reconnection counter however. */
                        if (reset_number != -1) {
                            reset_number--;
                        }

                        return E_AR_CONNECT_FAILED;
                    } else {
                        if(errno == EINVAL) {
                            /* This occurs sometime on HPUX but is not a true INVAL */
                            ERROR("Unable to connect a TCP/SCTP/TLS socket, remote peer error");
                        } else {
                            ERROR_NO("Unable to connect a TCP/SCTP/TLS socket");
                        }
                    }
                }
            }
        } else if (currentAction->getActionType() == CAction::E_AT_VERIFY_AUTH) {
            bool result;
            const char* lf;
            const char* end;

            lf = strchr(msg, '\n');
            end = strchr(msg, ' ');

            if (!lf || !end) {
                result = false;
            } else if (lf < end) {
                result = false;
            } else {
                char *auth = get_header(msg, "Authorization:", true);
                auth = strdup(auth); // make a copy to avoid later get_header function call(clear its content)
                char *method = (char *)malloc(end - msg + 1);
                strncpy(method, msg, end - msg);
                method[end - msg] = '\0';

                /* Generate the username to verify it against. */
                char *tmp = createSendingMessage(currentAction->getMessage(0));
                char *username = strdup(tmp);
                /* Generate the password to verify it against. */
                tmp= createSendingMessage(currentAction->getMessage(1));
                char *password = strdup(tmp);
                /* Need the body for length and auth-int calculation */
                const char *body;
                const char *auth_body = nullptr;
                body = strstr(msg, "\r\n\r\n");
                if (body) {
                    auth_body = body;
                    auth_body += strlen("\r\n\r\n");
                } else {
                    auth_body = "";
                }

                result = verifyAuthHeader(username, password, method, auth, auth_body);

                free(username);
                free(password);
                free(method);
                free(auth);
            }

            M_callVariableTable->getVar(currentAction->getVarId())->setBool(result);
        } else if (currentAction->getActionType() == CAction::E_AT_JUMP) {
            double operand = get_rhs(currentAction);
            if (msg_index == ((int)operand)) {
                ERROR("Jump statement at index %d jumps to itself and causes an infinite loop", msg_index);
            }
            msg_index = (int)operand - 1;
            /* -1 is allowed to go to the first label, but watch out
             * when using msg_index. */
            if (msg_index < -1 || msg_index >= (int)call_scenario->messages.size()) {
                ERROR("Jump statement out of range (not 0 <= %d <= %zu)",
                      msg_index + 1, call_scenario->messages.size());
            }
        } else if (currentAction->getActionType() == CAction::E_AT_PAUSE_RESTORE) {
            double operand = get_rhs(currentAction);
            paused_until = (int)operand;
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_ADD) {
            double value = M_callVariableTable->getVar(currentAction->getVarId())->getDouble();
            double operand = get_rhs(currentAction);
            M_callVariableTable->getVar(currentAction->getVarId())->setDouble(value + operand);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_SUBTRACT) {
            double value = M_callVariableTable->getVar(currentAction->getVarId())->getDouble();
            double operand = get_rhs(currentAction);
            M_callVariableTable->getVar(currentAction->getVarId())->setDouble(value - operand);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_MULTIPLY) {
            double value = M_callVariableTable->getVar(currentAction->getVarId())->getDouble();
            double operand = get_rhs(currentAction);
            M_callVariableTable->getVar(currentAction->getVarId())->setDouble(value * operand);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_DIVIDE) {
            double value = M_callVariableTable->getVar(currentAction->getVarId())->getDouble();
            double operand = get_rhs(currentAction);
            if (operand == 0) {
                WARNING("Action failure: Can not divide by zero ($%d/$%d)!\n", currentAction->getVarId(), currentAction->getVarInId());
            } else {
                M_callVariableTable->getVar(currentAction->getVarId())->setDouble(value / operand);
            }
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_TEST) {
            bool value = currentAction->compare(M_callVariableTable);
            if ((currentAction->getCheckIt() && !value) ||
                (currentAction->getCheckItInverse() && value)
            ) {
                double lhs = M_callVariableTable->getVar(currentAction->getVarInId())->getDouble();
                double rhs = currentAction->getVarIn2Id() ?
                    M_callVariableTable->getVar(currentAction->getVarIn2Id())->getDouble() :
                    currentAction->getDoubleValue();
                char *lhsName = call_scenario->allocVars->getName(currentAction->getVarInId());
                const char *rhsName = "";
                if (currentAction->getVarIn2Id()) {
                    rhsName = call_scenario->allocVars->getName(currentAction->getVarIn2Id());
                }
                const char *_inverse = currentAction->getCheckIt() ? "" : "_inverse";
                call::T_ActionResult result = currentAction->getCheckIt() ? call::E_AR_TEST_DOESNT_MATCH : call::E_AR_TEST_SHOULDNT_MATCH;

                WARNING("test \"%s:%f %s %s:%f\" with check_it%s failed",
                    lhsName,
                    lhs,
                    currentAction->comparatorToString(currentAction->getComparator()),
                    rhsName,
                    rhs,
                    _inverse
                );
                return(result);
            }
            // "assign_to" is optional when "check_it" or "check_it_inverse" set
            if (currentAction->getVarId() ||
                (!currentAction->getCheckIt() && !currentAction->getCheckItInverse())
            ) {
                M_callVariableTable->getVar(currentAction->getVarId())->setBool(value);
            }
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_STRCMP) {
            char *lhs = M_callVariableTable->getVar(currentAction->getVarInId())->getString();
            char *rhs = currentAction->getVarIn2Id() ?
                M_callVariableTable->getVar(currentAction->getVarIn2Id())->getString() :
                currentAction->getStringValue();
            int value = strcmp(lhs, rhs);
            if ((currentAction->getCheckIt() && value) ||
                (currentAction->getCheckItInverse() && !value)
            ) {
                char *lhsName = call_scenario->allocVars->getName(currentAction->getVarInId());
                const char *rhsName = "";
                if (currentAction->getVarIn2Id()) {
                    rhsName = call_scenario->allocVars->getName(currentAction->getVarIn2Id());
                }
                const char *_inverse = currentAction->getCheckIt() ? "" : "_inverse";
                call::T_ActionResult result = currentAction->getCheckIt() ? call::E_AR_STRCMP_DOESNT_MATCH : call::E_AR_STRCMP_SHOULDNT_MATCH;

                WARNING("strcmp %s:\"%s\" and %s:\"%s\" with check_it%s returned %d",
                    lhsName,
                    lhs,
                    rhsName,
                    rhs,
                    _inverse,
                    value
                );
                return(result);
            }
            // "assign_to" is optional when "check_it" or "check_it_inverse" set
            if (currentAction->getVarId() ||
                (!currentAction->getCheckIt() && !currentAction->getCheckItInverse())
            ) {
                M_callVariableTable->getVar(currentAction->getVarId())->setDouble((double)value);
            }
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_TRIM) {
            CCallVariable *var = M_callVariableTable->getVar(currentAction->getVarId());
            char *in = var->getString();
            char *p = in;
            while (isspace(*p)) {
                p++;
            }
            char *q = strdup(p);
            var->setString(q);
            int l = strlen(q);
            for (int i = l - 1; (i >= 0) && isspace(q[i]); i--) {
                q[i] = '\0';
            }
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_URLDECODE) {
            CCallVariable *var = M_callVariableTable->getVar(currentAction->getVarId());
            std::string input = var->getString();
            std::string output = url_decode(input);
            char *char_output = strdup(output.c_str());
            var->setString(char_output);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_URLENCODE) {
            CCallVariable *var = M_callVariableTable->getVar(currentAction->getVarId());
            std::string input = var->getString();
            std::string output = url_encode(input);
            char *char_output = strdup(output.c_str());
            var->setString(char_output);
        } else if (currentAction->getActionType() == CAction::E_AT_VAR_TO_DOUBLE) {
            double value;

            if (M_callVariableTable->getVar(currentAction->getVarInId())->toDouble(&value)) {
                M_callVariableTable->getVar(currentAction->getVarId())->setDouble(value);
            } else {
                WARNING("Invalid double conversion from $%d to $%d", currentAction->getVarInId(), currentAction->getVarId());
            }
        } else if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_SAMPLE) {
            double value = currentAction->getDistribution()->sample();
            M_callVariableTable->getVar(currentAction->getVarId())->setDouble(value);
        } else if (currentAction->getActionType() == CAction::E_AT_ASSIGN_FROM_STRING) {
            char* x = createSendingMessage(currentAction->getMessage());
            char *str = strdup(x);
            if (!str) {
                ERROR("Out of memory duplicating string for assignment!");
            }
            M_callVariableTable->getVar(currentAction->getVarId())->setString(str);
        } else if (currentAction->getActionType() == CAction::E_AT_LOG_TO_FILE) {
            char* x = createSendingMessage(currentAction->getMessage());
            LOG_MSG("%s\n", x);
        } else if (currentAction->getActionType() == CAction::E_AT_LOG_WARNING) {
            char* x = createSendingMessage(currentAction->getMessage());
            WARNING("%s", x);
        } else if (currentAction->getActionType() == CAction::E_AT_LOG_ERROR) {
            char* x = createSendingMessage(currentAction->getMessage());
            ERROR("%s", x);
        } else if (currentAction->getActionType() == CAction::E_AT_EXECUTE_CMD) {
            char* x = createSendingMessage(currentAction->getMessage());
            // TRACE_MSG("Trying to execute [%s]", x);
            pid_t l_pid;
            switch(l_pid = fork()) {
            case -1:
                // error when forking !
                ERROR_NO("Forking error main");
                break;

            case 0:
                // first child process - execute the command
                if((l_pid = fork()) < 0) {
                    ERROR_NO("Forking error child");
                } else {
                    if( l_pid == 0) {
                        int ret;
                        ret = system(x); // second child runs
                        if(ret == -1) {
                            WARNING("system call error for %s", x);
                        }
                    }
                    exit(EXIT_OTHER);
                }
                break;
            default:
                // parent process continue
                // reap first child immediately
                pid_t ret;
                while ((ret=waitpid(l_pid, nullptr, 0)) != l_pid) {
                    if (ret != -1) {
                        ERROR("waitpid returns %1ld for child %1ld", (long) ret, (long) l_pid);
                    }
                }
                break;
            }
        } else if (currentAction->getActionType() == CAction::E_AT_EXEC_INTCMD) {
            switch (currentAction->getIntCmd()) {
            case CAction::E_INTCMD_STOP_ALL:
                if (!quitting) {
                    quitting = 1;
                }
                break;
            case CAction::E_INTCMD_STOP_NOW:
                sipp_exit(EXIT_TEST_RES_INTERNAL, 0, 0);
                break;
            case CAction::E_INTCMD_STOPCALL:
            default:
                return(call::E_AR_STOP_CALL);
                break;
            }
#ifdef PCAPPLAY
        } else if ((currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_AUDIO) ||
                   (currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_IMAGE) ||
                   (currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_VIDEO) ||
                   (currentAction->getActionType() == CAction::E_AT_PLAY_DTMF)) {
            play_args_t* play_args = 0;
            if ((currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_AUDIO) ||
                (currentAction->getActionType() == CAction::E_AT_PLAY_DTMF)) {
                play_args = &(this->play_args_a);
            } else if (currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_IMAGE) {
                play_args = &(this->play_args_i);
            } else if (currentAction->getActionType() == CAction::E_AT_PLAY_PCAP_VIDEO) {
                play_args = &(this->play_args_v);
            } else {
                ERROR("Can't find pcap data to play");
            }

            // existing media thread could be using play_args, so we have to kill it before modifying parameters
            if (media_thread != 0) {
                // If a media_thread is already active, kill it before starting a new one
                pthread_cancel(media_thread);
                pthread_join(media_thread, nullptr);
                media_thread = 0;
            }

            if (currentAction->getActionType() == CAction::E_AT_PLAY_DTMF) {
                char* digits = createSendingMessage(currentAction->getMessage());
                play_args->pcap = (pcap_pkts *) malloc(sizeof(pcap_pkts));
                play_args->last_seq_no += parse_dtmf_play_args(digits, play_args->pcap, play_args->last_seq_no);
                play_args->free_pcap_when_done = 1;
            } else {
                play_args->pcap = currentAction->getPcapPkts();
                play_args->free_pcap_when_done = 0;
            }

            /* port number is set in [auto_]media_port interpolation */
            if (media_ip_is_ipv6) {
                struct sockaddr_in6* from = (struct sockaddr_in6*) &(play_args->from);
                from->sin6_family = AF_INET6;
                inet_pton(AF_INET6, media_ip, &(from->sin6_addr));
            } else {
                struct sockaddr_in* from = (struct sockaddr_in*) &(play_args->from);
                from->sin_family = AF_INET;
                from->sin_addr.s_addr = inet_addr(media_ip);
            }
            /* Create a thread to send RTP or UDPTL packets */
            pthread_attr_t attr;
            pthread_attr_init(&attr);
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN  16384
#endif
            int ret = pthread_create(&media_thread, &attr, send_wrapper, play_args);
            if (ret) {
                ERROR("Can't create thread to send RTP packets");
            }
            pthread_attr_destroy(&attr);
#endif
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_ECHO) {
            rtp_echo_state = (currentAction->getDoubleValue() != 0);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_PAUSE) {
            rtpstream_pause(&rtpstream_callinfo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RESUME) {
            rtpstream_resume(&rtpstream_callinfo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_PLAY) {
            const char *fileName = createSendingMessage(currentAction->getMessage());
            currentAction->setRTPStreamActInfo(fileName);
            rtpstream_play(&rtpstream_callinfo, currentAction->getRTPStreamActInfo());
            // Obtain ID of parent thread used for the related RTP task
            call_scenario->addRtpTaskThreadID(rtpstream_callinfo.threadID);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_PAUSEAPATTERN) {
            rtpstream_pauseapattern(&rtpstream_callinfo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RESUMEAPATTERN) {
            rtpstream_resumeapattern(&rtpstream_callinfo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_PLAYAPATTERN) {
            const char *fileName = createSendingMessage(currentAction->getMessage());
            currentAction->setRTPStreamActInfo(fileName);
#ifdef USE_TLS
            //
            // TX/RX-UAC-AUDIO SRTP context (a)(b) -- SRTP PAYLOAD SIZE + DERIVE SESSION ENCRYPTION/SALTING/AUTHENTICATION KEYS + SELECT ENCRYPTION KEY + RESET CIPHER STATE
            // WE ASSUME THE SAME CODEC PAYLOAD SIZE WILL BE USED IN BOTH DIRECTIONS
            //
            if (sendMode == MODE_CLIENT)
            {
                rtpstream_actinfo_t* actinfo = currentAction->getRTPStreamActInfo();
                logSrtpInfo("call::executeAction():  (a) TX-UAC-AUDIO SRTP context - CLIENT setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _txUACAudio.setSrtpPayloadSize(actinfo->bytes_per_packet);
                logSrtpInfo("call::executeAction():  (b) RX-UAC-AUDIO SRTP context - CLIENT setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _rxUACAudio.setSrtpPayloadSize(actinfo->bytes_per_packet);

                logSrtpInfo("call::executeAction():  (a) TX-UAC-AUDIO SRTP context - CLIENT deriving session encryption/salting/authentication keys\n");
                _txUACAudio.deriveSessionEncryptionKey();
                _txUACAudio.deriveSessionSaltingKey();
                _txUACAudio.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction():  (a) TX-UAC-AUDIO SRTP context - CLIENT selecting encryption key\n");
                _txUACAudio.selectEncryptionKey();
                logSrtpInfo("call::executeAction():  (a) TX-UAC-AUDIO SRTP context - CLIENT resetting cipher state\n");
                _txUACAudio.resetCipherState();
                logSrtpInfo("call::executeAction():  (b) RX-UAC-AUDIO SRTP context - CLIENT deriving session encryption/salting/authentication keys\n");
                _rxUACAudio.deriveSessionEncryptionKey();
                _rxUACAudio.deriveSessionSaltingKey();
                _rxUACAudio.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction():  (b) RX-UAC-AUDIO SRTP context - CLIENT selecting decryption key\n");
                _rxUACAudio.selectDecryptionKey();
                logSrtpInfo("call::executeAction():  (b) RX-UAC-AUDIO SRTP context - CLIENT resetting cipher state\n");
                _rxUACAudio.resetCipherState();
                //logSrtpInfo("call::executeAction():  ******** (a) TX-UAC-AUDIO SRTP context dump ********\n");
                //logSrtpInfo("%s", _txUACAudio.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction():  ****************************************************\n");
                //logSrtpInfo("call::executeAction():  ******** (b) RX-UAC-AUDIO SRTP context dump ********\n");
                //logSrtpInfo("%s", _rxUACAudio.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction():  ****************************************************\n");
            }

            logSrtpInfo("call::executeAction():  rtpstream_playapattern\n");
#endif // USE_TLS
            rtpstream_playapattern(&rtpstream_callinfo,currentAction->getRTPStreamActInfo(), _txUACAudio, _rxUACAudio);
            // Obtain ID of parent thread used for the related RTP task
            call_scenario->addRtpTaskThreadID(rtpstream_callinfo.threadID);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_PAUSEVPATTERN) {
            rtpstream_pausevpattern(&rtpstream_callinfo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RESUMEVPATTERN) {
            rtpstream_resumevpattern(&rtpstream_callinfo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_PLAYVPATTERN) {
            const char *fileName = createSendingMessage(currentAction->getMessage());
            currentAction->setRTPStreamActInfo(fileName);
#ifdef USE_TLS
            //
            // TX/RX-UAC-VIDEO SRTP context (a)(b) -- SRTP PAYLOAD SIZE + DERIVE SESSION ENCRYPTION/SALTING/AUTHENTICATION KEYS + SELECT ENCRYPTION KEY + RESET CIPHER STATE
            // WE ASSUME THE SAME CODEC PAYLOAD SIZE WILL BE USED IN BOTH DIRECTIONS
            //
            if (sendMode == MODE_CLIENT)
            {
                rtpstream_actinfo_t* actinfo = currentAction->getRTPStreamActInfo();
                logSrtpInfo("call::executeAction():  (a) TX-UAC-VIDEO SRTP context - CLIENT setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _txUACVideo.setSrtpPayloadSize(actinfo->bytes_per_packet);
                logSrtpInfo("call::executeAction():  (b) RX-UAC-VIDEO SRTP context - CLIENT setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _rxUACVideo.setSrtpPayloadSize(actinfo->bytes_per_packet);

                logSrtpInfo("call::executeAction():  (a) TX-UAC-VIDEO SRTP context - CLIENT deriving session encryption/salting/authentication keys\n");
                _txUACVideo.deriveSessionEncryptionKey();
                _txUACVideo.deriveSessionSaltingKey();
                _txUACVideo.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction():  (a) TX-UAC-VIDEO SRTP context - CLIENT selecting encryption key\n");
                _txUACVideo.selectEncryptionKey();
                logSrtpInfo("call::executeAction():  (a) TX-UAC-VIDEO SRTP context - CLIENT resetting cipher state\n");
                _txUACVideo.resetCipherState();
                logSrtpInfo("call::executeAction():  (b) RX-UAC-VIDEO SRTP context - CLIENT deriving session encryption/salting/authentication keys\n");
                _rxUACVideo.deriveSessionEncryptionKey();
                _rxUACVideo.deriveSessionSaltingKey();
                _rxUACVideo.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction():  (b) RX-UAC-VIDEO SRTP context - CLIENT selecting decryption key\n");
                _rxUACVideo.selectDecryptionKey();
                logSrtpInfo("call::executeAction():  (b) RX-UAC-VIDEO SRTP context - CLIENT resetting cipher state\n");
                _rxUACVideo.resetCipherState();
                //logSrtpInfo("call::executeAction():  ******** (a) TX-UAC-VIDEO SRTP context dump ********\n");
                //logSrtpInfo("%s", _txUACVideo.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction():  ****************************************************\n");
                //logSrtpInfo("call::executeAction():  ******** (b) RX-UAC-VIDEO SRTP context dump ********\n");
                //logSrtpInfo("%s", _rxUACVideo.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction():  ****************************************************\n");
            }

            logSrtpInfo("call::executeAction():  rtpstream_playvpattern\n");
#endif // USE_TLS
            rtpstream_playvpattern(&rtpstream_callinfo,currentAction->getRTPStreamActInfo(), _txUACVideo, _rxUACVideo);
            // Obtain ID of parent thread used for the related RTP task
            call_scenario->addRtpTaskThreadID(rtpstream_callinfo.threadID);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RTPECHO_STARTAUDIO) {
#ifdef USE_TLS
            if (sendMode == MODE_SERVER)
            {
                //
                // RX-UAS-AUDIO SRTP context (c) -- SSRC/IPADDRESS/PORT
                //
                CryptoContextID rxUASA;
                rxUASA.ssrc = rtpstream_callinfo.taskinfo->audio_ssrc_id;
                rxUASA.address = media_ip;
                rxUASA.port = rtpstream_callinfo.local_audioport;
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (c) RX-UAS-AUDIO SRTP context - ssrc:0x%08x address:%s port:%d\n", rxUASA.ssrc, rxUASA.address.c_str(), rxUASA.port);
                _rxUASAudio.setID(rxUASA);

                //
                // RX/TX-UAS-AUDIO SRTP context (c)(d) -- SRTP PAYLOAD SIZE + DERIVE SESSION ENCRYPTION/SALTING/AUTHENTICATION KEYS + SELECT ENCRYPTION KEY + RESET CIPHER STATE
                // WE ASSUME THE SAME CODEC PAYLOAD SIZE WILL BE USED IN BOTH DIRECTIONS
                //
                rtpecho_actinfo_t* actinfo = currentAction->getRTPEchoActInfo();
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _rxUASAudio.setSrtpPayloadSize(actinfo->bytes_per_packet);
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _txUASAudio.setSrtpPayloadSize(actinfo->bytes_per_packet);

                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _rxUASAudio.deriveSessionEncryptionKey();
                _rxUASAudio.deriveSessionSaltingKey();
                _rxUASAudio.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER selecting decryption key\n");
                _rxUASAudio.selectDecryptionKey();
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER resetting cipher state\n");
                _rxUASAudio.resetCipherState();
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _txUASAudio.deriveSessionEncryptionKey();
                _txUASAudio.deriveSessionSaltingKey();
                _txUASAudio.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER selecting encryption key\n");
                _txUASAudio.selectEncryptionKey();
                logSrtpInfo("call::executeAction() [STARTAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER resetting cipher state\n");
                _txUASAudio.resetCipherState();
                //logSrtpInfo("call::executeAction() [STARTAUDIO]:  ******** (c) RX-UAS-AUDIO SRTP context dump ********\n");
                //logSrtpInfo("%s", _rxUASAudio.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [STARTAUDIO]:  ****************************************************\n");
                //logSrtpInfo("call::executeAction() [STARTAUDIO]:  ******** (d) TX-UAS-AUDIO SRTP context dump ********\n");
                //logSrtpInfo("%s", _txUASAudio.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [STARTAUDIO]:  ****************************************************\n");
            }

            logSrtpInfo("call::executeAction() [STARTAUDIO]:  rtpstream_rtpecho_startaudio\n");
#endif // USE_TLS
            rtpstream_rtpecho_startaudio(&rtpstream_callinfo, _rxUASAudio, _txUASAudio);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RTPECHO_UPDATEAUDIO) {
#ifdef USE_TLS
            if (sendMode == MODE_SERVER)
            {
                //
                // RX-UAS-AUDIO SRTP context (c) -- SSRC/IPADDRESS/PORT
                //
                CryptoContextID rxUASA;
                rxUASA.ssrc = rtpstream_callinfo.taskinfo->audio_ssrc_id;
                rxUASA.address = media_ip;
                rxUASA.port = rtpstream_callinfo.local_audioport;
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (c) RX-UAS-AUDIO SRTP context - ssrc:0x%08x address:%s port:%d\n", rxUASA.ssrc, rxUASA.address.c_str(), rxUASA.port);
                _rxUASAudio.setID(rxUASA);

                //
                // RX/TX-UAS-AUDIO SRTP context (c)(d) -- SRTP PAYLOAD SIZE + DERIVE SESSION ENCRYPTION/SALTING/AUTHENTICATION KEYS + SELECT ENCRYPTION KEY + RESET CIPHER STATE
                // WE ASSUME THE SAME CODEC PAYLOAD SIZE WILL BE USED IN BOTH DIRECTIONS
                //
                rtpecho_actinfo_t* actinfo = currentAction->getRTPEchoActInfo();
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _rxUASAudio.setSrtpPayloadSize(actinfo->bytes_per_packet);
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _txUASAudio.setSrtpPayloadSize(actinfo->bytes_per_packet);

                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _rxUASAudio.deriveSessionEncryptionKey();
                _rxUASAudio.deriveSessionSaltingKey();
                _rxUASAudio.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER selecting decryption key\n");
                _rxUASAudio.selectDecryptionKey();
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (c) RX-UAS-AUDIO SRTP context - SERVER resetting cipher state\n");
                _rxUASAudio.resetCipherState();
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _txUASAudio.deriveSessionEncryptionKey();
                _txUASAudio.deriveSessionSaltingKey();
                _txUASAudio.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER selecting encryption key\n");
                _txUASAudio.selectEncryptionKey();
                logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  (d) TX-UAS-AUDIO SRTP context - SERVER resetting cipher state\n");
                _txUASAudio.resetCipherState();
                //logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  ******** (c) RX-UAS-AUDIO SRTP context dump ********\n");
                //logSrtpInfo("%s", _rxUASAudio.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  ****************************************************\n");
                //logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  ******** (d) TX-UAS-AUDIO SRTP context dump ********\n");
                //logSrtpInfo("%s", _txUASAudio.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  ****************************************************\n");
            }

            logSrtpInfo("call::executeAction() [UPDATEAUDIO]:  rtpstream_rtpecho_updateaudio\n");
#endif // USE_TLS
            rtpstream_rtpecho_updateaudio(&rtpstream_callinfo, _rxUASAudio, _txUASAudio);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RTPECHO_STOPAUDIO) {
#ifdef USE_TLS
            logSrtpInfo("call::executeAction() [STOPAUDIO]:  rtpstream_rtpecho_stopaudio\n");
#endif // USE_TLS
            rc = rtpstream_rtpecho_stopaudio(&rtpstream_callinfo);
            if (rc < 0)
            {
#ifdef USE_TLS
                logSrtpInfo("call::executeAction() [STOPAUDIO]:  rtpstream_rtpecho_stopaudio() rc==%d\n", rc);
#endif // USE_TLS
                return call::E_AR_RTPECHO_ERROR;
            }
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RTPECHO_STARTVIDEO) {
#ifdef USE_TLS
            if (sendMode == MODE_SERVER)
            {
                //
                // RX-UAS-VIDEO SRTP context (c) -- SSRC/IPADDRESS/PORT
                //
                CryptoContextID rxUASV;
                rxUASV.ssrc = rtpstream_callinfo.taskinfo->video_ssrc_id;
                rxUASV.address = media_ip;
                rxUASV.port = rtpstream_callinfo.local_videoport;
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (c) RX-UAS-VIDEO SRTP context - ssrc:0x%08x address:%s port:%d\n", rxUASV.ssrc, rxUASV.address.c_str(), rxUASV.port);
                _rxUASVideo.setID(rxUASV);

                //
                // RX/TX-UAS-VIDEO SRTP context (c)(d) -- SRTP PAYLOAD SIZE + DERIVE SESSION ENCRYPTION/SALTING/AUTHENTICATION KEYS + SELECT ENCRYPTION KEY + RESET CIPHER STATE
                // WE ASSUME THE SAME CODEC PAYLOAD SIZE WILL BE USED IN BOTH DIRECTIONS
                //
                rtpecho_actinfo_t* actinfo = currentAction->getRTPEchoActInfo();
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _rxUASVideo.setSrtpPayloadSize(actinfo->bytes_per_packet);
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _txUASVideo.setSrtpPayloadSize(actinfo->bytes_per_packet);

                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _rxUASVideo.deriveSessionEncryptionKey();
                _rxUASVideo.deriveSessionSaltingKey();
                _rxUASVideo.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER selecting decryption key\n");
                _rxUASVideo.selectDecryptionKey();
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER resetting cipher state\n");
                _rxUASVideo.resetCipherState();
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _txUASVideo.deriveSessionEncryptionKey();
                _txUASVideo.deriveSessionSaltingKey();
                _txUASVideo.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER selecting encryption key\n");
                _txUASVideo.selectEncryptionKey();
                logSrtpInfo("call::executeAction() [STARTVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER resetting cipher state\n");
                _txUASVideo.resetCipherState();
                //logSrtpInfo("call::executeAction() [STARTVIDEO]:  ******** (c) RX-UAS-VIDEO SRTP context dump ********\n");
                //logSrtpInfo("%s", _rxUASVideo.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [STARTVIDEO]:  ****************************************************\n");
                //logSrtpInfo("call::executeAction() [STARTVIDEO]:  ******** (d) TX-UAS-VIDEO SRTP context dump ********\n");
                //logSrtpInfo("%s", _txUASVideo.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [STARTVIDEO]:  ****************************************************\n");
            }

            logSrtpInfo("call::executeAction() [STARTVIDEO]:  rtpstream_rtpecho_startvideo\n");
#endif // USE_TLS
            rtpstream_rtpecho_startvideo(&rtpstream_callinfo, _rxUASVideo, _txUASVideo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RTPECHO_UPDATEVIDEO) {
#ifdef USE_TLS
            if (sendMode == MODE_SERVER)
            {
                //
                // RX-UAS-VIDEO SRTP context (c) -- SSRC/IPADDRESS/PORT
                //
                CryptoContextID rxUASV;
                rxUASV.ssrc = rtpstream_callinfo.taskinfo->video_ssrc_id;
                rxUASV.address = media_ip;
                rxUASV.port = rtpstream_callinfo.local_videoport;
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (c) RX-UAS-VIDEO SRTP context - ssrc:0x%08x address:%s port:%d\n", rxUASV.ssrc, rxUASV.address.c_str(), rxUASV.port);
                _rxUASVideo.setID(rxUASV);

                //
                // RX/TX-UAS-VIDEO SRTP context (c)(d) -- SRTP PAYLOAD SIZE + DERIVE SESSION ENCRYPTION/SALTING/AUTHENTICATION KEYS + SELECT ENCRYPTION KEY + RESET CIPHER STATE
                // WE ASSUME THE SAME CODEC PAYLOAD SIZE WILL BE USED IN BOTH DIRECTIONS
                //
                rtpecho_actinfo_t* actinfo = currentAction->getRTPEchoActInfo();
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _rxUASVideo.setSrtpPayloadSize(actinfo->bytes_per_packet);
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER setting SRTP payload size to %d\n", actinfo->bytes_per_packet);
                _txUASVideo.setSrtpPayloadSize(actinfo->bytes_per_packet);

                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _rxUASVideo.deriveSessionEncryptionKey();
                _rxUASVideo.deriveSessionSaltingKey();
                _rxUASVideo.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER selecting decryption key\n");
                _rxUASVideo.selectDecryptionKey();
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (c) RX-UAS-VIDEO SRTP context - SERVER resetting cipher state\n");
                _rxUASVideo.resetCipherState();
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER deriving session encryption/salting/authentication keys\n");
                _txUASVideo.deriveSessionEncryptionKey();
                _txUASVideo.deriveSessionSaltingKey();
                _txUASVideo.deriveSessionAuthenticationKey();
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER selecting encryption key\n");
                _txUASVideo.selectEncryptionKey();
                logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  (d) TX-UAS-VIDEO SRTP context - SERVER resetting cipher state\n");
                _txUASVideo.resetCipherState();
                //logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  ******** (c) RX-UAS-VIDEO SRTP context dump ********\n");
                //logSrtpInfo("%s", _rxUASVideo.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  ****************************************************\n");
                //logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  ******** (d) TX-UAS-VIDEO SRTP context dump ********\n");
                //logSrtpInfo("%s", _txUASVideo.dumpCryptoContext().c_str());
                //logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  ****************************************************\n");
            }

            logSrtpInfo("call::executeAction() [UPDATEVIDEO]:  rtpstream_rtpecho_updatevideo\n");
#endif // USE_TLS
            rtpstream_rtpecho_updatevideo(&rtpstream_callinfo, _rxUASVideo, _txUASVideo);
        } else if (currentAction->getActionType() == CAction::E_AT_RTP_STREAM_RTPECHO_STOPVIDEO) {
#ifdef USE_TLS
            logSrtpInfo("call::executeAction() [STOPVIDEO]:  rtpstream_rtpecho_stopvideo\n");
#endif // USE_TLS
            rc = rtpstream_rtpecho_stopvideo(&rtpstream_callinfo);
            if (rc < 0)
            {
#ifdef USE_TLS
                logSrtpInfo("call::executeAction() [STOPVIDEO]:  rtpstream_rtpecho_stopvideo() rc==%d\n", rc);
#endif // USE_TLS
                return call::E_AR_RTPECHO_ERROR;
            }
        } else {
            ERROR("call::executeAction unknown action");
        }
    } // end for
    return(call::E_AR_NO_ERROR);
}

void call::extractSubMessage(const char* msg, char* matchingString, char* result, bool case_indep, int occurrence, bool headers)
{

    const char *ptr, *ptr1;
    int sizeOf;
    int i = 0;
    int len = strlen(matchingString);
    char mat1 = tolower(*matchingString);
    char mat2 = toupper(*matchingString);

    ptr = msg;
    while (*ptr) {
        if (!case_indep) {
            ptr = strstr(ptr, matchingString);
            if (ptr == nullptr) break;
            if (headers == true && ptr != msg && *(ptr-1) != '\n') {
                ++ptr;
                continue;
            }
        } else {
            if (headers) {
                if (ptr != msg) {
                    ptr = strchr(ptr, '\n');
                    if (ptr == nullptr) break;
                    ++ptr;
                    if (*ptr == 0) break;
                }
            } else {
                ptr1 = strchr(ptr, mat1);
                ptr = strchr(ptr, mat2);
                if (ptr == nullptr) {
                    if (ptr1 == nullptr) break;
                    ptr = ptr1;
                } else {
                    if (ptr1 != nullptr && ptr1 < ptr) ptr = ptr1;
                }
            }
            if (strncasecmp(ptr, matchingString, len) != 0) {
                ++ptr;
                continue;
            }
        }
        // here with ptr pointing to a matching string
        if (occurrence <= 1) break;
        --occurrence;
        ++ptr;
    }

    if(ptr != nullptr && *ptr != 0) {
        strncpy(result, ptr+len, MAX_SUB_MESSAGE_LENGTH);
        sizeOf = strlen(result);
        if(sizeOf >= MAX_SUB_MESSAGE_LENGTH)
            sizeOf = MAX_SUB_MESSAGE_LENGTH-1;
        while((i<sizeOf) && (result[i] != '\n') && (result[i] != '\r'))
            i++;
        result[i] = '\0';
    } else {
        result[0] = '\0';
    }
}

void call::getFieldFromInputFile(const char *fileName, int field, SendingMessage *lineMsg, char*& dest)
{
    if (m_lineNumber == nullptr) {
        ERROR("Automatic calls (created by -aa, -oocsn or -oocsf) cannot use input files!");
    }
    if (inFiles.find(fileName) == inFiles.end()) {
        ERROR("Invalid injection file: %s", fileName);
    }
    int line = (*m_lineNumber)[fileName];
    if (lineMsg) {
        char lineBuffer[20];
        char *endptr;
        createSendingMessage(lineMsg, SM_UNUSED, lineBuffer, sizeof(lineBuffer));
        line = (int) strtod(lineBuffer, &endptr);
        if (*endptr != 0) {
            ERROR("Invalid line number generated: '%s'", lineBuffer);
        }
        if (line > inFiles[fileName]->numLines()) {
            line = -1;
        }
    }
    if (line < 0) {
        return;
    }
    dest += inFiles[fileName]->getField(line, field, dest, SIPP_MAX_MSG_SIZE);
}

call::T_AutoMode call::checkAutomaticResponseMode(char* P_recv)
{
    if (strcmp(P_recv, "BYE")==0) {
        return E_AM_UNEXP_BYE;
    } else if (strcmp(P_recv, "CANCEL") == 0) {
        return E_AM_UNEXP_CANCEL;
    } else if (strcmp(P_recv, "PING") == 0) {
        return E_AM_PING;
    } else if (auto_answer &&
               ((strcmp(P_recv, "INFO") == 0) ||
                (strcmp(P_recv, "NOTIFY") == 0) ||
                (strcmp(P_recv, "OPTIONS") == 0) ||
                (strcmp(P_recv, "UPDATE") == 0))) {
        return E_AM_AA;
    } else {
        return E_AM_DEFAULT;
    }
}

void call::setLastMsg(const char *msg)
{
    realloc_ptr = (char *) realloc(last_recv_msg, strlen(msg) + 1);
    if (realloc_ptr) {
        last_recv_msg = realloc_ptr;
    } else {
        free(last_recv_msg);
        ERROR("Out of memory!");
        return;
    }

    strcpy(last_recv_msg, msg);
}

bool call::automaticResponseMode(T_AutoMode P_case, const char* P_recv)
{

    int res ;
    char * old_last_recv_msg = nullptr;
    bool last_recv_msg_saved = false;

    switch (P_case) {
    case E_AM_UNEXP_BYE: // response for an unexpected BYE
        // usage of last_ keywords
        realloc_ptr = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
        if (realloc_ptr) {
            last_recv_msg = realloc_ptr;
        } else {
            free(last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(last_recv_msg, P_recv);

        // The BYE is unexpected, count it
        call_scenario->messages[msg_index] -> nb_unexp++;
        if (default_behaviors & DEFAULT_BEHAVIOR_ABORTUNEXP) {
            WARNING("Aborting call on an unexpected BYE for call: %s", (id==nullptr)?"none":id);
            if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                sendBuffer(createSendingMessage(get_default_message("200")));
            }

            // if twin socket call => reset the other part here
            if (twinSippSocket && (msg_index > 0)) {
                res = sendCmdBuffer(createSendingMessage(get_default_message("3pcc_abort")));
                if (res) {
                    WARNING("sendCmdBuffer returned %d", res);
                    return false;
                }
            }
            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
            delete this;
        } else {
            WARNING("Continuing call on an unexpected BYE for call: %s", (id==nullptr)?"none":id);
        }
        break ;

    case E_AM_UNEXP_CANCEL: // response for an unexpected cancel
        // usage of last_ keywords
        realloc_ptr = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
        if (realloc_ptr) {
            last_recv_msg = realloc_ptr;
        } else {
            free(last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(last_recv_msg, P_recv);

        // The CANCEL is unexpected, count it
        call_scenario->messages[msg_index] -> nb_unexp++;
        if (default_behaviors & DEFAULT_BEHAVIOR_ABORTUNEXP) {
            WARNING("Aborting call on an unexpected CANCEL for call: %s", (id==nullptr)?"none":id);
            if (default_behaviors & DEFAULT_BEHAVIOR_BYE) {
                sendBuffer(createSendingMessage(get_default_message("200")));
            }

            // if twin socket call => reset the other part here
            if (twinSippSocket && (msg_index > 0)) {
                res = sendCmdBuffer(createSendingMessage(get_default_message("3pcc_abort")));
                if (res) {
                    WARNING("sendCmdBuffer returned %d", res);
                    return false;
                }
            }

            computeStat(CStat::E_CALL_FAILED);
            computeStat(CStat::E_FAILED_UNEXPECTED_MSG);
            delete this;
        } else {
            WARNING("Continuing call on unexpected CANCEL for call: %s", (id==nullptr)?"none":id);
        }
        break ;

    case E_AM_PING: // response for a random ping
        // usage of last_ keywords
        realloc_ptr = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
        if (realloc_ptr) {
            last_recv_msg = realloc_ptr;
        } else {
            free(last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(last_recv_msg, P_recv);

        if (default_behaviors & DEFAULT_BEHAVIOR_PINGREPLY) {
            WARNING("Automatic response mode for an unexpected PING for call: %s", (id==nullptr)?"none":id);
            sendBuffer(createSendingMessage(get_default_message("200")));
            // Note: the call ends here but it is not marked as bad. PING is a
            //       normal message.
            // if twin socket call => reset the other part here
            if (twinSippSocket && (msg_index > 0)) {
                res = sendCmdBuffer(createSendingMessage(get_default_message("3pcc_abort")));
                if (res) {
                    WARNING("sendCmdBuffer returned %d", res);
                    return false;
                }
            }

            CStat::globalStat(CStat::E_AUTO_ANSWERED);
            delete this;
        } else {
            WARNING("Do not answer on an unexpected PING for call: %s", (id==nullptr)?"none":id);
        }
        break ;

    case E_AM_AA: // response for a random INFO, NOTIFY, OPTIONS or UPDATE
        // store previous last msg if msg is INFO, NOTIFY, OPTIONS or UPDATE
        // restore last_recv_msg to previous one
        // after sending ok
        old_last_recv_msg = nullptr;
        if (last_recv_msg != nullptr) {
            last_recv_msg_saved = true;
            old_last_recv_msg = (char *) malloc(strlen(last_recv_msg)+1);
            strcpy(old_last_recv_msg, last_recv_msg);
        }
        // usage of last_ keywords
        realloc_ptr = (char *) realloc(last_recv_msg, strlen(P_recv) + 1);
        if (realloc_ptr) {
            last_recv_msg = realloc_ptr;
        } else {
            free(last_recv_msg);
            free(old_last_recv_msg);
            ERROR("Out of memory!");
            return false;
        }


        strcpy(last_recv_msg, P_recv);

        TRACE_CALLDEBUG("Automatic response mode for an unexpected INFO, NOTIFY, OPTIONS or UPDATE for call: %s",
                        (id == nullptr) ? "none" : id);
        sendBuffer(createSendingMessage(get_default_message("200")));

        // restore previous last msg
        if (last_recv_msg_saved == true) {
            realloc_ptr = (char *) realloc(last_recv_msg, strlen(old_last_recv_msg) + 1);
            if (realloc_ptr) {
                last_recv_msg = realloc_ptr;
            } else {
                free(last_recv_msg);
                ERROR("Out of memory!");
                return false;
            }


            strcpy(last_recv_msg, old_last_recv_msg);
            if (old_last_recv_msg != nullptr) {
                free(old_last_recv_msg);
                old_last_recv_msg = nullptr;
            }
        }
        CStat::globalStat(CStat::E_AUTO_ANSWERED);
        return true;
        break;

    default:
        ERROR("Internal error for automaticResponseMode - mode %d is not implemented!", P_case);
        break ;
    }

    return false;
}

#ifdef USE_TLS
int call::logSrtpInfo(const char *fmt, ...)
{
    va_list args;

    if (_srtpctxdebugfile != nullptr)
    {
        va_start(args, fmt);
        vfprintf(_srtpctxdebugfile, fmt, args);
        va_end(args);
    }

    return 0;
}
#endif // USE_TLS

void call::setSessionState(SessionState state)
{
    _sessionStateOld = _sessionStateCurrent;
    _sessionStateCurrent = state;
}

SessionState call::getSessionStateCurrent()
{
    return _sessionStateCurrent;
}

SessionState call::getSessionStateOld()
{
    return _sessionStateOld;
}

#ifdef PCAPPLAY
void *send_wrapper(void *arg)
{
    play_args_t *s = (play_args_t *) arg;
    //struct sched_param param;
    //int ret;
    //param.sched_priority = 10;
    //ret = pthread_setschedparam(pthread_self(), SCHED_RR, &param);
    //if(ret)
    //  ERROR("Can't set RTP play thread realtime parameters");
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, nullptr);
    send_packets(s);
    pthread_exit(nullptr);
    return nullptr;
}
#endif

#ifdef GTEST
#include "gtest/gtest.h"
#include "gtest/gtest.h"

class mockcall : public call {
public:
    mockcall(bool is_ipv6) : listener("//testing", true), call("///testing", is_ipv6, 0, nullptr) {}

    /* Helpers to poke at protected internals */
    void parse_media_addr(std::string const& msg) { get_remote_media_addr(msg); }

#ifdef PCAPPLAY
    bool has_media() { return hasMediaInformation; }

    template<typename T>
    T get_audio_addr() {
        T sa;
        std::memcpy(&sa, &play_args_a.to, sizeof(T));
        return sa;
    }
#endif
};

bool operator==(const struct sockaddr_in& a, const struct sockaddr_in &b) {
    return a.sin_family == b.sin_family
        && a.sin_port == b.sin_port
        && std::memcmp(&a.sin_addr, &b.sin_addr, sizeof(in_addr)) == 0;
}

bool operator==(const struct sockaddr_in6& a, const struct sockaddr_in6 &b) {
    return a.sin6_family == b.sin6_family
        && a.sin6_port == b.sin6_port
        && std::memcmp(&a.sin6_addr, &b.sin6_addr, sizeof(in_addr)) == 0;
}

const std::string test_sdp_v4 = "v=0\r\n"
                                "o=user1 53655765 2353687637 IN IP4 127.0.0.1\r\n"
                                "s=-\r\n"
                                "c=IN IP4 127.0.0.1\r\n"
                                "t=0 0\r\n"
                                "m=audio 12345 RTP/AVP 0\r\n"
                                "a=rtpmap:0 PCMU/8000\r\n";

const std::string test_sdp_v6 = "v=0\r\n"
                                "o=user1 53655765 2353687637 IN IP6 ::1\r\n"
                                "s=-\r\n"
                                "c=IN IP6 ::1\r\n"
                                "t=0 0\r\n"
                                "m=audio 12345 RTP/AVP 0\r\n"
                                "a=rtpmap:0 PCMU/8000\r\n";

TEST(sdp, parse_valid_sdp_msg) {
    ASSERT_EQ(find_in_sdp("c=IN IP4 ", test_sdp_v4), "127.0.0.1");
    ASSERT_EQ(find_in_sdp("c=IN IP6 ", test_sdp_v6), "::1");
    ASSERT_EQ(find_in_sdp("m=audio ", test_sdp_v4), "12345");
    ASSERT_EQ(find_in_sdp("m=audio ", test_sdp_v6), "12345");
}

TEST(sdp, parse_invalid_sdp_msg) {
    ASSERT_EQ(find_in_sdp("c=IN IP4 ", test_sdp_v6), "");
    ASSERT_EQ(find_in_sdp("c=IN IP6 ", test_sdp_v4), "");
    ASSERT_EQ(find_in_sdp("m=video ", test_sdp_v6), "");
    ASSERT_EQ(find_in_sdp("m=video ", test_sdp_v4), "");
}

#ifdef PCAPPLAY
TEST(sdp, good_remote_media_addr_v4) {
    media_ip_is_ipv6 = false;

    struct sockaddr_in reference;
    reference.sin_family = AF_INET;
    reference.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &reference.sin_addr);

    mockcall call(false);
    call.parse_media_addr(test_sdp_v4);
    ASSERT_EQ(call.has_media(), true);
    ASSERT_EQ(reference, call.get_audio_addr<struct sockaddr_in>());
}

TEST(sdp, good_remote_media_addr_v6) {
    media_ip_is_ipv6 = true;

    struct sockaddr_in6 reference;
    reference.sin6_family = AF_INET6;
    reference.sin6_port = htons(12345);
    inet_pton(AF_INET6, "::1", &reference.sin6_addr);

    mockcall call(true);
    call.parse_media_addr(test_sdp_v6);
    ASSERT_EQ(call.has_media(), true);
    ASSERT_EQ(reference, call.get_audio_addr<struct sockaddr_in6>());
}
#endif /* PCAP_PLAY */
#endif
