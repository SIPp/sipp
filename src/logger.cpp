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
 *           Marc LAMBERTON
 *           Olivier JACQUES
 *           Herve PELLAN
 *           David MANSUTTI
 *           Francois-Xavier Kowalski
 *           Gerard Lyonnaz
 *           Francois Draperi (for dynamic_id)
 *           From Hewlett Packard Company.
 *           F. Tarek Rogers
 *           Peter Higginson
 *           Vincent Luba
 *           Shriram Natarajan
 *           Guillaume Teissier from FTR&D
 *           Clement Chen
 *           Wolfgang Beck
 *           Charles P Wright from IBM Research
 *           Martin Van Leeuwen
 *           Andy Aicken
 *           Michael Hirschbichler
 */

#include <curses.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "logger.hpp"

unsigned long total_errors = 0;
/* screen_last_error is on stderr already: print_errors() leaves it out. */
static bool last_error_shown = false;

void log_off(struct logfile_info* lfi)
{
    if (lfi->fptr) {
        fflush(lfi->fptr);
        fclose(lfi->fptr);
        lfi->fptr = nullptr;
        lfi->overwrite = false;
    }
}

void print_count_file(FILE* f, int header)
{
    char temp_str[256];

    if (!main_scenario || (!header && !main_scenario->stats)) {
        return;
    }

    if (header) {
        fprintf(f, "CurrentTime%sElapsedTime%s", stat_delimiter,
                stat_delimiter);
    } else {
        struct timeval currentTime, startTime;
        GET_TIME(&currentTime);
        main_scenario->stats->getStartTime(&startTime);
        unsigned long globalElapsedTime =
            CStat::computeDiffTimeInMs(&currentTime, &startTime);
        fprintf(f, "%s%s", CStat::formatTime(&currentTime, rfc3339), stat_delimiter);
        fprintf(f, "%s%s", CStat::msToHHMMSSus(globalElapsedTime).c_str(),
                stat_delimiter);
    }

    for (unsigned int index = 0; index < main_scenario->messages.size();
         index++) {
        message* curmsg = main_scenario->messages[index];
        if (curmsg->hide) {
            continue;
        }

        if (SendingMessage* src = curmsg->send_scheme) {
            if (header) {
                if (src->isResponse()) {
                    sprintf(temp_str, "%u_%d_", index, src->getCode());
                } else {
                    sprintf(temp_str, "%u_%s_", index, src->getMethod());
                }

                fprintf(f, "%sSent%s", temp_str, stat_delimiter);
                fprintf(f, "%sRetrans%s", temp_str, stat_delimiter);
                if (curmsg->retrans_delay) {
                    fprintf(f, "%sTimeout%s", temp_str, stat_delimiter);
                }
                if (lose_packets) {
                    fprintf(f, "%sLost%s", temp_str, stat_delimiter);
                }
            } else {
                fprintf(f, "%lu%s", curmsg->nb_sent, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_sent_retrans, stat_delimiter);
                if (curmsg->retrans_delay) {
                    fprintf(f, "%lu%s", curmsg->nb_timeout, stat_delimiter);
                }
                if (lose_packets) {
                    fprintf(f, "%lu%s", curmsg->nb_lost, stat_delimiter);
                }
            }
        } else if (curmsg->recv_response) {
            if (header) {
                sprintf(temp_str, "%u_%s_", index, curmsg->recv_response->c_str());

                fprintf(f, "%sRecv%s", temp_str, stat_delimiter);
                fprintf(f, "%sRetrans%s", temp_str, stat_delimiter);
                fprintf(f, "%sTimeout%s", temp_str, stat_delimiter);
                fprintf(f, "%sUnexp%s", temp_str, stat_delimiter);
                if (lose_packets) {
                    fprintf(f, "%sLost%s", temp_str, stat_delimiter);
                }
            } else {
                fprintf(f, "%lu%s", curmsg->nb_recv, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_recv_retrans, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_timeout, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_unexp, stat_delimiter);
                if (lose_packets) {
                    fprintf(f, "%lu%s", curmsg->nb_lost, stat_delimiter);
                }
            }
        } else if (curmsg->recv_request) {
            if (header) {
                sprintf(temp_str, "%u_%s_", index, curmsg->recv_request->c_str());

                fprintf(f, "%sRecv%s", temp_str, stat_delimiter);
                fprintf(f, "%sRetrans%s", temp_str, stat_delimiter);
                fprintf(f, "%sTimeout%s", temp_str, stat_delimiter);
                fprintf(f, "%sUnexp%s", temp_str, stat_delimiter);
                if (lose_packets) {
                    fprintf(f, "%sLost%s", temp_str, stat_delimiter);
                }
            } else {
                fprintf(f, "%lu%s", curmsg->nb_recv, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_recv_retrans, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_timeout, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_unexp, stat_delimiter);
                if (lose_packets) {
                    fprintf(f, "%lu%s", curmsg->nb_lost, stat_delimiter);
                }
            }
        } else if (curmsg->pause_distribution || curmsg->pause_variable != -1) {

            if (header) {
                sprintf(temp_str, "%u_Pause_", index);
                fprintf(f, "%sSessions%s", temp_str, stat_delimiter);
                fprintf(f, "%sUnexp%s", temp_str, stat_delimiter);
            } else {
                fprintf(f, "%d%s", curmsg->sessions, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_unexp, stat_delimiter);
            }
        } else if (curmsg->M_type == MSG_TYPE_NOP) {
            /* No output. */
        } else if (curmsg->M_type == MSG_TYPE_RECVCMD) {
            if (header) {
                sprintf(temp_str, "%u_RecvCmd", index);
                fprintf(f, "%s%s", temp_str, stat_delimiter);
                fprintf(f, "%s_Timeout%s", temp_str, stat_delimiter);
            } else {
                fprintf(f, "%lu%s", curmsg->M_nbCmdRecv, stat_delimiter);
                fprintf(f, "%lu%s", curmsg->nb_timeout, stat_delimiter);
            }
        } else if (curmsg->M_type == MSG_TYPE_SENDCMD) {
            if (header) {
                sprintf(temp_str, "%u_SendCmd", index);
                fprintf(f, "%s%s", temp_str, stat_delimiter);
            } else {
                fprintf(f, "%lu%s", curmsg->M_nbCmdSent, stat_delimiter);
            }
        } else {
            ERROR("Unknown count file message type:");
        }
    }
    fprintf(f, "\n");
    fflush(f);
}

void print_error_codes_file(FILE* f)
{
    if (!main_scenario || !main_scenario->stats) {
        return;
    }

    // Print time and elapsed time to file
    struct timeval currentTime, startTime;
    GET_TIME(&currentTime);
    main_scenario->stats->getStartTime(&startTime);
    unsigned long globalElapsedTime =
        CStat::computeDiffTimeInMs(&currentTime, &startTime);
    fprintf(f, "%s%s", CStat::formatTime(&currentTime, rfc3339), stat_delimiter);
    fprintf(f, "%s%s", CStat::msToHHMMSSus(globalElapsedTime).c_str(), stat_delimiter);

    // Print comma-separated list of all error codes seen since the last time
    // this function was called
    for (; main_scenario->stats->error_codes.size() != 0;) {
        fprintf(
            f, "%d,",
            main_scenario->stats
                ->error_codes[main_scenario->stats->error_codes.size() - 1]);
        main_scenario->stats->error_codes.pop_back();
    }

    fprintf(f, "\n");
    fflush(f);
}

/* Function to dump all available screens in a file */
void print_screens(void)
{
    int oldScreen = currentScreenToDisplay;
    int oldRepartition = currentRepartitionToDisplay;

    currentScreenToDisplay = DISPLAY_SCENARIO_SCREEN;
    sp->print_to_file(screen_lfi.fptr);

    currentScreenToDisplay = DISPLAY_STAT_SCREEN;
    sp->print_to_file(screen_lfi.fptr);

    currentScreenToDisplay = DISPLAY_REPARTITION_SCREEN;
    sp->print_to_file(screen_lfi.fptr);

    currentScreenToDisplay = DISPLAY_SECONDARY_REPARTITION_SCREEN;
    for (currentRepartitionToDisplay = 2;
         currentRepartitionToDisplay <= display_scenario->stats->nRtds();
         currentRepartitionToDisplay++) {
        sp->print_to_file(screen_lfi.fptr);
    }
    fflush(screen_lfi.fptr);

    currentScreenToDisplay = oldScreen;
    currentRepartitionToDisplay = oldRepartition;
}

/* <scenario>_<pid>_<name>, the start of the name of a log file. */
static std::string log_file_stem(const struct logfile_info *lfi)
{
    /* An error while the scenario loads comes before it has a name. */
    const char *scenario = scenario_file ? scenario_file : "sipp";
    return std::string(scenario) + "_" + std::to_string(getpid()) + "_" + lfi->name;
}

/* The name a log file is rotated away to. */
static std::string rotated_file_name(const struct logfile_info *lfi, const struct logfile_id &id)
{
    std::string name = log_file_stem(lfi) + "_" + std::to_string((unsigned long)id.start);
    if (id.n) {
        name += "." + std::to_string(id.n);
    }
    return name + ".log";
}

static void rotatef(struct logfile_info *lfi)
{
    if (!lfi->fixedname) {
        lfi->file_name = log_file_stem(lfi) + ".log";
    }

    if (ringbuffer_files > 0) {
        if (!lfi->ftimes) {
            lfi->ftimes = (struct logfile_id*)calloc(ringbuffer_files,
                                                     sizeof(struct logfile_id));
        }
        /* We need to rotate away an existing file. */
        if (lfi->nfiles == ringbuffer_files) {
            unlink(rotated_file_name(lfi, (lfi->ftimes)[0]).c_str());
            lfi->nfiles--;
            memmove(lfi->ftimes, &((lfi->ftimes)[1]),
                    sizeof(struct logfile_id) * (lfi->nfiles));
        }
        if (lfi->starttime) {
            (lfi->ftimes)[lfi->nfiles].start = lfi->starttime;
            (lfi->ftimes)[lfi->nfiles].n = 0;
            /* If we have the same time, then we need to append an identifier.
             */
            if (lfi->nfiles && ((lfi->ftimes)[lfi->nfiles].start ==
                                (lfi->ftimes)[lfi->nfiles - 1].start)) {
                (lfi->ftimes)[lfi->nfiles].n =
                    (lfi->ftimes)[lfi->nfiles - 1].n + 1;
            }
            std::string rotate_file_name = rotated_file_name(lfi, (lfi->ftimes)[lfi->nfiles]);
            lfi->nfiles++;
            /* None open after a "trace ... off" */
            if (lfi->fptr) {
                fclose(lfi->fptr);
                lfi->fptr = nullptr;
            }
            if (rename(lfi->file_name.c_str(), rotate_file_name.c_str())) {
                /* Not rotated away: add to it rather than truncate it. */
                lfi->nfiles--;
                lfi->overwrite = false;
            }
        }
    }

    /* A file reopened in place: close the old stream, or it leaks, and
     * whatever it still buffers lands in the new file at exit. */
    if (lfi->fptr) {
        fclose(lfi->fptr);
        lfi->fptr = nullptr;
    }

    time(&lfi->starttime);
    if (lfi->overwrite) {
        lfi->fptr = fopen(lfi->file_name.c_str(), "w");
    } else {
        lfi->fptr = fopen(lfi->file_name.c_str(), "a");
        lfi->overwrite = true;
    }
    if (lfi->check && !lfi->fptr) {
        /* We can not use the error functions from this function, as we may be
         * rotating the error log itself! */
        ERROR("Unable to create '%s'", lfi->file_name.c_str());
    }
}

void rotate_screenf() { rotatef(&screen_lfi); }

void rotate_calldebugf() { rotatef(&calldebug_lfi); }

void rotate_messagef() { rotatef(&message_lfi); }

void rotate_shortmessagef() { rotatef(&shortmessage_lfi); }

void rotate_logfile() { rotatef(&log_lfi); }

void rotate_errorf()
{
    rotatef(&error_lfi);
    screen_logfile = error_lfi.file_name;
}

static void close_trace(struct logfile_info *lfi)
{
    if (lfi->fptr) {
        fclose(lfi->fptr);
        lfi->fptr = nullptr;
    }
}

void stop_oversized_traces()
{
    static bool stopped = false;

    // we can receive the signal more than once
    if (!file_size_exceeded || stopped) {
        return;
    }
    stopped = true;

    char L_file_name[MAX_PATH];
    snprintf(L_file_name, MAX_PATH, "%s_%ld_traces_oversized.log", scenario_file, (long)getpid());
    FILE *f = fopen(L_file_name, "w");
    if (!f) {
        ERROR_NO("Unable to open oversized log file");
    }

    struct timeval currentTime;
    GET_TIME(&currentTime);
    fprintf(f,
            "-------------------------------------------- %s\n"
            "Max file size reached - no more logs\n",
            CStat::formatTime(&currentTime, rfc3339));

    fclose(f);
    close_trace(&message_lfi);
    close_trace(&log_lfi);
    dumpInRtt = 0;
    dumpInFile = 0;
    print_all_responses = 0;
    close_trace(&error_lfi);
}

static int _trace(struct logfile_info* lfi, const char* fmt, va_list ap)
{
    int ret = 0;
    /* Not into a file over the size limit */
    stop_oversized_traces();
    if (lfi->fptr) {
        ret = vfprintf(lfi->fptr, fmt, ap);
        fflush(lfi->fptr);

        lfi->count += ret;

        if (max_log_size && lfi->count > max_log_size) {
            fclose(lfi->fptr);
            lfi->fptr = nullptr;
        }

        if (ringbuffer_size && lfi->count > ringbuffer_size) {
            rotatef(lfi);
            lfi->count = 0;
        }
    }
    return ret;
}

int TRACE_MSG(const char* fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = _trace(&message_lfi, fmt, ap);
    va_end(ap);

    return ret;
}

int TRACE_SHORTMSG(const char* fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = _trace(&shortmessage_lfi, fmt, ap);
    va_end(ap);

    return ret;
}

int LOG_MSG(const char* fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = _trace(&log_lfi, fmt, ap);
    va_end(ap);

    return ret;
}

int TRACE_CALLDEBUG(const char* fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = _trace(&calldebug_lfi, fmt, ap);
    va_end(ap);

    return ret;
}

void print_errors() {
    if (total_errors == 0) {
        return;
    }

    if (!last_error_shown) {
        fprintf(stderr, "%s\n", screen_last_error);
    }
    if (total_errors > 1) {
        if (!screen_logfile.empty()) {
            fprintf(stderr, "There were more errors, see '%s' file\n", screen_logfile.c_str());
        } else {
            fprintf(stderr,
                    "There were more errors, enable -trace_err to log them.\n");
        }
    }
    fflush(stderr);
}

static void _advance(char*& c, const int snprintfResult)
{
    if (snprintfResult > 0) {
        c += snprintfResult;
    }
}

static void _screen_error(int fatal, bool use_errno, int error, const char *fmt, va_list ap)
{
    static unsigned long long count = 0;
    struct timeval currentTime;

    CStat::globalStat(fatal ? CStat::E_FATAL_ERRORS : CStat::E_WARNING);

    GET_TIME (&currentTime);

    const std::size_t bufSize = sizeof(screen_last_error) / sizeof(screen_last_error[0]);
    const char* const bufEnd = &screen_last_error[bufSize];
    char* c = screen_last_error;
    _advance(c, snprintf(c, bufEnd - c, "%s: ", CStat::formatTime(&currentTime, rfc3339)));
    if (c < bufEnd) {
        _advance(c, vsnprintf(c, bufEnd - c, fmt, ap));
    }
    if (use_errno && c < bufEnd) {
        _advance(c, snprintf(c, bufEnd - c, ", errno = %d (%s)", error, strerror(error)));
    }
    total_errors++;
    last_error_shown = false;

    if (!error_lfi.fptr && print_all_responses) {
        rotate_errorf();
        if (error_lfi.fptr) {
            fprintf(error_lfi.fptr, "The following events occurred:\n");
            fflush(error_lfi.fptr);
        } else {
            if (c < bufEnd) {
                _advance(c, snprintf(c, bufEnd - c, "Unable to create '%s': %s.\n", screen_logfile.c_str(),
                                     strerror(errno)));
            }
            sipp_exit(EXIT_FATAL_ERROR, 0, 0);
        }
    }

    if (error_lfi.fptr) {
        count += fprintf(error_lfi.fptr, "%s\n", screen_last_error);
        fflush(error_lfi.fptr);
        if (ringbuffer_size && count > ringbuffer_size) {
            rotate_errorf();
            count = 0;
        }
        if (max_log_size && count > max_log_size) {
            print_all_responses = 0;
            if (error_lfi.fptr) {
                fflush(error_lfi.fptr);
                fclose(error_lfi.fptr);
                error_lfi.fptr = nullptr;
                error_lfi.overwrite = false;
            }
        }
    } else if (fatal) {
        fprintf(stderr, "%s\n", screen_last_error);
        fflush(stderr);
        /* Unless the screen, closing, clears it. */
        last_error_shown = !screen_inited;
    }

    if (fatal) {
        if (error == EADDRINUSE) {
            sipp_exit(EXIT_BIND_ERROR, 0, 0);
        } else {
            sipp_exit(EXIT_FATAL_ERROR, 0, 0);
        }
    }
}

extern "C" {
    void ERROR(const char *fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        _screen_error(true, false, 0, fmt, ap);
        va_end(ap);
        exit(1);
    }

    void ERROR_NO(const char *fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        _screen_error(true, true, errno, fmt, ap);
        va_end(ap);
        exit(1);
    }

    void WARNING(const char *fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        _screen_error(false, false, 0, fmt, ap);
        va_end(ap);
    }

    void WARNING_NO(const char *fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        _screen_error(false, true, errno, fmt, ap);
        va_end(ap);
    }
}
