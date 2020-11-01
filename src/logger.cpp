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

void log_off(struct logfile_info* lfi)
{
    if (lfi->fptr) {
        fflush(lfi->fptr);
        fclose(lfi->fptr);
        lfi->fptr = NULL;
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
        fprintf(f, "%s%s", CStat::formatTime(&currentTime), stat_delimiter);
        fprintf(f, "%s%s", CStat::msToHHMMSSus(globalElapsedTime),
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
                sprintf(temp_str, "%u_%d_", index, curmsg->recv_response);

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
                sprintf(temp_str, "%u_%s_", index, curmsg->recv_request);

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
        } else if (curmsg->pause_distribution || curmsg->pause_variable) {

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
    fprintf(f, "%s%s", CStat::formatTime(&currentTime), stat_delimiter);
    fprintf(f, "%s%s", CStat::msToHHMMSSus(globalElapsedTime), stat_delimiter);

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

    currentScreenToDisplay = oldScreen;
    currentRepartitionToDisplay = oldRepartition;
}

static void rotatef(struct logfile_info* lfi)
{
    char L_rotate_file_name[MAX_PATH];

    if (!lfi->fixedname) {
        sprintf(lfi->file_name, "%s_%ld_%s.log", scenario_file, (long)getpid(),
                lfi->name);
    }

    if (ringbuffer_files > 0) {
        if (!lfi->ftimes) {
            lfi->ftimes = (struct logfile_id*)calloc(ringbuffer_files,
                                                     sizeof(struct logfile_id));
        }
        /* We need to rotate away an existing file. */
        if (lfi->nfiles == ringbuffer_files) {
            if ((lfi->ftimes)[0].n) {
                sprintf(L_rotate_file_name, "%s_%ld_%s_%lu.%d.log",
                        scenario_file, (long)getpid(), lfi->name,
                        (unsigned long)(lfi->ftimes)[0].start,
                        (lfi->ftimes)[0].n);
            } else {
                sprintf(L_rotate_file_name, "%s_%ld_%s_%lu.log", scenario_file,
                        (long)getpid(), lfi->name,
                        (unsigned long)(lfi->ftimes)[0].start);
            }
            unlink(L_rotate_file_name);
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
            if ((lfi->ftimes)[lfi->nfiles].n) {
                sprintf(L_rotate_file_name, "%s_%ld_%s_%lu.%d.log",
                        scenario_file, (long)getpid(), lfi->name,
                        (unsigned long)(lfi->ftimes)[lfi->nfiles].start,
                        (lfi->ftimes)[lfi->nfiles].n);
            } else {
                sprintf(L_rotate_file_name, "%s_%ld_%s_%lu.log", scenario_file,
                        (long)getpid(), lfi->name,
                        (unsigned long)(lfi->ftimes)[lfi->nfiles].start);
            }
            lfi->nfiles++;
            fflush(lfi->fptr);
            fclose(lfi->fptr);
            lfi->fptr = NULL;
            rename(lfi->file_name, L_rotate_file_name);
        }
    }

    time(&lfi->starttime);
    if (lfi->overwrite) {
        lfi->fptr = fopen(lfi->file_name, "w");
    } else {
        lfi->fptr = fopen(lfi->file_name, "a");
        lfi->overwrite = true;
    }
    if (lfi->check && !lfi->fptr) {
        /* We can not use the error functions from this function, as we may be
         * rotating the error log itself! */
        ERROR("Unable to create '%s'", lfi->file_name);
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
    strcpy(screen_logfile, error_lfi.file_name);
}

static int _trace(struct logfile_info* lfi, const char* fmt, va_list ap)
{
    int ret = 0;
    if (lfi->fptr) {
        ret = vfprintf(lfi->fptr, fmt, ap);
        fflush(lfi->fptr);

        lfi->count += ret;

        if (max_log_size && lfi->count > max_log_size) {
            fclose(lfi->fptr);
            lfi->fptr = NULL;
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

    fprintf(stderr, "%s\n", screen_last_error);
    if (total_errors > 1) {
        if (screen_logfile[0] != '\0') {
            fprintf(stderr,
                    "There were more errors, see '%s' file\n",
                    screen_logfile);
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
    _advance(c, snprintf(c, bufEnd - c, "%s: ", CStat::formatTime(&currentTime)));
    if (c < bufEnd) {
        _advance(c, vsnprintf(c, bufEnd - c, fmt, ap));
    }
    if (use_errno && c < bufEnd) {
        _advance(c, snprintf(c, bufEnd - c, ", errno = %d (%s)", error, strerror(error)));
    }
    total_errors++;

    if (!error_lfi.fptr && print_all_responses) {
        rotate_errorf();
        if (error_lfi.fptr) {
            fprintf(error_lfi.fptr, "The following events occurred:\n");
            fflush(error_lfi.fptr);
        } else {
            if (c < bufEnd) {
                _advance(c, snprintf(c, bufEnd - c, "Unable to create '%s': %s.\n",
                                     screen_logfile, strerror(errno)));
            }
            sipp_exit(EXIT_FATAL_ERROR, 0, 0);
        }
    }

    if (error_lfi.fptr) {
        count += fprintf(error_lfi.fptr, "%s", screen_last_error);
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
                error_lfi.fptr = NULL;
                error_lfi.overwrite = false;
            }
        }
    } else if (fatal) {
        fprintf(stderr, "%s\n", screen_last_error);
        fflush(stderr);
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
