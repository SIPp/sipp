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
 *           From Hewlett Packard Company.
 */

/****
 * Screen.cpp : Simple curses & logfile encapsulation
 */


#include <stdarg.h>
#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#include "screen.hpp"
#include "sipp.hpp"

/* Export these so others needn't include curses.h */
int key_backspace = KEY_BACKSPACE;
int key_dc = KEY_DC;

unsigned long screen_errors;
int           screen_inited = 0;
char          screen_exename[255];

/* ERR is actually -1, but this prevents us from needing to use curses.h in
 * sipp.cpp. */
int screen_readkey()
{
    int c = getch();
    if (c == ERR) {
        return -1;
    }
    return c;
}

void screen_exit()
{
    if (!screen_inited) {
        return;
    }

    endwin();
}

void screen_show_errors() {
    if (!screen_errors) {
        return;
    }

    fprintf(stderr, "%s\n", screen_last_error);
    if (screen_errors > 1) {
        if (screen_logfile[0] != '\0') {
            fprintf(stderr,
                    "%s: There were more errors, see '%s' file\n",
                    screen_exename, screen_logfile);
        } else {
            fprintf(stderr,
                    "%s: There were more errors, enable -trace_err to log them.\n",
                    screen_exename);
        }
    }
    fflush(stderr);
}

void screen_clear()
{
    printf("\033[2J");
}

void screen_set_exename(const char* exe_name)
{
    strncpy(screen_exename, exe_name, sizeof(screen_exename) - 1);
}

void screen_init()
{
    if (backgroundMode) {
        return;
    }

    screen_inited = 1;

    initscr();
    noecho();
    screen_clear();
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
    screen_errors++;

    if (!error_lfi.fptr && print_all_responses) {
        rotate_errorf();
        if (error_lfi.fptr) {
            fprintf(error_lfi.fptr, "%s: The following events occurred:\n",
                    screen_exename);
            fflush(error_lfi.fptr);
        } else {
            if (screen_inited && c < bufEnd) {
                _advance(c, snprintf(c, bufEnd - c, "%s: Unable to create '%s': %s.\n",
                    screen_exename, screen_logfile, strerror(errno)));
            }
            sipp_exit(EXIT_FATAL_ERROR);
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
        if (!screen_inited) {
            if (error == EADDRINUSE) {
                exit(EXIT_BIND_ERROR);
            } else {
                exit(EXIT_FATAL_ERROR);
            }
        } else {
            if (error == EADDRINUSE) {
                sipp_exit(EXIT_BIND_ERROR);
            } else {
                sipp_exit(EXIT_FATAL_ERROR);
            }
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
        assert(0);
    }

    void ERROR_NO(const char *fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        _screen_error(true, true, errno, fmt, ap);
        va_end(ap);
        assert(0);
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
