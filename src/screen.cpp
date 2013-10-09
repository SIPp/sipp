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

#include "stat.hpp"
#include "sipp.hpp"

#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <screen.hpp>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef __SUNOS
#include<stdarg.h>
#endif

#include <unistd.h>

extern bool    timeout_exit;

unsigned long screen_errors;
int           screen_inited = 0;
char          screen_exename[255];
extern bool   backgroundMode;

void (*screen_exit_handler)();

/* Clock must be a pointer to struct timeval */
#define GET_TIME(clock)       \
{                             \
  struct timezone tzp;        \
  gettimeofday (clock, &tzp); \
}

void stop_all_traces()
{
    message_lfi.fptr = NULL;
    log_lfi.fptr = NULL;
    if(dumpInRtt) dumpInRtt = 0;
    if(dumpInFile) dumpInFile = 0;
}

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

void freeInFiles()
{
    for (file_map::iterator file_it = inFiles.begin(); file_it != inFiles.end(); file_it++) {
        delete file_it->second;
    }
}

void freeUserVarMap()
{
    for (int_vt_map::iterator vt_it = userVarMap.begin(); vt_it != userVarMap.end(); vt_it++) {
        vt_it->second->putTable();
        userVarMap[vt_it->first] = NULL;
    }
}

void releaseGlobalAllocations()
{
    delete main_scenario;
    delete ooc_scenario;
    delete aa_scenario;
    free_default_messages();
    freeInFiles();
    freeUserVarMap();
    delete globalVariables;
}

void screen_exit(int rc)
{
    unsigned long counter_value_failed=0;
    unsigned long counter_value_success=0;

    /* Some signals may be delivered twice during exit() execution,
     * and we must prevent all this from beeing done twice */

    {
        static int already_exited = 0;
        if(already_exited) {
            return;
        }
        already_exited = 1;
    }

    if( backgroundMode == false )
        endwin();

    if(screen_exit_handler) {
        screen_exit_handler();
    }

    if(screen_errors) {
        fprintf(stderr, "%s", screen_last_error);
        if(screen_errors > 1) {
            if (screen_logfile[0] != (char)0) {
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

    // Get failed calls counter value before releasing objects
    if (display_scenario) {
        counter_value_failed = display_scenario->stats->GetStat (CStat::CPT_C_FailedCall);
        counter_value_success = display_scenario->stats->GetStat (CStat::CPT_C_SuccessfulCall);
    } else {
        rc = EXIT_TEST_FAILED;
    }

    releaseGlobalAllocations();

    if (rc != EXIT_TEST_RES_UNKNOWN) {
        // Exit is not a normal exit. Just use the passed exit code.
        exit(rc);
    } else {
        // Normal exit: we need to determine if the calls were all
        // successful or not.
        // In order to compute the return code, get the counter
        // of failed calls. If there is 0 failed calls, then everything is OK!
        if (counter_value_failed == 0) {

            if ((timeout_exit) && (counter_value_success < 1)) {

                exit (EXIT_TEST_RES_INTERNAL);
            } else {
                exit(EXIT_TEST_OK);
            }
        } else {
            exit(EXIT_TEST_FAILED);
        }
    }
}

/* Exit handler for Curses */

void screen_quit()
{
    screen_exit(EXIT_TEST_RES_UNKNOWN);
}


void manage_oversized_file()
{
    FILE * f;
    char L_file_name [MAX_PATH];
    struct timeval currentTime;
    static int managing = 0;

    if(managing) return;   //we can receive this signal more than once

    managing = 1;

    sprintf (L_file_name, "%s_%d_traces_oversized.log", scenario_file, getpid());
    f = fopen(L_file_name, "w");
    if(!f) ERROR_NO("Unable to open special error file\n");
    GET_TIME (&currentTime);
    fprintf(f,
            "-------------------------------------------- %s\n"
            "Max file size reached - no more logs\n",
            CStat::formatTime(&currentTime));
    fflush(f);
    stop_all_traces();
    print_all_responses = 0;
    error_lfi.fptr = NULL;
}


void screen_clear()
{
    printf("\033[2J");
}

void screen_set_exename(char * exe_name)
{
    strcpy(screen_exename, exe_name);
}

void screen_init(void (*exit_handler)())
{
    struct sigaction action_quit, action_file_size_exceeded;

    screen_inited = 1;
    screen_exit_handler = exit_handler;

    if (backgroundMode == false) {
        /* Initializes curses and signals */
        initscr();
        /* Enhance performances and display */
        noecho();
    }

    /* Map exit handlers to curses reset procedure */
    memset(&action_quit, 0, sizeof(action_quit));
    memset(&action_file_size_exceeded, 0, sizeof(action_file_size_exceeded));
    (*(void **)(&(action_quit.sa_handler)))=(void *)screen_quit;
    (*(void **)(&(action_file_size_exceeded.sa_handler)))=(void *)manage_oversized_file;
    sigaction(SIGTERM, &action_quit, NULL);
    sigaction(SIGINT, &action_quit, NULL);
    sigaction(SIGXFSZ, &action_file_size_exceeded, NULL);   // avoid core dump if the max file size is exceeded

    if (backgroundMode == false) {
        screen_clear();
    }
}

static void _screen_error(int fatal, bool use_errno, int error, const char *fmt, va_list ap)
{
    static unsigned long long count = 0;
    char * c = screen_last_error;
    struct timeval currentTime;

    CStat::globalStat(fatal ? CStat::E_FATAL_ERRORS : CStat::E_WARNING);

    GET_TIME (&currentTime);

    c+= sprintf(c, "%s: ", CStat::formatTime(&currentTime));
    c+= vsprintf(c, fmt, ap);
    if (use_errno) {
        c += sprintf(c, ", errno = %d (%s)", error, strerror(error));
    }
    c+= sprintf(c, ".\n");
    screen_errors++;

    if(screen_inited && !error_lfi.fptr && print_all_responses) {
        rotate_errorf();
        if(!error_lfi.fptr) {
            c += sprintf(c, "%s: Unable to create '%s': %s.\n",
                         screen_exename, screen_logfile, strerror(errno));
            screen_exit(EXIT_FATAL_ERROR);
        } else {
            fprintf(error_lfi.fptr, "%s: The following events occured:\n",
                    screen_exename);
            fflush(error_lfi.fptr);
        }
    }

    if(error_lfi.fptr) {
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
        fprintf(stderr, "%s", screen_last_error);
        fflush(stderr);
    }

    if(fatal) {
        if(!screen_inited) {
            if(error == EADDRINUSE) {
                exit(EXIT_BIND_ERROR);
            } else {
                exit(EXIT_FATAL_ERROR);
            }
        } else {
            if(error == EADDRINUSE) {
                screen_exit(EXIT_BIND_ERROR);
            } else {
                screen_exit(EXIT_FATAL_ERROR);
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
