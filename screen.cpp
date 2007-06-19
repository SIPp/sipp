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

#include <unistd.h>

extern bool    timeout_exit;

unsigned long screen_errors;
char          screen_last_error[32768];
char          _screen_err[32768];
FILE        * screen_errorf = 0;
int           screen_inited = 0;
char          screen_logfile[255];
char          screen_exename[255];
extern void   releaseGlobalAllocations();
extern void   stop_all_traces();
extern bool   backgroundMode;

void (*screen_exit_handler)();

/* Clock must be a pointer to struct timeval */
#define GET_TIME(clock)       \
{                             \
  struct timezone tzp;        \
  gettimeofday (clock, &tzp); \
}

int  screen_readkey()
{
  return getch();
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
  counter_value_failed = CStat::instance()->GetStat (CStat::CPT_C_FailedCall);
  counter_value_success = CStat::instance()->GetStat (CStat::CPT_C_SuccessfulCall);

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
           CStat::instance()->formatTime(&currentTime));
  fflush(f);
  stop_all_traces(); 
  screen_logfile[0] = (char)0;
  screen_errorf = 0; 
  CStat::instance()->close();
}


void screen_clear() 
{
  printf("\033[2J");
}

void screen_set_exename(char * exe_name)
{
  strcpy(screen_exename, exe_name);
}

void screen_init(char *logfile_name, void (*exit_handler)())
{
  struct sigaction action_quit, action_file_size_exceeded;
  
  screen_inited = 1;
  if (logfile_name == NULL) {
    screen_logfile[0] = (char)0;
  } else {
    strcpy(screen_logfile, logfile_name);
  }
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
  sigaction(SIGKILL, &action_quit, NULL);  
  sigaction(SIGXFSZ, &action_file_size_exceeded, NULL);   // avoid core dump if the max file size is exceeded

  if (backgroundMode == false) {
    screen_clear();
  }
}

void _screen_error(char *s, int fatal)
{
  FILE * output;
  char * c = screen_last_error;
  struct timeval currentTime;

  GET_TIME (&currentTime);
  
  c+= sprintf(c, "%s: ", CStat::instance()->formatTime(&currentTime));
  c+= sprintf(c, "%s", s);
  c+= sprintf(c, ".\n");
  screen_errors++;

  if(screen_inited && (!screen_errorf) && screen_logfile[0] != (char)0) {
    screen_errorf = fopen(screen_logfile, "w");
    if(!screen_errorf) {
      c += sprintf(c, "%s: Unable to create '%s': %s.\n",
                   screen_exename, screen_logfile, strerror(errno));
      screen_exit(EXIT_FATAL_ERROR);
    } else {
      fprintf(screen_errorf, "%s: The following events occured:\n",
              screen_exename);
      fflush(screen_errorf);
    }
  }

  if(screen_errorf) {
    output = screen_errorf;
    fprintf(output, "%s", screen_last_error);
    fflush(output);
  } else if (fatal) {
    output = stderr;
    fprintf(output, "%s", screen_last_error);
    fflush(output);
  }

  if(fatal) {
    if(!screen_inited) {
      exit(EXIT_FATAL_ERROR);
    } else {
      screen_exit(EXIT_FATAL_ERROR);
    }
  }
}
