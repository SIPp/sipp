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

#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <screen.hpp>


#ifdef __3PCC__
#include <unistd.h>
extern int           twinSippSocket;
extern int           localTwinSippSocket;
#endif // __3PCC__ //

extern bool    timeout_exit;

unsigned long screen_errors;
char          screen_last_error[32768];
char          _screen_err[32768];
FILE        * screen_errorf = 0;
int           screen_inited = 0;
char          screen_logfile[255];
char          screen_exename[255];
extern void   releaseGlobalAllocations();
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
              "%s: There were more errors, see scenarioname_pid_errors.log file\n",
              screen_exename);
      } else {
          fprintf(stderr, 
              "%s: There were more errors, enable -trace_err to log them.\n",
              screen_exename);
      }
    }
    fflush(stderr);
  }

#ifdef __3PCC__
  if(twinSippSocket) {
    close(twinSippSocket);
  }

  if(localTwinSippSocket) {
    close(localTwinSippSocket);
  }
#endif //__3PCC__
 
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
  struct sigaction action_quit;
  
  screen_inited = 1;
  if (logfile_name == NULL) {
    screen_logfile[0] = (char)0;
  } else {
  strcpy(screen_logfile, logfile_name);
  }
  screen_exit_handler = exit_handler;

  /* Initializes curses and signals */
  initscr();
  /* Enhance performances and display */
  noecho();
  
  /* Map exit handlers to curses reset procedure */
  memset(&action_quit, 0, sizeof(action_quit));
  (*(void **)(&(action_quit.sa_handler)))=(void *)screen_quit;
  sigaction(SIGTERM, &action_quit, NULL);
  sigaction(SIGINT, &action_quit, NULL);
  sigaction(SIGKILL, &action_quit, NULL);  

  printf("\033[2J");
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
      c += sprintf(c, "%s: Unable to create '%s'.\n",
                   screen_exename, screen_logfile);
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
