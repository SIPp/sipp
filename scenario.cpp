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
 *           Venkatesh
 *           Lee Ballard
 *           Guillaume TEISSIER from FTR&D
 *           Wolfgang Beck
 *           Marc Van Diest from Belgacom
 *	     Charles P. Wright from IBM Research
 */

#include <stdlib.h>
#include "sipp.hpp"
#ifdef HAVE_GSL
#include <gsl/gsl_rng.h>
#include <gsl/gsl_randist.h>
#include <gsl/gsl_cdf.h>
#endif

/************************ Class Constructor *************************/

message::message()
{
  //ugly memset(this, 0, sizeof(message));
  pause_function = NULL;
  pause_desc = NULL;
  pause_param = 0;
  pause_param2 = 0;
  pause_dparam = 0;
  pause_dparam2 = 0;
  sessions = 0;
  bShouldRecordRoutes = 0;
#ifdef _USE_OPENSSL
  bShouldAuthenticate = 0;
#endif

  send_scheme = NULL;
  retrans_delay = 0;

  recv_response = 0;
  recv_request = NULL;
  optional = 0;
  regexp_match = 0;
  regexp_compile = NULL;

  /* Anyway */
  start_rtd = 0;
  stop_rtd  = 0;
  repeat_rtd = 0;
  lost = -1;
  crlf = 0;
  test = 0;
  chance = 0;/* meaning always */
  next = 0;
  on_timeout = 0;

/* 3pcc extended mode */
  peer_dest = NULL;
  peer_src = NULL;

  /* Statistics */
  nb_sent = 0;
  nb_recv = 0;
  nb_sent_retrans = 0;
  nb_recv_retrans = 0;
  nb_timeout = 0;
  nb_unexp = 0;
  nb_lost = 0;
  counter = 0;

  M_actions = NULL;

  M_type = 0;

#ifdef __3PCC__
  M_sendCmdData = NULL;
  M_nbCmdSent   = 0;
  M_nbCmdRecv   = 0;
#endif

  content_length_flag = ContentLengthNoPresent;
}

message::~message()
{
  if(M_actions != NULL)
    delete(M_actions);
  M_actions = NULL;

  if(send_scheme != NULL)
    free (send_scheme);
  send_scheme = NULL;

  if(recv_request != NULL)
    free (recv_request);
  recv_request = NULL;

  if(regexp_compile != NULL)
    regfree(regexp_compile);
    free(regexp_compile);
  regexp_compile = NULL;

  if(peer_dest != NULL)
     free (peer_dest);
  peer_dest = NULL; 

  if(peer_src != NULL)
     delete (peer_src);
  peer_src = NULL;

  if(pause_desc != NULL)
     free(pause_desc);
  pause_desc = NULL;

#ifdef __3PCC__
  if(M_sendCmdData != NULL)
    delete(M_sendCmdData);
  M_sendCmdData = NULL;
#endif
}

/******** Global variables which compose the scenario file **********/

message*      scenario[SCEN_MAX_MESSAGES];
CVariable*    scenVariableTable[SCEN_VARIABLE_SIZE][SCEN_MAX_MESSAGES];
bool	      variableUsed[SCEN_VARIABLE_SIZE];
int           scenario_len = 0;
char          scenario_name[255];
int           toolMode  = MODE_CLIENT;
unsigned long scenario_duration = 0;
unsigned int  labelArray[MAX_LABELS];
bool	      rtd_stopped[MAX_RTD_INFO_LENGTH];
bool	      rtd_started[MAX_RTD_INFO_LENGTH];

/*************** Helper functions for various types *****************/
long get_long(const char *ptr, const char *what) {
  char *endptr;
  long ret;

  ret = strtol(ptr, &endptr, 0);
  if (*endptr) {
    ERROR_P2("%s, \"%s\" is not a valid integer!\n", what, ptr);
  }
  return ret;
}

/* This function returns a time in milliseconds from a string.
 * The multiplier is used to convert from the default input type into
 * milliseconds.  For example, for seconds you should use 1000 and for
 * milliseconds use 1. */
long get_time(const char *ptr, const char *what, int multiplier) {
  char *endptr;
  const char *p;
  long ret;
  double dret;
  int i;

  if (!isdigit(*ptr)) {
    ERROR_P2("%s, \"%s\" is not a valid time!\n", what, ptr);
  }

  for (i = 0, p = ptr; *p; p++) {
	if (*p == ':') {
		i++;
	}
  }

  if (i == 1) { /* mm:ss */
    ERROR_P2("%s, \"%s\" mm:ss not implemented yet!\n", what, ptr);
  }
  else if (i == 2) { /* hh:mm:ss */
    ERROR_P2("%s, \"%s\" hh:mm:ss not implemented yet!\n", what, ptr);
  } else if (i != 0) {
    ERROR_P2("%s, \"%s\" is not a valid time!\n", what, ptr);
  }

  dret = strtod(ptr, &endptr);
  if (*endptr) {
    if (!strcmp(endptr, "s")) { /* Seconds */
	ret = (long)(dret * 1000);
    } else if (!strcmp(endptr, "ms")) { /* Milliseconds. */
	ret = (long)dret;
    } else if (!strcmp(endptr, "m")) { /* Minutes. */
	ret = (long)(dret * 60000);
    } else if (!strcmp(endptr, "h")) { /* Hours. */
	ret = (long)(dret * 60 * 60 * 1000);
    } else {
      ERROR_P2("%s, \"%s\" is not a valid time!\n", what, ptr);
    }
  } else {
    ret = (long)(dret * multiplier);
  }
  return ret;
}

double get_double(const char *ptr, const char *what) {
  char *endptr;
  double ret;

  ret = strtod(ptr, &endptr);
  if (*endptr) {
    ERROR_P2("%s, \"%s\" is not a floating point number!\n", what, ptr);
  }
  return ret;
}

bool get_bool(const char *ptr, const char *what) {
  char *endptr;
  long ret;

  if (!strcmp(ptr, "true")) {
    return true;
  }
  if (!strcmp(ptr, "false")) {
    return false;
  }

  ret = strtol(ptr, &endptr, 0);
  if (*endptr) {
    ERROR_P2("%s, \"%s\" is not a valid boolean!\n", what, ptr);
  }
  return ret ? true : false;
}

/* Pretty print a time. */
char *time_string(int ms) {
   static char tmp[20];

   if (ms < 10000) {
	snprintf(tmp, sizeof(tmp), "%dms", ms);
   } else if (ms < 100000) {
	snprintf(tmp, sizeof(tmp), "%.1fs", ((float)ms)/1000);
   } else {
	snprintf(tmp, sizeof(tmp), "%ds", ms/1000);
   }

   return tmp;
}

int time_string(double ms, char *res, int reslen) {
  if (ms < 10000) {
    /* Less then 10 seconds we represent accurately. */
    if ((int)(ms + 0.9999) == (int)(ms)) {
      /* We have an integer, or close enough to it. */
      return snprintf(res, reslen, "%dms", (int)ms);
    } else {
      if (ms < 1000) {
	return snprintf(res, reslen, "%.2lfms", ms);
      } else {
	return snprintf(res, reslen, "%.1lfms", ms);
      }
    }
  } else if (ms < 60000) {
    /* We round to 100ms for times less than a minute. */
    return snprintf(res, reslen, "%.1fs", ms/1000);
  } else if (ms < 60 * 60000) {
    /* We round to 1s for times more than a minute. */
    int s = (unsigned int)(ms / 1000);
    int m = s / 60;
    s %= 60;
    return snprintf(res, reslen, "%d:%02d", m, s);
  } else {
    int s = (unsigned int)(ms / 1000);
    int m = s / 60;
    int h = m / 60;
    s %= 60;
    m %= 60;
    return snprintf(res, reslen, "%d:%02d:%02d", h, m, s);
  }
}

char *double_time_string(double ms) {
   static char tmp[20];

   if (ms < 1000) {
	snprintf(tmp, sizeof(tmp), "%.2lfms", ms);
   } else if (ms < 10000) {
	snprintf(tmp, sizeof(tmp), "%.1lfms", ms);
   } else if (ms < 100000) {
	snprintf(tmp, sizeof(tmp), "%.1lfs", ms / 1000);
   } else {
	snprintf(tmp, sizeof(tmp), "%ds", (int)(ms/1000));
   }

   return tmp;
}

/* For backwards compatibility, we assign "true" to slot 1, false to 0, and
 * allow other valid integers. */
int get_rtd(const char *ptr) {
  char *endptr;
  int ret;

  if(!strcmp(ptr, (char *)"true"))
    return 1;
  if(!strcmp(ptr, (char *)"false"))
    return 0;

  ret = strtol(ptr, &endptr, 0);
  if (*endptr) {
    ERROR_P1("rtd \"%s\" is not a valid integer!\n", ptr);
  }

  if (ret > MAX_RTD_INFO_LENGTH) {
    ERROR_P2("rtd %d exceeds MAX_RTD_INFO_LENGTH %d!\n", ret, MAX_RTD_INFO_LENGTH);
  }

  return ret;
}

/* Get a counter */
long get_counter(const char *ptr, const char *what) {
  long ret;

  ret = get_long(ptr, what);
  if (ret < 1 || ret > MAX_COUNTER) {
    ERROR_P2("Counter %ld exceeds MAX_COUNTER %d!\n", ret, MAX_COUNTER);
  }

  return ret;
}


/*************** Helper functions for computing pauses *************/
unsigned int pause_default(message *msg) {
  if (msg -> pause_param == -1) {
    return duration;
  }
  return msg -> pause_param;
}

unsigned int pause_uniform(message *msg) {
  return msg-> pause_param + rand() % (msg -> pause_param2 - msg -> pause_param);
}

#ifdef HAVE_GSL

gsl_rng *rng;

void init_rng() {
  if (rng) {
    return;
  }
  gsl_rng_env_setup();

  rng = gsl_rng_alloc(gsl_rng_default);
  if (!rng) {
    ERROR("Could not initialize GSL random number generator.\n");
  }
}

unsigned int pause_normal(message *msg) {
  double duration;

  duration = gsl_ran_gaussian(rng, (double)msg->pause_param2);
  duration += msg->pause_param;
  /* The normal distribution can include negative numbers, which make no sense
   * for a pause. */
  if (duration < 0) {
    duration = 0;
  }

  return (unsigned int)duration;
}

unsigned int pause_lognormal(message *msg) {
  double duration;

  duration = gsl_ran_lognormal(rng, msg->pause_dparam, msg->pause_dparam2);

  return (unsigned int)duration;
}

unsigned int pause_exponential(message *msg) {
  double duration = 0;

  duration = gsl_ran_exponential(rng, (double)msg->pause_param);

  return (unsigned int)duration;
}

unsigned int pause_weibull(message *msg) {
  double duration;

  duration = gsl_ran_weibull(rng, msg->pause_dparam, msg->pause_dparam2);

  return (unsigned int)duration;
}

#endif

/* Some validation functions. */

/* If you start an RTD, then you should be interested in collecting statistics for it. */
void validate_rtds() {
  for (int i = 0; i < MAX_RTD_INFO_LENGTH; i++) {
    if (rtd_started[i] && !rtd_stopped[i]) {
      ERROR_P1("You have started Response Time Duration %d, but have never stopped it!", i + 1);
    }
  }
}

/********************** Scenario File analyser **********************/

void load_scenario(char * filename, int deflt)
{
  char * elem;
  char method_list[METHOD_LIST_LENGTH]; // hopefully the method list wont be longer than this
  char method_list_length = 0;           // Enforce length, in case...
  unsigned int scenario_file_cursor = 0;
  int    L_content_length = 0 ;
  unsigned int recv_count = 0;
  unsigned int recv_opt_count = 0;
  char * peer; 
  memset (method_list, 0, sizeof (method_list));

  if(filename) {
    if(!xp_set_xml_buffer_from_file(filename)) {
      ERROR_P1("Unable to load or parse '%s' xml scenario file", filename);
    }
  } else {
    if(!xp_set_xml_buffer_from_string(default_scenario[deflt])) {
      ERROR("Unable to load default xml scenario file");
    }
  }
  
  // set all variable in scenVariable table to NULL
  for(int i=0; i<SCEN_VARIABLE_SIZE; i++) { 
    variableUsed[i] = false;
    for (int j=0; j<SCEN_MAX_MESSAGES; j++) {
      scenVariableTable[i][j] = NULL;
    }
  }
  elem = xp_open_element(0);
  if(strcmp("scenario", elem)) {
    ERROR("No 'scenario' section in xml scenario file");    
  }
  
  if(xp_get_value((char *)"name")) {
    strcpy(scenario_name, xp_get_value((char *)"name"));
  } else {
    scenario_name[0] = 0;
  }

  scenario_len = 0;
  scenario_file_cursor = 0;
  
  while(elem = xp_open_element(scenario_file_cursor)) {
    char * ptr;
    scenario_file_cursor ++;

    if(!strcmp(elem, "CallLengthRepartition")) {
      ptr = xp_get_value((char *)"value");
      CStat::instance()->setRepartitionCallLength(ptr);

    } else if(!strcmp(elem, "ResponseTimeRepartition")) {
      ptr = xp_get_value((char *)"value");
      CStat::instance()->setRepartitionResponseTime(ptr);
    } else if(!strcmp(elem, "label")) {
      ptr = xp_get_value((char *)"id");
      unsigned int labelNumber = get_long(ptr, "label identifier");
      if (labelNumber < (sizeof(labelArray)/sizeof(labelArray[0]))) {
       labelArray[labelNumber] = ::scenario_len;
      }
    } else { /** Message Case */
      scenario[scenario_len]    = new message();
      scenario[scenario_len] -> content_length_flag = message::ContentLengthNoPresent;   // Initialize to No present

      if(!strcmp(elem, "send")) {
        if (recv_count) {
          if (recv_count != recv_opt_count) {
            recv_count = 0;
            recv_opt_count = 0;
          } else {
            ERROR_P1("<recv> before <send> sequence without a mandatory message. Please remove one 'optional=true' (element %d).", scenario_file_cursor);
          }
        }
        
        scenario[scenario_len]->M_type = MSG_TYPE_SEND;
        /* Sent messages descriptions */
        if(ptr = xp_get_cdata()) {

          char * msg;
          int removed_clrf = 0;

          while((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n')) ptr++;

          msg = 
            scenario[scenario_len] -> send_scheme = 
            (char *) malloc(strlen(ptr) + 3);
        

          if(!msg) { ERROR("Memory Overflow"); }

          strcpy(msg, ptr);
          
          //
          // If this is a request we are sending, then copy over the method so that we can associate
          // responses to the request
          //
          if (0 != strncmp (ptr, "SIP/2.0", 7) )
          {
            char *methodEnd = ptr;
            int   bytesToCopy = 0;
            while (*methodEnd != ' ') {
              methodEnd++;
              bytesToCopy++;
            }
            if (method_list_length + bytesToCopy + 1 > METHOD_LIST_LENGTH) {
              ERROR_P2("METHOD_LIST_LENGTH in scenario.hpp is too small (currently %d, need at least %d). Please modify and recompile.", 
                       METHOD_LIST_LENGTH,
                       method_list_length + bytesToCopy + 1);
            }
            strncat (method_list, ptr, bytesToCopy);
            method_list_length += bytesToCopy;
            method_list[method_list_length+1] = '\0';
          }

          L_content_length = xp_get_content_length(msg); 
          switch (L_content_length) {
            case  -1 : 
                  // the msg does not contain content-length field
                  break ;
            case  0 :
                  scenario[scenario_len] -> content_length_flag = 
                           message::ContentLengthValueZero;   // Initialize to No present
                  break ;
            default :
                  scenario[scenario_len] -> content_length_flag = 
                           message::ContentLengthValueNoZero;   // Initialize to No present
                  break ;
            
          }
           
          ptr = msg + strlen(msg);
          ptr --;

          while((ptr >= msg) && 
                ((*ptr == ' ')  || 
                 (*ptr == '\t') || 
                 (*ptr == '\n'))) {
            if(*ptr == '\n') {
              removed_clrf++;
            }
            *ptr-- = 0;
          }
        
          if(ptr == msg) {
            ERROR("Empty cdata in xml scenario file");    
          }

          if(!strstr(msg, "\n\n")) {
            strcat(msg, "\n\n");
          }
        
          while(ptr = strstr(msg, "\n ")) {
            memmove(((char *)(ptr + 1)), 
                    ((char *)(ptr + 2)), 
                    strlen(ptr) - 1);
          }
        
          while(ptr = strstr(msg, " \n")) {
            memmove(((char *)(ptr)), 
                    ((char *)(ptr + 1)), 
                    strlen(ptr));
          }

          if((msg[strlen(msg) - 1] != '\n') && (removed_clrf)) {
            strcat(msg, "\n");
          }

        } else {
          ERROR("No CDATA in 'send' section of xml scenario file");
        }
      
        if(ptr = xp_get_value((char *)"retrans")) {
          scenario[scenario_len] -> retrans_delay = get_long(ptr, "retransmission timer");
        }
      
        if(ptr = xp_get_value((char *)"rtd")) {
          scenario[scenario_len] -> stop_rtd = get_rtd(ptr);
	  rtd_stopped[scenario[scenario_len]->stop_rtd - 1] = true;
	}

        if(ptr = xp_get_value((char *)"start_rtd")) {
          scenario[scenario_len] -> start_rtd = get_rtd(ptr);
	  rtd_started[scenario[scenario_len]->start_rtd - 1] = true;
	}
        if (ptr = xp_get_value((char *)"repeat_rtd")) {
	  if (scenario[scenario_len] -> stop_rtd) {
	    scenario[scenario_len] -> repeat_rtd = get_bool(ptr, "repeat_rtd");
	  } else {
	    ERROR("There is a repeat_rtd element without an rtd element");
	  }
	}

        if(ptr = xp_get_value((char *)"counter")) {
          scenario[scenario_len] -> counter = get_counter(ptr, "counter");
	}

#ifdef PCAPPLAY
        getActionForThisMessage();
#endif

      } else if(!strcmp(elem, (char *)"recv")) {
        recv_count++;
        scenario[scenario_len]->M_type = MSG_TYPE_RECV;
        /* Received messages descriptions */
        if(ptr = xp_get_value((char *)"response")) {
          scenario[scenario_len] -> recv_response = get_long(ptr, "response code");
          strcpy (scenario[scenario_len]->recv_response_for_cseq_method_list, method_list);
        }

        if(ptr = xp_get_value((char *)"request")) {
          scenario[scenario_len] -> recv_request = strdup(ptr);
        }

        if(ptr = xp_get_value((char *)"rtd")) {
          scenario[scenario_len] -> stop_rtd = get_rtd(ptr);
	  rtd_stopped[scenario[scenario_len]->stop_rtd - 1] = true;
	}

        if(ptr = xp_get_value((char *)"start_rtd")) {
          scenario[scenario_len] -> start_rtd = get_rtd(ptr);
	  rtd_started[scenario[scenario_len]->start_rtd - 1] = true;
	}
        if (ptr = xp_get_value((char *)"repeat_rtd")) {
	  if (scenario[scenario_len] -> stop_rtd) {
	    scenario[scenario_len] -> repeat_rtd = get_bool(ptr, "repeat_rtd");
	  } else {
	    ERROR("There is a repeat_rtd element without an rtd element");
	  }
	}


	if(ptr = xp_get_value((char *)"counter")) {
	  scenario[scenario_len] -> counter = get_counter(ptr, "counter");
	}

        if (0 != (ptr = xp_get_value((char *)"optional"))) {
          if(!strcmp(ptr, "true")) {
            scenario[scenario_len] -> optional = OPTIONAL_TRUE;
            ++recv_opt_count;
          } else if(!strcmp(ptr, "global")) {
            scenario[scenario_len] -> optional = OPTIONAL_GLOBAL;
            ++recv_opt_count;
          } else if(!strcmp(ptr, "false")) {
            scenario[scenario_len] -> optional = OPTIONAL_FALSE;
          } else {
	    ERROR_P1("Could not understand optional value: %s", ptr);
	  }
        }

        if (0 != (ptr = xp_get_value((char *)"regexp_match"))) {
          if(!strcmp(ptr, "true")) {
            scenario[scenario_len] -> regexp_match = 1;
          }
        }

        if (0 != (ptr = xp_get_value((char *)"timeout"))) {
          scenario[scenario_len]->retrans_delay = get_long(ptr, "message timeout");
        }

        /* record the route set  */
        /* TODO disallow optional and rrs to coexist? */
        if(ptr = xp_get_value((char *)"rrs")) {
	  scenario[scenario_len] -> bShouldRecordRoutes = get_bool(ptr, "record route set");
        }

        /* record the authentication credentials  */
        if(ptr = xp_get_value((char *)"auth")) {
	  bool temp = get_bool(ptr, "message authentication");
#ifdef _USE_OPENSSL
	  scenario[scenario_len] -> bShouldAuthenticate = temp;
#else
	  if (temp) {
	    ERROR("Authentication requires OpenSSL support!");
	  }
#endif
        }

        getActionForThisMessage();

      } else if(!strcmp(elem, "pause")) {
        if (recv_count) {
          if (recv_count != recv_opt_count) {
            recv_count = 0;
            recv_opt_count = 0;
          } else {
            ERROR_P1("<recv> before <send> sequence without a mandatory message. Please remove one 'optional=true' (element %d).", scenario_file_cursor);
          }
        }
        scenario[scenario_len]->M_type = MSG_TYPE_PAUSE;

	if(ptr = xp_get_value("milliseconds")) {
	  scenario[scenario_len] -> pause_function = pause_default;
	  scenario[scenario_len] -> pause_param = get_long(ptr, "Pause milliseconds");
	  scenario[scenario_len] -> pause_desc =
	    strdup(time_string(scenario[scenario_len] -> pause_param));
	  scenario_duration += scenario[scenario_len] -> pause_param;
	} else if(xp_get_value("min") || xp_get_value("max")) {
	  int isMin = !!xp_get_value("min");
	  int isMax = !!xp_get_value("max");
	  int min, max;
	  char tmp[42];

	  if (isMin && !isMax) {
	    ERROR("Max without min for a variable pause");
	  }
	  if (isMax && !isMin) {
	    ERROR("Min without max for a variable pause");
	  }

	  min = get_long(xp_get_value("min"), "Pause minimum");
	  max = get_long(xp_get_value("max"), "Pause maximum");

	  scenario[scenario_len] -> pause_function = pause_uniform;
	  strncpy(tmp, time_string(min), sizeof(tmp));
	  strncat(tmp, "/", sizeof(tmp) - strlen(tmp));
	  strncat(tmp, time_string(max), sizeof(tmp) - strlen(tmp));
	  scenario[scenario_len] -> pause_desc = strdup(tmp);
	  scenario[scenario_len] -> pause_param = min;
	  scenario[scenario_len] -> pause_param2 = max;

	  if (min >= max) {
	    ERROR("Min is greater than or equal to max in variable pause!");
	  }

          /* Update scenario duration with max duration */
	  scenario_duration += scenario[scenario_len] -> pause_param;
#ifdef HAVE_GSL
	} else if (xp_get_value("normal")) {
	  long mean = 0;
	  long stdev = 1;
	  char tmp[45];

	  init_rng();

          if (ptr = xp_get_value("mean")) {
		mean = get_long(ptr, "Mean pause");
	  }
          if (ptr = xp_get_value("stdev")) {
		stdev = get_long(ptr, "Pause standard deviation");
	  }

	  if (stdev < 0) {
	    ERROR_P1("Standard deviations must be positive: %ld\n", stdev);
	  }
	  if (mean < 0) {
	    ERROR_P1("Pause means should not be negative: %ld\n", mean);
	  }

          scenario[scenario_len] -> pause_param  = mean;
          scenario[scenario_len] -> pause_param2 = stdev;

	  scenario[scenario_len] -> pause_function = pause_normal;
	  strcpy(tmp, "N(");
	  strncat(tmp, time_string(mean), sizeof(tmp) - strlen(tmp));
	  strncat(tmp, ",", sizeof(tmp) - strlen(tmp));
	  strncat(tmp, time_string(stdev), sizeof(tmp) - strlen(tmp));
	  strncat(tmp, ")", sizeof(tmp) - strlen(tmp));
	  scenario[scenario_len] -> pause_desc = strdup(tmp);

	  /* We have no true maximum duration for a distributed pause, but this
	   * captures 99% of all calls. */
	  scenario_duration += (int)gsl_cdf_gaussian_Pinv(0.99, stdev) + mean;
	} else if (xp_get_value("lognormal")) {
	  double mean = 0;
	  double stdev = 1;
	  char tmp[46];

	  init_rng();

          if (ptr = xp_get_value("mean")) {
		mean = get_double(ptr, "Lognormal mean pause");
	  }
          if (ptr = xp_get_value("stdev")) {
		stdev = get_double(ptr, "Lognormal pause standard deviation");
	  }

	  if (stdev < 0) {
	    ERROR_P1("Standard deviations must be positive: %lf\n", stdev);
	  }
	  if (mean < 0) {
	    ERROR_P1("Pause means should not be negative: %lf\n", mean);
	  }

          scenario[scenario_len] -> pause_dparam  = mean;
          scenario[scenario_len] -> pause_dparam2 = stdev;
	  scenario[scenario_len] -> pause_function = pause_lognormal;
	  strcpy(tmp, "LN(");
	  strncat(tmp, double_time_string(mean), sizeof(tmp) - strlen(tmp));
	  strncat(tmp, ",", sizeof(tmp) - strlen(tmp));
	  strncat(tmp, double_time_string(stdev), sizeof(tmp) - strlen(tmp));
	  strncat(tmp, ")", sizeof(tmp) - strlen(tmp));
	  scenario[scenario_len] -> pause_desc = strdup(tmp);

	  /* It is easy to shoot yourself in the foot with this distribution,
	   * so the 99-th percentile serves as a sanity check for duration. */
	  if (gsl_cdf_lognormal_Pinv(0.99, mean, stdev) > INT_MAX) {
	    ERROR_P2("You should use different Lognormal(%lf, %lf) parameters.\n"
		"The scenario is likely to take much too long.\n", mean, stdev);
	  }

	  scenario_duration += (int)gsl_cdf_lognormal_Pinv(0.99, mean, stdev);
	} else if (xp_get_value("weibull")) {
	  double lambda, k;
	  char tmp[46];

	  init_rng();

          if (ptr = xp_get_value("lambda")) {
	    lambda = get_double(ptr, "Weibull lambda");
	  } else {
	    ERROR("lambda and k must be specified for weibull pauses!\n");
	  }
          if (ptr = xp_get_value("k")) {
	    k = get_double(ptr, "Weibull k");
	  } else {
	    ERROR("lambda and k must be specified for weibull pauses!\n");
	  }

	  if (lambda <= 0) {
	    ERROR_P1("Weibull lambda must be positive: %lf\n", lambda);
	  }
	  if (k <= 0) {
	    ERROR_P1("Weibull k must be positive: %lf\n", k);
	  }

          scenario[scenario_len] -> pause_dparam  = lambda;
          scenario[scenario_len] -> pause_dparam2 = k;
	  scenario[scenario_len] -> pause_function = pause_weibull;
	  snprintf(tmp, sizeof(tmp), "Wb(%.2lf,%.2lf)", lambda, k);
	  scenario[scenario_len] -> pause_desc = strdup(tmp);

	  /* It is easy to shoot yourself in the foot with this distribution,
	   * so the 99-th percentile serves as a sanity check for duration. */
	  if (gsl_cdf_weibull_Pinv(0.99, lambda, k) > INT_MAX) {
	    ERROR_P2("You should use different Weibull(%lf, %lf) parameters.\n"
		"The scenario is likely to take much too long.\n", lambda, k);
	  }

	  scenario_duration += (int)gsl_cdf_weibull_Pinv(0.99, lambda, k);
	} else if (xp_get_value("exponential")) {
	  long mean = 0;
	  char tmp[26];

	  init_rng();

          if (ptr = xp_get_value("mean")) {
		mean = get_long(ptr, "Mean pause");
	  }

	  if (mean < 0) {
	    ERROR_P1("Pause means should not be negative: %ld\n", mean);
	  }

          scenario[scenario_len] -> pause_param = mean;
          scenario[scenario_len] -> pause_function = pause_exponential;
	  strcpy(tmp, "Exp(");
	  strncat(tmp, time_string(mean), sizeof(tmp) - strlen(tmp));
	  strncat(tmp, ")", sizeof(tmp) - strlen(tmp));
	  scenario[scenario_len] -> pause_desc = strdup(tmp);
	  scenario_duration += (int)gsl_cdf_exponential_Pinv(0.99, mean);
#else
	} else if (xp_get_value("normal") ||
		   xp_get_value("lognormal") ||
		   xp_get_value("exponential") ||
		   xp_get_value("weibull")
	          ) {
	  ERROR("To use a statistically distributed pause, you must have the GNU Scientific Library.\n");
#endif
        } else {
	  scenario[scenario_len] -> pause_function = pause_default;
          scenario[scenario_len] -> pause_param = -1;
	  scenario[scenario_len] -> pause_desc = strdup(time_string(duration));
        }
        getActionForThisMessage();
      }
      else if(!strcmp(elem, "nop")) {
	/* Does nothing at SIP level.  This message type can be used to handle
	 * actions, increment counters, or for RTDs. */
	scenario[scenario_len]->M_type = MSG_TYPE_NOP;

        if(ptr = xp_get_value((char *)"rtd")) {
          scenario[scenario_len] -> stop_rtd = get_rtd(ptr);
	  rtd_stopped[scenario[scenario_len]->stop_rtd - 1] = true;
	}

        if(ptr = xp_get_value((char *)"start_rtd")) {
          scenario[scenario_len] -> start_rtd = get_rtd(ptr);
	  rtd_started[scenario[scenario_len]->start_rtd - 1] = true;
	}

        if(ptr = xp_get_value((char *)"counter")) {
          scenario[scenario_len] -> counter = get_counter(ptr, "counter");
	}

        getActionForThisMessage();
      }
#ifdef __3PCC__
      else if(!strcmp(elem, "recvCmd")) {
        recv_count++;
        scenario[scenario_len]->M_type = MSG_TYPE_RECVCMD;

	/* 3pcc extended mode */
        if(ptr = xp_get_value((char *)"src")) { 
           scenario[scenario_len] ->peer_src = strdup(ptr) ;
        }
        getActionForThisMessage();

      } else if(!strcmp(elem, "sendCmd")) {
        if (recv_count) {
          if (recv_count != recv_opt_count) {
            recv_count = 0;
            recv_opt_count = 0;
          } else {
            ERROR_P1("<recv> before <send> sequence without a mandatory message. Please remove one 'optional=true' (element %d).", scenario_file_cursor);
          }
        }
        scenario[scenario_len]->M_type = MSG_TYPE_SENDCMD;
        /* Sent messages descriptions */

	/* 3pcc extended mode  */
	if(ptr = xp_get_value((char *)"dest")) { 
	   peer = strdup(ptr) ;
	   scenario[scenario_len] ->peer_dest = peer ;
           peer_map::iterator peer_it;
	   peer_it = peers.find(peer_map::key_type(peer));
	   if(peer_it == peers.end())  /* the peer (slave or master)
					  has not been added in the map
					  (first occurence in the scenario) */
	   {
	     T_peer_infos infos;
	     infos.peer_socket = 0;
	     strcpy(infos.peer_host, get_peer_addr(peer));
             peers[std::string(peer)] = infos; 
	     }
        }

        if(ptr = xp_get_cdata()) {
        
          char * msg;
        
          while((*ptr == ' ') || (*ptr == '\t') || (*ptr == '\n')) ptr++;
        
          msg = 
            scenario[scenario_len] -> M_sendCmdData = 
            (char *) malloc(strlen(ptr) + 3);
        
          if(!msg) { ERROR("Memory Overflow"); }

          strcpy(msg, ptr);
        
          ptr = msg + strlen(msg);
          ptr --;
        
          while((ptr >= msg) && 
                ((*ptr == ' ')  || 
                 (*ptr == '\t') || 
                 (*ptr == '\n'))) {
            *ptr-- = 0;
          }
        
          if(ptr != msg) {
      
            while(ptr = strstr(msg, "\n ")) {
              memmove(((char *)(ptr + 1)), 
                      ((char *)(ptr + 2)), 
                      strlen(ptr) - 1);
            }
        
            while(ptr = strstr(msg, " \n")) {
              memmove(((char *)(ptr)), 
                      ((char *)(ptr + 1)), 
                      strlen(ptr));
            }
          }
        }

      } 
#endif
      else {
        ERROR_P1("Unknown element '%s' in xml scenario file", elem);
      }
    
      if(ptr = xp_get_value((char *)"lost")) {
        scenario[scenario_len] -> lost = get_double(ptr, "lost percentage");
        lose_packets = 1;
      }

      if(ptr = xp_get_value((char *)"crlf")) {
        scenario[scenario_len] -> crlf = 1;
      }

      if ( 0 != ( ptr = xp_get_value((char *)"next") ) ) {
        scenario[scenario_len] -> next = get_long(ptr, "next jump");
         if ( 0 != ( ptr = xp_get_value((char *)"test") ) ) {
           scenario[scenario_len] -> test = get_long(ptr, "test variable");
         }
         else {
           scenario[scenario_len] -> test = -1;
         }
         if ( 0 != ( ptr = xp_get_value((char *)"chance") ) ) {
           float chance = get_double(ptr,"chance");
                                     /* probability of branch to next */
           if (( chance < 0.0 ) || (chance > 1.0 )) {
             ERROR_P1("Chance %s not in range [0..1]", ptr);
           }
           scenario[scenario_len] -> chance = (int)((1.0-chance)*RAND_MAX);
         }
         else {
           scenario[scenario_len] -> chance = 0;/* always */
         }
      } else {
        scenario[scenario_len] -> next = 0;
      }

      if (0 != (ptr = xp_get_value((char *)"ontimeout")) ) {
        if ((::scenario[scenario_len]->on_timeout = get_long(ptr, "timeout jump")) >= MAX_LABELS) {
            ERROR_P1("Ontimeout label larger than max supported %d", MAX_LABELS-1);
        }
      }
     
      if (++scenario_len >= SCEN_MAX_MESSAGES) {
          ERROR("Too many items in xml scenario file");
      }
    } /** end * Message case */
    xp_close_element();
  } // end while

  /* Some post-scenario loading validation. */
  validate_rtds();
}

/* 3pcc extended mode:
   get the correspondances between
   slave and master names and their 
   addresses */

void parse_slave_cfg()
{
  FILE * f;
  char line[MAX_PEER_SIZE];
  char * temp_peer;
  char * peer_host;

  f = fopen(slave_cfg_file, "r");
  if(f){
     while (fgets(line, MAX_PEER_SIZE, f) != NULL)
     {
       temp_peer = strtok(line, ";");
       peer_host = (char *) malloc(MAX_PEER_SIZE);
       strcpy(peer_host, strtok(NULL, ";"));
       peer_addrs[std::string(temp_peer)] = peer_host; 
     }
   }else{ 
     ERROR_P1("Can not open slave_cfg file %s\n", slave_cfg_file);
     }
}

// Determine in which mode the sipp tool has been 
// launched (client, server, 3pcc client, 3pcc server, 3pcc extended master or slave)
void computeSippMode()
{
  bool isRecvCmdFound = false;
  bool isSendCmdFound = false;
  bool isFirstMessageFound = true;

  toolMode = -1;
  for(int i=0; i<scenario_len; i++)
    { 
      switch(scenario[i] -> M_type)
        {
        case MSG_TYPE_PAUSE:
        case MSG_TYPE_NOP:
	  /* Allow pauses or nops to go first. */
	  continue;
        case MSG_TYPE_SEND: 
          if(isFirstMessageFound)
            toolMode  = MODE_CLIENT;
          isFirstMessageFound = false;
          break;

        case MSG_TYPE_RECV:
          if(isFirstMessageFound)
            toolMode  = MODE_SERVER;
          isFirstMessageFound = false;
          break;
#ifdef __3PCC__
        case MSG_TYPE_SENDCMD:
          isSendCmdFound = true;
          if(!isRecvCmdFound) {
            if (false == isFirstMessageFound && toolMode == MODE_SERVER) {
              /*
               * If it is a server already, then start it in
               * 3PCC A passive mode
               */
	       if(twinSippMode){
              toolMode = MODE_3PCC_A_PASSIVE;
	       }else if (extendedTwinSippMode){
		  toolMode = MODE_MASTER_PASSIVE;
               }
            } else {
	        if(twinSippMode){
              toolMode = MODE_3PCC_CONTROLLER_A;
                 }else if (extendedTwinSippMode){
                   toolMode = MODE_MASTER;
                 } 
            }
            if((toolMode == MODE_MASTER_PASSIVE || toolMode == MODE_MASTER) && !master_name){
              ERROR("Inconsistency between command line and scenario: master scenario but -master option not set\n");
            }
            if(!twinSippMode && !extendedTwinSippMode)
              ERROR("sendCmd message found in scenario but no twin sipp"
                    " address has been passed! Use -3pcc option or 3pcc extended mode.\n");
            return;
          }
          isFirstMessageFound = false;
          break;

        case MSG_TYPE_RECVCMD:
          isRecvCmdFound = true;
          if(!isSendCmdFound)
            {
              if(twinSippMode){
              toolMode  = MODE_3PCC_CONTROLLER_B;
              } else if(extendedTwinSippMode){
	         toolMode = MODE_SLAVE;
                 if(!slave_number) {
                    ERROR("Inconsistency between command line and scenario: slave scenario but -slave option not set\n");
                   }else{
                    toolMode = MODE_SLAVE;
                   } 
              }
              if(!twinSippMode && !extendedTwinSippMode)
                ERROR("sendCmd message found in scenario but no "
                      "twin sipp address has been passed! Use "
                      "-3pcc option\n");
              return;
            }
          isFirstMessageFound = false;
          break;
#endif // __3PCC__
        default:
          break;
        }
    }
    if(toolMode == -1)
      ERROR("Unable to determine mode of the tool (server, "
            "client, 3PCC controller A, 3PCC controller B).\n");
}


// Action list for the message indexed by message_index in 
// the scenario
void getActionForThisMessage()
{
  unsigned int recvScenarioLen = 0;
  char *        actionElem;
  char *        currentRegExp = NULL;
  char *        buffer = NULL;
  unsigned int* currentTabVarId = NULL;
  int           currentNbVarId;
  char * ptr;
  int           sub_currentNbVarId;

  if(!(actionElem = xp_open_element(0))) {
    return;
  }
  if(strcmp(actionElem, "action")) {
    return;
  }

  /* We actually have an action element. */
  if(scenario[scenario_len] != NULL) {
    if(scenario[scenario_len]->M_actions != NULL) {
      delete(scenario[scenario_len]->M_actions);
    }
    scenario[scenario_len]->M_actions = new CActions();
  }

  while(actionElem = xp_open_element(recvScenarioLen)) {
    CAction *tmpAction = new CAction();

    if(!strcmp(actionElem, "ereg")) {
      if(!(ptr = xp_get_value((char *)"regexp"))) {
	ERROR("'ereg' action without 'regexp' argument (mandatory)");
      }

      // keeping regexp expression in memory
      if(currentRegExp != NULL)
	delete[] currentRegExp;
      currentRegExp = new char[strlen(ptr)+1];
      buffer = new char[strlen(ptr)+1];
      xp_replace(ptr, buffer, "&lt;", "<");
      xp_replace(buffer, currentRegExp, "&gt;", ">");
      if(buffer != NULL)
	delete[] buffer;
      tmpAction->setVarType(E_VT_REGEXP);
      tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_REGEXP);

      // warning - although these are detected for both msg and hdr
      // they are only implemented for search_in="hdr"
      if ((ptr = xp_get_value((char *)"case_indep"))) {
	tmpAction->setCaseIndep(get_bool(ptr, "case_indep"));
      } else {
	tmpAction->setCaseIndep(false);
      }

      if ((ptr = xp_get_value((char *)"start_line"))) {
	tmpAction->setHeadersOnly(get_bool(ptr, "start_line"));
      } else {
	tmpAction->setHeadersOnly(false);
      }

      if ( 0 != ( ptr = xp_get_value((char *)"search_in") ) ) {
	tmpAction->setOccurence(1);

	if ( 0 == strcmp(ptr, (char *)"msg") ) {
	  tmpAction->setLookingPlace(CAction::E_LP_MSG);
	  tmpAction->setLookingChar (NULL);
	} else if (!strcmp(ptr, (char *)"hdr")) {
	  if ( 0 != ( ptr = xp_get_value((char *)"header") ) ) {
	    if ( 0 < strlen(ptr) ) {
	      tmpAction->setLookingPlace(CAction::E_LP_HDR);
	      tmpAction->setLookingChar(ptr);
	      if (0 != (ptr = xp_get_value((char *)"occurence"))) {
		tmpAction->setOccurence (atol(ptr));
	      }
	    } else {
	      tmpAction->setLookingPlace(CAction::E_LP_MSG);
	      tmpAction->setLookingChar(NULL);
	    }
	  }
	} else {
	  tmpAction->setLookingPlace(CAction::E_LP_MSG);
	  tmpAction->setLookingChar(NULL);
	}
      } else {
	tmpAction->setLookingPlace(CAction::E_LP_MSG);
	tmpAction->setLookingChar(NULL);
      } // end if-else search_in

      if(ptr = xp_get_value((char *)"check_it")) {
	tmpAction->setCheckIt(get_bool(ptr, "check_it"));
      } else {
	tmpAction->setCheckIt(false);
      }

      if(!(ptr = xp_get_value((char *)"assign_to"))) {
	ERROR("'ereg' action without 'assign_to' argument (mandatory)");
      }

      if(createIntegerTable(ptr, &currentTabVarId, &currentNbVarId) == 1) {

	if(currentTabVarId[0] <  SCEN_VARIABLE_SIZE) {
	  tmpAction->setVarId(currentTabVarId[0]);
	  /* and creating the associated variable */
	  if (scenVariableTable[currentTabVarId[0]][scenario_len] != NULL) {
	    delete(scenVariableTable[currentTabVarId[0]][scenario_len]);
	    scenVariableTable[currentTabVarId[0]][scenario_len] = NULL;
	  }
	  variableUsed[currentTabVarId[0]] = true;
	  scenVariableTable[currentTabVarId[0]][scenario_len] =
	    new CVariable(currentRegExp);

	  if(!(scenVariableTable[currentTabVarId[0]][scenario_len]
		->isRegExpWellFormed()))
	    ERROR_P1("Regexp '%s' is not valid in xml "
		"scenario file", currentRegExp);
	} else {
	  ERROR("Too many call variables in the scenario. Please change '#define SCEN_VARIABLE_SIZE' in scenario.hpp and recompile SIPp");
	}

	if (currentNbVarId > 1 ) {
	  sub_currentNbVarId = currentNbVarId - 1 ;
	  tmpAction->setNbSubVarId(sub_currentNbVarId);

	  for(int i=1; i<= sub_currentNbVarId; i++) {
	    if(currentTabVarId[i] <  SCEN_VARIABLE_SIZE) {
	      tmpAction->setSubVarId(currentTabVarId[i]);

	      /* and creating the associated variable */
	      if (scenVariableTable[currentTabVarId[i]][scenario_len] != NULL) {
		delete(scenVariableTable[currentTabVarId[i]][scenario_len]);
		scenVariableTable[currentTabVarId[i]][scenario_len] = NULL;
	      }
	      scenVariableTable[currentTabVarId[i]][scenario_len] =
		new CVariable(currentRegExp);

	      if(!(scenVariableTable[currentTabVarId[i]][scenario_len]
		    ->isRegExpWellFormed()))
		ERROR_P1("Regexp '%s' is not valid in xml "
		    "scenario file", currentRegExp);
	    }
	  }
	}

	delete[] currentTabVarId;
      }

      if(currentRegExp != NULL) {
	delete[] currentRegExp;
      }
      currentRegExp = NULL;
    } /* end !strcmp(actionElem, "ereg") */ else if(!strcmp(actionElem, "log")) {
      if(ptr = xp_get_value((char *)"message")) {
	tmpAction->setActionType(CAction::E_AT_LOG_TO_FILE);
	tmpAction->setMessage(ptr);
      }
    } /* end !strcmp(actionElem, "log") */ else if(!strcmp(actionElem, "logvars")) {
      tmpAction->setActionType(CAction::E_AT_LOG_VARS_TO_FILE);
    } /* end !strcmp(actionElem, "logvars") */ else if(!strcmp(actionElem, "assign")) {
      if(ptr = xp_get_value((char *)"assign_to")) {
	int var = get_long(ptr, "assignment variable ID");
	if(var >=  SCEN_VARIABLE_SIZE) {
	  ERROR("Too many call variables in the scenario. Please change '#define SCEN_VARIABLE_SIZE' in scenario.hpp and recompile SIPp");
	}
	variableUsed[var] = true;
	tmpAction->setVarId(var);
      } else { // end "assign_to"
	ERROR("'assign' action without 'assign_to' argument (mandatory)");
      }

      if(!(ptr = xp_get_value((char *)"value"))) {
	ERROR("'assign' action requires 'value' parameter");
      }
      double val = get_double(ptr, "assignment value");

      tmpAction->setVarType(E_VT_DOUBLE);
      tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_VALUE);
      tmpAction->setDoubleValue(val);
    } /* end !strcmp(actionElem, "assign") */ else if(!strcmp(actionElem, "sample")) {
      if(ptr = xp_get_value((char *)"assign_to")) {
	int var = get_long(ptr, "sample variable ID");
	if(var >=  SCEN_VARIABLE_SIZE) {
	  ERROR("Too many call variables in the scenario. Please change '#define SCEN_VARIABLE_SIZE' in scenario.hpp and recompile SIPp");
	}
	tmpAction->setVarId(var);
	variableUsed[var] = true;
      } else { // end "assign_to"
	ERROR("'sample' action without 'assign_to' argument (mandatory)");
      }

      if(!(ptr = xp_get_value((char *)"distribution"))) {
	ERROR("'sample' action requires 'distribution' parameter");
      }
      CSample *distribution = NULL;

      if (!strcmp(ptr, "fixed")) {
	double value;
	if (ptr = xp_get_value("value")) {
	  value = get_double(ptr, "Fixed distribution value");
	} else {
	  ERROR("Fixed distributions require a value parameter.");
	}
	distribution = new CFixed(value);
      } else if (!strcmp(ptr, "uniform")) {
	double min, max;
	if (ptr = xp_get_value("min")) {
	  min = get_double(ptr, "Uniform distribution minimum");
	} else {
	  ERROR("Uniform distributions require a min and max parameter.");
	}
	if (ptr = xp_get_value("max")) {
	  max = get_double(ptr, "Uniform distribution minimum");
	} else {
	  ERROR("Uniform distributions require a min and max parameter.");
	}
	distribution = new CUniform(min, max);
      } else if (!strcmp(ptr, "normal")) {
	double mean, stdev;
	if (ptr = xp_get_value("mean")) {
	  mean = get_double(ptr, "Noraml distribution mean");
	} else {
	  ERROR("Normal distributions require a mean and stdev parameter.");
	}
	if (ptr = xp_get_value("stdev")) {
	  stdev = get_double(ptr, "Normal distribution stdev");
	} else {
	  ERROR("Normal distributions require a mean and stdev parameter.");
	}
	distribution = new CNormal(mean, stdev);
      } else {
	ERROR_P1("Unknown distribution: %s\n", ptr);
      }

      tmpAction->setVarType(E_VT_DOUBLE);
      tmpAction->setActionType(CAction::E_AT_ASSIGN_FROM_SAMPLE);
      assert(distribution);
      tmpAction->setDistribution(distribution);
    } /* end !strcmp(actionElem, "sample")  */ else if(!strcmp(actionElem, "exec")) {
      if(ptr = xp_get_value((char *)"command")) {
	tmpAction->setActionType(CAction::E_AT_EXECUTE_CMD);
	tmpAction->setCmdLine(ptr);
	/* the action is well formed, adding it in the */
	/* tmpActionTable */
      } /* end (ptr = xp_get_value("command")  */ else if(ptr = xp_get_value((char *)"int_cmd")) {
	CAction::T_IntCmdType type(CAction::E_INTCMD_STOPCALL); /* assume the default */

	if (!strcmp(ptr, "stop_now")) {
	  type = CAction::E_INTCMD_STOP_NOW;
	} else if (!strcmp(ptr, "stop_gracefully")) {
	  type = CAction::E_INTCMD_STOP_ALL;
	} else if (!strcmp(ptr, "stop_call")) {
	  type = CAction::E_INTCMD_STOPCALL;
	}

	/* the action is well formed, adding it in the */
	/* tmpActionTable */
	tmpAction->setActionType(CAction::E_AT_EXEC_INTCMD);
	tmpAction->setIntCmd(type);
#ifdef PCAPPLAY
      } else if (ptr = xp_get_value((char *) "play_pcap_audio")) {
	tmpAction->setPcapArgs(ptr);
	tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_AUDIO);
	hasMedia = 1;
      } else if (ptr = xp_get_value((char *) "play_pcap_video")) {
	tmpAction->setPcapArgs(ptr);
	tmpAction->setActionType(CAction::E_AT_PLAY_PCAP_VIDEO);
	hasMedia = 1;
#else
      } else if (ptr = xp_get_value((char *) "play_pcap_audio")) {
	ERROR("play_pcap_audio requires pcap support! Please recompile SIPp");
      } else if (ptr = xp_get_value((char *) "play_pcap_video")) {
	ERROR("play_pcap_video requires pcap support! Please recompile SIPp");
#endif
      } else {
	ERROR("illegal <exec> in the scenario\n");
      }
    } else {
      ERROR_P1("Unknown action: %s", actionElem);
    }

    /* If the action was not well-formed, there should have already been an
     * ERROR declaration, thus it is safe to add it here at the end of the loop. */
    scenario[scenario_len]->M_actions->setAction(tmpAction);

    xp_close_element();
    recvScenarioLen++;
  } // end while
  xp_close_element();
}

// char* manipulation : create a int[] from a char*
// test first is the char* is formed by int separeted by coma
// and then create the table

int isWellFormed(char * P_listeStr, int * nombre)
{
  char * ptr = P_listeStr;
  int sizeOf;
  bool isANumber;

  (*nombre) = 0; 
  sizeOf = strlen(P_listeStr);
  // getting the number 
  if(sizeOf > 0)
    {
      // is the string well formed ? [0-9] [,]
      isANumber = false;
      for(int i=0; i<=sizeOf; i++)
        {
          switch(ptr[i])
            {
            case ',':
              if(isANumber == false)
                {   
                  return(0);
                }
              else
                {
                  (*nombre)++;             
                } 
              isANumber = false;
              break;
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
              isANumber = true;
              break;
            case '\t':
            case ' ' :
              break;
            case '\0':
              if(isANumber == false)
                {   
                  return(0);
                }
              else
                {
                  (*nombre)++;
                } 
              break;
            default:
              return(0);
            }
        } // end for
    }
  return(1);
}

int createIntegerTable(char * P_listeStr, 
                       unsigned int ** listeInteger, 
                       int * sizeOfList)
{
  int nb=0;
  char * ptr = P_listeStr;
  char * ptr_prev = P_listeStr;
  unsigned int current_int;
 
  if(isWellFormed(P_listeStr, sizeOfList) == 1)
    {
      (*listeInteger) = new unsigned int[(*sizeOfList)];
      while((*ptr) != ('\0'))
        {
          if((*ptr) == ',')
            {
              sscanf(ptr_prev, "%u", &current_int);
              if (nb<(*sizeOfList))
                (*listeInteger)[nb] = current_int;
              nb++;
              ptr_prev = ptr+1;
            }
          ptr++;
        }

      // Read the last
      sscanf(ptr_prev, "%u", &current_int); 
      if (nb<(*sizeOfList))
        (*listeInteger)[nb] = current_int;
      nb++;
      return(1);
    }
  return(0);
}

/* These are the names of the scenarios, they must match the default_scenario table. */
char *scenario_table[] = {
	"uac",
	"uas",
	"regexp",
	"3pcc-C-A",
	"3pcc-C-B",
	"3pcc-A",
	"3pcc-B",
	"branchc",
	"branchs",
	"uac_pcap"
};

int find_scenario(const char *scenario) {
  int i, max;
  max = sizeof(scenario_table)/sizeof(scenario_table[0]);

  for (i = 0; i < max; i++) {
    if (!strcmp(scenario_table[i], scenario)) {
	return i;
    }
  }

  return -1;
}

// TIP: to integrate an existing XML scenario, use the following sed line:
// cat ../3pcc-controller-B.xml | sed -e 's/\"/\\\"/g' -e 's/\(.*\)/\"\1\\n\"/'
char * default_scenario [] = {
  
/************* Default_scenario[0] ***************/
(char *)
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 Sipp default 'uac' scenario.                       -->\n"
"<!--                                                                    -->\n"
"\n"
"<scenario name=\"Basic Sipstone UAC\">\n"
"  <!-- In client mode (sipp placing calls), the Call-ID MUST be         -->\n"
"  <!-- generated by sipp. To do so, use [call_id] keyword.                -->\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 INVITE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[media_ip_type] [media_ip]\n"
"      t=0 0\n"
"      m=audio [media_port] RTP/AVP 0\n"
"      a=rtpmap:0 PCMU/8000\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"100\"\n"
"        optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"180\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"183\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- By adding rrs=\"true\" (Record Route Sets), the route sets         -->\n"
"  <!-- are saved and used for following messages sent. Useful to test   -->\n"
"  <!-- against stateful SIP proxies/B2BUAs.                             -->\n"
"  <recv response=\"200\" rtd=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- Packet lost can be simulated in any send/recv message by         -->\n"
"  <!-- by adding the 'lost = \"10\"'. Value can be [1-100] percent.       -->\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 ACK\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- This delay can be customized by the -d command-line option       -->\n"
"  <!-- or by adding a 'milliseconds = \"value\"' option here.             -->\n"
"  <pause/>\n"
"\n"
"  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 2 BYE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"200\" crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- definition of the response time repartition table (unit is ms)   -->\n"
"  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
"\n"
"  <!-- definition of the call length repartition table (unit is ms)     -->\n"
"  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
"\n"
"</scenario>\n"
"\n"
, 

/************* Default_scenario[1] ***************/
(char *)
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 Sipp default 'uas' scenario.                       -->\n"
"<!--                                                                    -->\n"
"\n"
"<scenario name=\"Basic UAS responder\">\n"
"  <!-- By adding rrs=\"true\" (Record Route Sets), the route sets         -->\n"
"  <!-- are saved and used for following messages sent. Useful to test   -->\n"
"  <!-- against stateful SIP proxies/B2BUAs.                             -->\n"
"  <recv request=\"INVITE\" crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- The '[last_*]' keyword is replaced automatically by the          -->\n"
"  <!-- specified header if it was present in the last message received  -->\n"
"  <!-- (except if it was a retransmission). If the header was not       -->\n"
"  <!-- present or if no message has been received, the '[last_*]'       -->\n"
"  <!-- keyword is discarded, and all bytes until the end of the line    -->\n"
"  <!-- are also discarded.                                              -->\n"
"  <!--                                                                  -->\n"
"  <!-- If the specified header was present several times in the         -->\n"
"  <!-- message, all occurences are concatenated (CRLF seperated)        -->\n"
"  <!-- to be used in place of the '[last_*]' keyword.                   -->\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 180 Ringing\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag01[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag01[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[media_ip_type] [media_ip]\n"
"      t=0 0\n"
"      m=audio [media_port] RTP/AVP 0\n"
"      a=rtpmap:0 PCMU/8000\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv request=\"ACK\"\n"
"        optional=\"true\"\n"
"        rtd=\"true\"\n"
"        crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv request=\"BYE\">\n"
"  </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
"  <!-- able to retransmit it if we receive the BYE again.               -->\n"
"  <pause milliseconds=\"4000\"/>\n"
"\n"
"\n"
"  <!-- definition of the response time repartition table (unit is ms)   -->\n"
"  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
"\n"
"  <!-- definition of the call length repartition table (unit is ms)     -->\n"
"  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
"\n"
"</scenario>\n"
"\n",

/************* Default_scenario[2] ***************/
(char *)
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 Sipp default 'regexp client' scenario.             -->\n"
"<!--                                                                    -->\n"
"\n"
"<scenario name=\"Client with regexp scenario\">\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag02[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 INVITE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[media_ip_type] [media_ip]\n"
"      t=0 0\n"
"      m=audio [media_port] RTP/AVP 0\n"
"      a=rtpmap:0 PCMU/8000\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"100\"\n"
"        optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"180\" optional=\"true\">\n"
"  </recv>\n"
"  <recv response=\"183\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"200\" start_rtd=\"true\">\n"
"    <!-- Definition of regexp in the action tag. The regexp must follow -->\n"
"    <!-- the Posix Extended standard (POSIX 1003.2), see:               -->\n"
"    <!--                                                                -->\n"
"    <!--   http://www.opengroup.org/onlinepubs/007908799/xbd/re.html    -->\n"
"    <!--                                                                -->\n"
"    <!-- regexp    : Contain the regexp to use for matching the         -->\n"
"    <!--             received message                                   -->\n"
"    <!--             MANDATORY                                          -->\n"
"    <!-- search_in : msg (try to match against the entire message)      -->\n"
"    <!--           : hdr (try to match against a specific SIP header    -->\n"
"    <!--             (passed in the header tag)                         -->\n"
"    <!--             OPTIONAL - default value : msg                     -->\n"
"    <!-- header    : Header to try to match against.                    -->\n"
"    <!--             Only used when the search_in tag is set to hdr     -->\n"
"    <!--             MANDATORY IF search_in is equal to hdr             -->\n"
"    <!-- check_it  : if set to true, the call is marked as failed if    -->\n"
"    <!--             the regexp doesn't match.                          -->\n"
"    <!--             OPTIONAL - default value : false                   -->\n"
"    <!-- assign_to : contain the variable id (integer) or a list of     -->\n"
"    <!--             variable id which will be used to store the        -->\n"
"    <!--             result of the matching process between the regexp  -->\n"
"    <!--             and the message. This variable can be re-used at   -->\n"
"    <!--             a later time in the scenario using '[$n]' syntax   -->\n"
"    <!--             where n is the variable id.                        -->\n"
"    <!--             MANDATORY                                          -->\n"
"    <action>\n"
"      <ereg regexp=\"[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[:][0-9]{1,5}\" \n"
"            search_in=\"msg\" \n"
"            check_it=\"true\" \n"
"            assign_to=\"1\"/>\n"
"      <ereg regexp=\".*\" \n"
"            search_in=\"hdr\" \n"
"            header=\"Contact:\" \n"
"            check_it=\"true\" \n"
"            assign_to=\"6\"/>\n"
"      <ereg regexp=\"o=([[:alnum:]]*) ([[:alnum:]]*) ([[:alnum:]]*)\"\n"
"            search_in=\"msg\" \n"
"            check_it=\"true\" \n"
"            assign_to=\"3,4,5,8\"/>\n"
"    </action>\n"
"  </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag02[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 ACK\n"
"      retrievedIp: [$1]\n"
"      retrievedContact:[$6]\n"
"      retrievedSdpOrigin:[$3]\n"
"      retrievedSdpOrigin-username:[$4]\n"
"      retrievedSdpOrigin-session-id:[$5]\n"
"      retrievedSdpOrigin-version:[$8]\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- This delay can be customized by the -d command-line option       -->\n"
"  <!-- or by adding a 'milliseconds = \"value\"' option here.           -->\n"
"  <pause milliseconds = \"1000\"/>\n"
"\n"
"  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag02[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 2 BYE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"200\" crlf=\"true\" rtd=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- definition of the response time repartition table (unit is ms)   -->\n"
"  <ResponseTimeRepartition value=\"1000, 1040, 1080, 1120, 1160, 1200\"/>\n"
"\n"
"  <!-- definition of the call length repartition table (unit is ms)     -->\n"
"  <CallLengthRepartition value=\"1000, 1100, 1200, 1300, 1400\"/>\n"
"\n"
"</scenario>\n"
"\n",

/************* Default_scenario[3] ***************/
(char*)
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 3PCC - Controller - A side                         -->\n"
"<!--                                                                    -->\n"
"<!--             A              Controller               B              -->\n"
"<!--             |(1) INVITE no SDP  |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(2) 200 offer1     |                   |              -->\n"
"<!--             |==================>|                   |              -->\n"
"<!--             |                   |(3) INVITE offer1  |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |                   |(4) 200 OK answer1 |              -->\n"
"<!--             |                   |<==================|              -->\n"
"<!--             |                   |(5) ACK            |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |(6) ACK answer1    |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(7) RTP            |                   |              -->\n"
"<!--             |.......................................|              -->\n"
"<!--                                                                    -->\n"
"\n"
"<scenario name=\"3PCC Controller - A side\">\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag03[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 INVITE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"100\" optional=\"true\"> </recv>\n"
"  <recv response=\"180\" optional=\"true\"> </recv>\n"
"  <recv response=\"183\" optional=\"true\"> </recv>\n"
"  <recv response=\"200\" crlf=\"true\" start_rtd=\"true\">\n"
"    <action>\n"
"       <ereg regexp=\"Content-Type:.*\" \n"
"             search_in=\"msg\"  \n"
"             assign_to=\"1\"/> \n"
"    </action>\n"
"  </recv>\n"
"\n"
"  <sendCmd>\n"
"    <![CDATA[\n"
"      Call-ID: [call_id]\n"
"      [$1]\n"
"\n"
"     ]]>\n"
"  </sendCmd>\n"
"  \n"
"  <recvCmd>\n"
"    <action>\n"
"       <ereg regexp=\"Content-Type:.*\"  \n"
"             search_in=\"msg\"  \n"
"             assign_to=\"2\"/>\n"
"    </action>\n"
"  \n"
"  </recvCmd>\n"
"  \n"
"  <send rtd=\"true\">\n"
"    <![CDATA[\n"
"\n"
"      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag03[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 ACK\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      [$2]\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <pause milliseconds=\"1000\"/>\n"
"\n"
"  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag03[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 2 BYE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"200\" crlf=\"true\"> </recv>\n"
"\n"
"</scenario>\n"
"\n",

/************* Default_scenario[4] ***************/
(char*) 
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 3PCC - Controller - B side                         -->\n"
"<!--                                                                    -->\n"
"<!--             A              Controller               B              -->\n"
"<!--             |(1) INVITE no SDP  |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(2) 200 offer1     |                   |              -->\n"
"<!--             |==================>|                   |              -->\n"
"<!--             |                   |(3) INVITE offer1  |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |                   |(4) 200 OK answer1 |              -->\n"
"<!--             |                   |<==================|              -->\n"
"<!--             |                   |(5) ACK            |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |(6) ACK answer1    |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(7) RTP            |                   |              -->\n"
"<!--             |.......................................|              -->\n"
"<!--                                                                    -->\n"
"\n"
"\n"
"<scenario name=\"3PCC Controller - B side\">\n"
"\n"
"<recvCmd>\n"
"  <action>\n"
"       <ereg regexp=\"Content-Type:.*\"  \n"
"             search_in=\"msg\"  \n"
"             assign_to=\"1\"/>\n"
"  </action>\n"
"</recvCmd>\n"
"\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag04[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 INVITE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      [$1]\n"
"\n"
"     ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"100\" optional=\"true\"> </recv>\n"
"  <recv response=\"180\" optional=\"true\"> </recv>\n"
"  <recv response=\"183\" optional=\"true\"> </recv>\n"
"  <recv response=\"200\" crlf=\"true\">\n"
"    <action>\n"
"       <ereg regexp=\"Content-Type:.*\"  \n"
"             search_in=\"msg\"  \n"
"             assign_to=\"2\"/>\n"
"    </action>\n"
"  </recv>\n"
"  \n"
"    \n"
"  <send start_rtd=\"true\">\n"
"    <![CDATA[\n"
"\n"
"      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag04[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 ACK\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <sendCmd>\n"
"    <![CDATA[\n"
"      Call-ID: [call_id]\n"
"      [$2]\n"
"\n"
"    ]]>\n"
"  </sendCmd>\n"
" \n"
"  <pause milliseconds=\"1000\"/>\n"
"\n"
"\n"
"  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
"  <send retrans=\"500\" rtd=\"true\">\n"
"    <![CDATA[\n"
"\n"
"      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag04[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 2 BYE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"200\" crlf=\"true\">\n"
"  </recv>\n"
"\n"
"\n"
"</scenario>\n"
"\n",

/************* Default_scenario[5] ***************/
(char*) 
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 3PCC - A side emulator                             -->\n"
"<!--                                                                    -->\n"
"<!--             A              Controller               B              -->\n"
"<!--             |(1) INVITE no SDP  |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(2) 200 offer1     |                   |              -->\n"
"<!--             |==================>|                   |              -->\n"
"<!--             |                   |(3) INVITE offer1  |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |                   |(4) 200 OK answer1 |              -->\n"
"<!--             |                   |<==================|              -->\n"
"<!--             |                   |(5) ACK            |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |(6) ACK answer1    |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(7) RTP            |                   |              -->\n"
"<!--             |.......................................|              -->\n"
"<!--                                                                    -->\n"
"\n"
"\n"
"<scenario name=\"3PCC A side\">\n"
"  <recv request=\"INVITE\" crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag05[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[media_ip_type] [media_ip]\n"
"      t=0 0\n"
"      m=audio [media_port] RTP/AVP 0\n"
"      a=rtpmap:0 PCMU/8000\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv request=\"ACK\" rtd=\"true\" crlf=\"true\"> </recv>\n"
"\n"
"  <!-- RTP flow starts from here! -->\n"
"\n"
"  <recv request=\"BYE\" crlf=\"true\"> </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
"  <!-- able to retransmit it if we receive the BYE again.               -->\n"
"  <pause milliseconds=\"2000\"/>\n"
"\n"
"</scenario>\n"
"\n",

/************* Default_scenario[6] ***************/
(char*) 
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 3PCC - B side emulator                             -->\n"
"<!--                                                                    -->\n"
"<!--             A              Controller               B              -->\n"
"<!--             |(1) INVITE no SDP  |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(2) 200 offer1     |                   |              -->\n"
"<!--             |==================>|                   |              -->\n"
"<!--             |                   |(3) INVITE offer1  |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |                   |(4) 200 OK answer1 |              -->\n"
"<!--             |                   |<==================|              -->\n"
"<!--             |                   |(5) ACK            |              -->\n"
"<!--             |                   |==================>|              -->\n"
"<!--             |(6) ACK answer1    |                   |              -->\n"
"<!--             |<==================|                   |              -->\n"
"<!--             |(7) RTP            |                   |              -->\n"
"<!--             |.......................................|              -->\n"
"<!--                                                                    -->\n"
"\n"
"\n"
"\n"
"<scenario name=\"3PCC B side\">\n"
"  <recv request=\"INVITE\" crlf=\"true\"> </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag06[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[media_ip_type] [media_ip]\n"
"      t=0 0\n"
"      m=audio [media_port] RTP/AVP 0\n"
"      a=rtpmap:0 PCMU/8000\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv request=\"ACK\" rtd=\"true\" crlf=\"true\"> </recv>\n"
"\n"
"  <!-- RTP flow starts from here! -->\n"
"\n"
"  <recv request=\"BYE\"> </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
"  <!-- able to retransmit it if we receive the BYE again.               -->\n"
"  <pause milliseconds=\"2000\"/>\n"
"\n"
"</scenario>\n",

/************* Default_scenario[7] ***************/
(char*)
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 Sipp default 'branchc' scenario.                   -->\n"
"<!--                                                                    -->\n"
"\n"
"<scenario name=\"branch_client\">\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      REGISTER sip:CA.cym.com SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: ua1 <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07[call_number]\n"
"      To: ua1 <sip:ua1@nnl.cym:[local_port]>\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 REGISTER\n"
"      Contact: sip:ua1@[local_ip]:[local_port]\n"
"      Content-Length: 0\n"
"      Expires: 300\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- simple case - just jump over a line   -->\n"
"  <recv response=\"200\" rtd=\"true\" next=\"5\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"200\">\n"
"  </recv>\n"
"\n"
"  <label id=\"5\"/>\n"
"\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      INVITE sip:ua2@CA.cym.com SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: ua[call_number] <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07b[call_number]\n"
"      To: ua2 <sip:ua2@nnl.cym:[remote_port]>\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 INVITE\n"
"      Contact: sip:ua1@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[media_ip_type] [media_ip]\n"
"      t=0 0\n"
"      m=audio [media_port] RTP/AVP 0\n"
"      a=rtpmap:0 PCMU/8000\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"100\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"180\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"183\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- Do something different on an optional receive   -->\n"
"  <recv response=\"403\" optional=\"true\" next=\"1\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"200\">\n"
"    <action>\n"
"      <ereg regexp=\"ua25\"\n"
"            search_in=\"hdr\"\n"
"            header=\"From: \"\n"
"            assign_to=\"8\"/>\n"
"    </action>\n"
"  </recv>\n"
"\n"
"  <!-- set variable 8 above on 25th call, send the ACK but skip the pause for it   -->\n"
"  <send next=\"1\" test=\"8\">\n"
"    <![CDATA[\n"
"\n"
"      ACK sip:ua2@CA.cym.com SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: ua1 <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07b[call_number]\n"
"      To: ua2 <sip:ua2@nnl.cym:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 ACK\n"
"      Contact: sip:ua1@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <pause milliseconds=\"5000\"/>\n"
"\n"
"  <label id=\"1\"/>\n"
"\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      BYE sip:ua2@CA.cym.com SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: ua1 <sip:ua1@nnl.cym:[local_port]>;tag=[pid]SIPpTag07b[call_number]\n"
"      To: ua2 <sip:ua2@nnl.cym:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 2 BYE\n"
"      Contact: sip:ua1@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"200\" crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <pause milliseconds=\"4000\"/>\n"
"\n"
"  <!-- definition of the response time repartition table (unit is ms)   -->\n"
"  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
"\n"
"  <!-- definition of the call length repartition table (unit is ms)     -->\n"
"  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
"\n"
"</scenario>\n"
"\n",

/************* Default_scenario[8] ***************/
(char*)
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 Sipp default 'branchs' scenario.                   -->\n"
"<!--                                                                    -->\n"
"\n"
"<scenario name=\"branch_server\">\n"
"  <recv request=\"REGISTER\">\n"
"  </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag08[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"      Expires: 300\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- Set variable 3 if the ua is of the form ua2... -->\n"
"  <recv request=\"INVITE\" crlf=\"true\">\n"
"    <action>\n"
"      <ereg regexp=\"ua2\"\n"
"            search_in=\"hdr\"\n"
"            header=\"From: \"\n"
"            assign_to=\"3\"/>\n"
"    </action>\n"
"  </recv>\n"
"\n"
"  <!-- send 180 then trying if variable 3 is set -->\n"
"  <send next=\"1\" test=\"3\">\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 180 Ringing\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- if not, send a 403 error then skip to wait for a BYE -->\n"
"  <send next=\"2\">\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 403 Error\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <label id=\"1\"/>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 100 Trying\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:];tag=[pid]SIPpTag08b[call_number]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[media_ip_type] [media_ip]\n"
"      t=0 0\n"
"      m=audio [media_port] RTP/AVP 0\n"
"      a=rtpmap:0 PCMU/8000\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv request=\"ACK\"\n"
"        optional=\"true\"\n"
"        rtd=\"true\"\n"
"        crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <label id=\"2\"/>\n"
"\n"
"  <recv request=\"BYE\">\n"
"  </recv>\n"
"\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      SIP/2.0 200 OK\n"
"      [last_Via:]\n"
"      [last_From:]\n"
"      [last_To:]\n"
"      [last_Call-ID:]\n"
"      [last_CSeq:]\n"
"      Contact: <sip:[local_ip]:[local_port];transport=[transport]>\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- Keep the call open for a while in case the 200 is lost to be     -->\n"
"  <!-- able to retransmit it if we receive the BYE again.               -->\n"
"  <pause milliseconds=\"4000\"/>\n"
"\n"
"  <!-- Definition of the response time repartition table (unit is ms)   -->\n"
"  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
"\n"
"  <!-- Definition of the call length repartition table (unit is ms)     -->\n"
"  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
"\n"
"</scenario>\n"
"\n",

/* Although this scenario will not work without pcap play enabled, there is no
 * harm in including it in the binary anyway, because the user could have
 * dumped it and passed it with -sf. */

/************* Default_scenario[9] ***************/
(char*)
"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n"
"<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n"
"\n"
"<!-- This program is free software; you can redistribute it and/or      -->\n"
"<!-- modify it under the terms of the GNU General Public License as     -->\n"
"<!-- published by the Free Software Foundation; either version 2 of the -->\n"
"<!-- License, or (at your option) any later version.                    -->\n"
"<!--                                                                    -->\n"
"<!-- This program is distributed in the hope that it will be useful,    -->\n"
"<!-- but WITHOUT ANY WARRANTY; without even the implied warranty of     -->\n"
"<!-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      -->\n"
"<!-- GNU General Public License for more details.                       -->\n"
"<!--                                                                    -->\n"
"<!-- You should have received a copy of the GNU General Public License  -->\n"
"<!-- along with this program; if not, write to the                      -->\n"
"<!-- Free Software Foundation, Inc.,                                    -->\n"
"<!-- 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA             -->\n"
"<!--                                                                    -->\n"
"<!--                 Sipp 'uac' scenario with pcap (rtp) play           -->\n"
"<!--                                                                    -->\n"
"\n"
"<scenario name=\"UAC with media\">\n"
"  <!-- In client mode (sipp placing calls), the Call-ID MUST be         -->\n"
"  <!-- generated by sipp. To do so, use [call_id] keyword.                -->\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag09[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 INVITE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Type: application/sdp\n"
"      Content-Length: [len]\n"
"\n"
"      v=0\n"
"      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]\n"
"      s=-\n"
"      c=IN IP[local_ip_type] [local_ip]\n"
"      t=0 0\n"
"      m=audio [auto_media_port] RTP/AVP 8 101\n"
"      a=rtpmap:8 PCMA/8000\n"
"      a=rtpmap:101 telephone-event/8000\n"
"      a=fmtp:101 0-11,16\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"100\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <recv response=\"180\" optional=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- By adding rrs=\"true\" (Record Route Sets), the route sets         -->\n"
"  <!-- are saved and used for following messages sent. Useful to test   -->\n"
"  <!-- against stateful SIP proxies/B2BUAs.                             -->\n"
"  <recv response=\"200\" rtd=\"true\" crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- Packet lost can be simulated in any send/recv message by         -->\n"
"  <!-- by adding the 'lost = \"10\"'. Value can be [1-100] percent.       -->\n"
"  <send>\n"
"    <![CDATA[\n"
"\n"
"      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag09[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 1 ACK\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <!-- Play a pre-recorded PCAP file (RTP stream)                       -->\n"
"  <nop>\n"
"    <action>\n"
"      <exec play_pcap_audio=\"pcap/g711a.pcap\"/>\n"
"    </action>\n"
"  </nop>\n"
"\n"
"  <!-- Pause 8 seconds, which is approximately the duration of the      -->\n"
"  <!-- PCAP file                                                        -->\n"
"  <pause milliseconds=\"8000\"/>\n"
"\n"
"  <!-- Play an out of band DTMF '1'                                     -->\n"
"  <nop>\n"
"    <action>\n"
"      <exec play_pcap_audio=\"pcap/dtmf_2833_1.pcap\"/>\n"
"    </action>\n"
"  </nop>\n"
"\n"
"  <pause milliseconds=\"1000\"/>\n"
"\n"
"  <!-- The 'crlf' option inserts a blank line in the statistics report. -->\n"
"  <send retrans=\"500\">\n"
"    <![CDATA[\n"
"\n"
"      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0\n"
"      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n"
"      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag09[call_number]\n"
"      To: sut <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]\n"
"      Call-ID: [call_id]\n"
"      CSeq: 2 BYE\n"
"      Contact: sip:sipp@[local_ip]:[local_port]\n"
"      Max-Forwards: 70\n"
"      Subject: Performance Test\n"
"      Content-Length: 0\n"
"\n"
"    ]]>\n"
"  </send>\n"
"\n"
"  <recv response=\"200\" crlf=\"true\">\n"
"  </recv>\n"
"\n"
"  <!-- definition of the response time repartition table (unit is ms)   -->\n"
"  <ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\"/>\n"
"\n"
"  <!-- definition of the call length repartition table (unit is ms)     -->\n"
"  <CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\"/>\n"
"\n"
"</scenario>\n"
"\n"
};
