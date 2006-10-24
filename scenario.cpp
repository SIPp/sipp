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
 */

#include "sipp.hpp"

/************************ Class Constructor *************************/

message::message()
{
  //ugly memset(this, 0, sizeof(message));
  pause = 0;
  pause_min = 0;
  pause_max = 0;
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

  /* Anyway */
  start_rtd = 0;
  stop_rtd  = 0;
  lost = 0;
  crlf = 0;
  test = 0;
  next = 0;
  on_timeout = 0;

  /* Statistics */
  nb_sent = 0;
  nb_recv = 0;
  nb_sent_retrans = 0;
  nb_recv_retrans = 0;
  nb_timeout = 0;
  nb_unexp = 0;
  nb_lost = 0;

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

#ifdef __3PCC__
  if(M_sendCmdData != NULL)
    delete(M_sendCmdData);
  M_sendCmdData = NULL;
#endif
}

/******** Global variables which compose the scenario file **********/

message*      scenario[SCEN_MAX_MESSAGES];
CVariable*    scenVariableTable[SCEN_VARIABLE_SIZE][SCEN_MAX_MESSAGES];
int           scenario_len = 0;
char          scenario_name[255];
int           toolMode  = MODE_CLIENT;
unsigned long scenario_duration = 0;
unsigned int  labelArray[MAX_LABELS];

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
      unsigned int labelNumber = atoi(ptr);
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
            ERROR_P1("<recv> before <send> sequence without a mandatory message. Please remove one 'optional=true'.", scenario_file_cursor);
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
          scenario[scenario_len] -> retrans_delay = atol(ptr);
        }
      
        if(ptr = xp_get_value((char *)"rtd")) {
          if(!strcmp(ptr, (char *)"true")) {
            scenario[scenario_len] -> stop_rtd = true;
          }
        }

        if(ptr = xp_get_value((char *)"start_rtd")) {
          if(!strcmp(ptr, (char *)"true")) {
            scenario[scenario_len] -> start_rtd = true;
          }
        }

#ifdef PCAPPLAY
        getActionForThisMessage();
#endif

      } else if(!strcmp(elem, (char *)"recv")) {
        recv_count++;
        scenario[scenario_len]->M_type = MSG_TYPE_RECV;
        /* Received messages descriptions */
        if(ptr = xp_get_value((char *)"response")) {
          scenario[scenario_len] -> recv_response = atol(ptr);
          strcpy (scenario[scenario_len]->recv_response_for_cseq_method_list, method_list);
        }

        if(ptr = xp_get_value((char *)"request")) {
          scenario[scenario_len] -> recv_request = strdup(ptr);
        }
      
        if(ptr = xp_get_value((char *)"rtd")) {
          if(!strcmp(ptr, "true")) {
            scenario[scenario_len] -> stop_rtd = true;
          }
        }

        if(ptr = xp_get_value((char *)"start_rtd")) {
          if(!strcmp(ptr, (char *)"true")) {
            scenario[scenario_len] -> start_rtd = true;
          }
        }

        if (0 != (ptr = xp_get_value((char *)"optional"))) {
          if(!strcmp(ptr, "true")) {
            scenario[scenario_len] -> optional = OPTIONAL_TRUE;
            ++recv_opt_count;
          }
          if(!strcmp(ptr, "global")) {
            scenario[scenario_len] -> optional = OPTIONAL_GLOBAL;
            ++recv_opt_count;
          }
        }

        if (0 != (ptr = xp_get_value((char *)"timeout"))) {
          scenario[scenario_len]->retrans_delay = atol(ptr);
        }

        /* record the route set  */
        /* TODO disallow optional and rrs to coexist? */
        if(ptr = xp_get_value((char *)"rrs")) {
          if(!strcmp(ptr, "true")) {
            scenario[scenario_len] -> bShouldRecordRoutes = true;
          }
        }
      
#ifdef _USE_OPENSSL
        /* record the authentication credentials  */
        if(ptr = xp_get_value((char *)"auth")) {
          if(!strcmp(ptr, "true")) {
            scenario[scenario_len] -> bShouldAuthenticate = true;
          }
        }
#endif

        getActionForThisMessage();

      } else if(!strcmp(elem, "pause")) {
        if (recv_count) {
          if (recv_count != recv_opt_count) {
            recv_count = 0;
            recv_opt_count = 0;
          } else {
            ERROR_P1("<recv> before <send> sequence without a mandatory message. Please remove one 'optional=true'.", scenario_file_cursor);
          }
        }
        scenario[scenario_len]->M_type = MSG_TYPE_PAUSE;

	if(ptr = xp_get_value("milliseconds")) {
	  scenario[scenario_len] -> pause = get_long(ptr, "Pause milliseconds");
	  scenario_duration += scenario[scenario_len] -> pause;
	} else if(xp_get_value("min") || xp_get_value("max")) {
	  int isMin = !!xp_get_value("min");
	  int isMax = !!xp_get_value("max");

	  if (isMin && !isMax) {
	    ERROR("Max without min for a variable pause");
	  }
	  if (isMax && !isMin) {
	    ERROR("Min without max for a variable pause");
	  }

	  scenario[scenario_len] -> pause_min = get_long(xp_get_value("min"), "Pause minimum");
	  scenario[scenario_len] -> pause_max = get_long(xp_get_value("max"), "Pause maximum");

	  if (scenario[scenario_len] -> pause_max <= scenario[scenario_len] -> pause_min) {
	    ERROR("Min is greater than or equal to max in variable pause!");
	  }

          /* Update scenario duration with max duration */
          scenario_duration += scenario[scenario_len] -> pause_max;
        } else {
          scenario[scenario_len] -> pause = -1;
          scenario_duration += duration;
        }
        getActionForThisMessage();
      }
      else if(!strcmp(elem, "nop")) {
        /* Does nothing at SIP level, only meant to handle actions */
        scenario[scenario_len]->M_type = MSG_TYPE_NOP;
        getActionForThisMessage();
      }
#ifdef __3PCC__
      else if(!strcmp(elem, "recvCmd")) {
        if (recv_count) {
          if (recv_count != recv_opt_count) {
            recv_count = 0;
            recv_opt_count = 0;
          } else {
            ERROR_P1("<recv> before <send> sequence without a mandatory message. Please remove one 'optional=true'.", scenario_file_cursor);
          }
        }
        scenario[scenario_len]->M_type = MSG_TYPE_RECVCMD;
        getActionForThisMessage();

      } else if(!strcmp(elem, "sendCmd")) {
        if (recv_count) {
          if (recv_count != recv_opt_count) {
            recv_count = 0;
            recv_opt_count = 0;
          } else {
            ERROR_P1("<recv> before <send> sequence without a mandatory message. Please remove one 'optional=true'.", scenario_file_cursor);
          }
        }
        scenario[scenario_len]->M_type = MSG_TYPE_SENDCMD;
        /* Sent messages descriptions */
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
        scenario[scenario_len] -> lost = atol(ptr);
        lose_packets = 1;
      }

      if(ptr = xp_get_value((char *)"crlf")) {
        scenario[scenario_len] -> crlf = 1;
      }
      
      if ( 0 != ( ptr = xp_get_value((char *)"next") ) ) {
        scenario[scenario_len] -> next = atol(ptr);
         if ( 0 != ( ptr = xp_get_value((char *)"test") ) ) {
           scenario[scenario_len] -> test = atol(ptr);
         }
         else {
           scenario[scenario_len] -> test = -1;
         }
      } else {
        scenario[scenario_len] -> next = 0;
      }

      if (0 != (ptr = xp_get_value((char *)"ontimeout")) ) {
        if ((::scenario[scenario_len]->on_timeout = atol(ptr)) >= MAX_LABELS) {
            ERROR_P1("Ontimeout label larger than max supported %d", MAX_LABELS-1);
        }
      }
     
      if (++scenario_len >= SCEN_MAX_MESSAGES) {
          ERROR("Too many items in xml scenario file");
      }
    } /** end * Message case */
    xp_close_element();
  } // end while
}


// Determine in which mode the sipp tool has been 
// launched (client, server, 3pcc client, 3pcc server)
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
              toolMode = MODE_3PCC_A_PASSIVE;
            } else {
              toolMode = MODE_3PCC_CONTROLLER_A;
            }
            if(!twinSippMode)
              ERROR("sendCmd message found in scenario but no twin sipp"
                    " address has been passed! Use -3pcc option.\n");
            return;
          }
          isFirstMessageFound = false;
          break;

        case MSG_TYPE_RECVCMD:
          isRecvCmdFound = true;
          if(!isSendCmdFound)
            {
              toolMode  = MODE_3PCC_CONTROLLER_B;
              if(!twinSippMode)
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
  const int     MAX_ACTIONS(100);
  char *        actionElem;
  CActions      tmpActions(MAX_ACTIONS);
  CAction       tmpAction;
  int           tmpActionNumber(0);
  char *        currentRegExp = NULL;
  char *        buffer = NULL;
  unsigned int* currentTabVarId = NULL;
  int           currentNbVarId;
  unsigned int  recvScenarioLen;
  char * ptr;
  int           sub_currentNbVarId;

  tmpActions.reset();
  
  if(actionElem = xp_open_element(0)) {
    if(!strcmp(actionElem, "action")) {
      tmpActionNumber = 0;
      recvScenarioLen = 0;
      while(actionElem = xp_open_element(recvScenarioLen)) {
        if(!strcmp(actionElem, "ereg")) {
          if(ptr = xp_get_value((char *)"regexp")) {
            // keeping regexp expression in memory
            if(currentRegExp != NULL)
              delete[] currentRegExp;
            currentRegExp = new char[strlen(ptr)+1]; 
            buffer = new char[strlen(ptr)+1]; 
            xp_replace(ptr, buffer, "&lt;", "<");
            xp_replace(buffer, currentRegExp, "&gt;", ">");
            if(buffer != NULL)
              delete[] buffer;
            tmpAction.setVarType(CAction::E_VT_REGEXP);
            tmpAction.setActionType(CAction::E_AT_ASSIGN_FROM_REGEXP);
            
            if(ptr = xp_get_value((char *)"search_in")){
              if(!strcmp(ptr, (char *)"msg")) {
                tmpAction.setLookingPlace(CAction::E_LP_MSG);
                tmpAction.setLookingChar(NULL);
              } else if (!strcmp(ptr, (char *)"hdr")) {
                if(ptr = xp_get_value((char *)"header")) {
                  if(strlen(ptr) > 0) {
                    tmpAction.setLookingPlace(CAction::E_LP_HDR);
                    tmpAction.setLookingChar(ptr);
                  } else {
                    tmpAction.setLookingPlace(CAction::E_LP_MSG);
                    tmpAction.setLookingChar(NULL);
                  }
                } else {
                  tmpAction.setLookingPlace(CAction::E_LP_MSG);
                  tmpAction.setLookingChar(NULL);
                }
              } else {
                tmpAction.setLookingPlace(CAction::E_LP_MSG);
                tmpAction.setLookingChar(NULL);
              }
            } else {
              tmpAction.setLookingPlace(CAction::E_LP_MSG);
              tmpAction.setLookingChar(NULL);
            } // end if-else search_in
            
            if(ptr = xp_get_value((char *)"check_it")) {
              if(!strcmp(ptr, (char *)"true")) {
                tmpAction.setCheckIt(true);
              } else {
                tmpAction.setCheckIt(false);
              }
            } else {
              tmpAction.setCheckIt(false);
            }
            
            
            if(ptr = xp_get_value((char *)"assign_to")) {
              if(createIntegerTable(ptr, 
                                    &currentTabVarId, 
                                    &currentNbVarId) == 1) {

                if(currentTabVarId[0] <  SCEN_VARIABLE_SIZE) {
                    tmpAction.setVarId(currentTabVarId[0]);
                    /* and creating the associated variable */
                    if (scenVariableTable[currentTabVarId[0]][scenario_len] != NULL) {
                      delete(scenVariableTable[currentTabVarId[0]][scenario_len]);
                      scenVariableTable[currentTabVarId[0]][scenario_len] = NULL;
                    }
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
                  tmpAction.setNbSubVarId(sub_currentNbVarId);

                  for(int i=1; i<= sub_currentNbVarId; i++) {
                  if(currentTabVarId[i] <  SCEN_VARIABLE_SIZE) {
                      tmpAction.setSubVarId(currentTabVarId[i]);

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

                /* the action is well formed, adding it in the */
                /* tmpActionTable */
                tmpActions.setAction(tmpAction);
                tmpActionNumber++;
                delete[] currentTabVarId;
              }
            } else { // end "assign_to"
              ERROR("'ereg' action without 'assign_to' "
                    "argument (mandatory)");
            }
            if(currentRegExp != NULL) {
              delete[] currentRegExp;
            }
            currentRegExp = NULL;
          } else { // end if regexp
            ERROR("'ereg' action without 'regexp' argument (mandatory)");
          }
          
        } /* end !strcmp(actionElem, "ereg") */ else if(!strcmp(actionElem, "log")) {
          if(ptr = xp_get_value((char *)"message")) {
            tmpAction.setActionType(CAction::E_AT_LOG_TO_FILE);
            tmpAction.setMessage(ptr);
            /* the action is well formed, adding it in the */
            /* tmpActionTable */
            tmpActions.setAction(tmpAction);
            tmpActionNumber++;
          }
        } /* end !strcmp(actionElem, "log")  */ else if(!strcmp(actionElem, "exec")) {
          if(ptr = xp_get_value((char *)"command")) {
            tmpAction.setActionType(CAction::E_AT_EXECUTE_CMD);
            tmpAction.setCmdLine(ptr);
            /* the action is well formed, adding it in the */
            /* tmpActionTable */
            tmpActions.setAction(tmpAction);
            tmpActionNumber++;
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
            tmpAction.setActionType(CAction::E_AT_EXEC_INTCMD);
            tmpAction.setIntCmd(type);
            tmpActions.setAction(tmpAction);
            tmpActionNumber++;
#ifdef PCAPPLAY
          } else if (ptr = xp_get_value((char *) "play_pcap_audio")) {
            tmpAction.setPcapArgs(ptr);
            tmpAction.setActionType(CAction::E_AT_PLAY_PCAP_AUDIO);
            tmpActions.setAction(tmpAction);
            tmpActionNumber++;
            hasMedia = 1;
          } else if (ptr = xp_get_value((char *) "play_pcap_video")) {
            tmpAction.setPcapArgs(ptr);
            tmpAction.setActionType(CAction::E_AT_PLAY_PCAP_VIDEO);
            tmpActions.setAction(tmpAction);
            tmpActionNumber++;
            hasMedia = 1;
#endif
          } else {
              ERROR("illegal <exec> in the scenario\n");
          }
        }
        xp_close_element();
        recvScenarioLen++;
      } // end while
      
      // creation the action list for this message
      
      if(tmpActionNumber != 0) {
        if(scenario[scenario_len] != NULL) {
          if(scenario[scenario_len]->M_actions != NULL)
            delete(scenario[scenario_len]->M_actions);
          scenario[scenario_len]->M_actions 
            = new CActions(tmpActions);
        }
      } 
      } // end if "action"
      xp_close_element();
  }// end open element
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
#ifdef PCAPPLAY
"\n",

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
#endif
};
