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
 *           Peter Higginson
 *           JPeG
 *           Guillaume TEISSIER from FTR&D
*/

#ifndef __SCENARIO__
#define __SCENARIO__

#include "actions.hpp"
#include "variables.hpp"


#define SCEN_VARIABLE_SIZE 20

#ifdef __3PCC__
#define MSG_TYPE_SENDCMD   0
#define MSG_TYPE_RECVCMD   1
#endif

#define MSG_TYPE_SEND      2
#define MSG_TYPE_RECV      3
#define MSG_TYPE_PAUSE     4
#define MSG_TYPE_NOP       5

#define MODE_CLIENT        0
#define MODE_SERVER        1

#define METHOD_LIST_LENGTH      255

#ifdef __3PCC__
#define MODE_3PCC_CONTROLLER_A  2
#define MODE_3PCC_CONTROLLER_B  3   
#define MODE_3PCC_A_PASSIVE     4
#endif

class message {

public:

  /* If this is a pause */
  int            pause;    /* -1 => use 'duration' global. */
  int            pause_min;
  int            pause_max;

  /* Number of sessions in a pause */
  int            sessions; 

  /* should collect route set? */
  bool           bShouldRecordRoutes;

#ifdef _USE_OPENSSL
  /* should collect authentication info? */
  bool           bShouldAuthenticate;
#endif

  /* If this is a send */
  char         * send_scheme;
  unsigned int   retrans_delay;

  /* If this is a recv */
  unsigned int   recv_response;
  char         * recv_request;
  bool           optional;

  /* Anyway */
  bool           start_rtd;
  bool           stop_rtd;
  int            lost;
  int            crlf;
  unsigned int   next;
  int            test;

  /* Statistics */
  unsigned long   nb_sent;
  unsigned long   nb_recv;
  unsigned long   nb_sent_retrans;
  unsigned long   nb_recv_retrans;
  unsigned long   nb_timeout;
  unsigned long   nb_unexp;
  unsigned long   nb_lost;

  CActions*       M_actions;

  int             M_type;

#ifdef __3PCC__
  char*           M_sendCmdData;
  unsigned long   M_nbCmdSent;
  unsigned long   M_nbCmdRecv;
#endif

  typedef enum {
      ContentLengthNoPresent = 0,
      ContentLengthValueZero,
      ContentLengthValueNoZero
  }ContentLengthFlag;
  
  ContentLengthFlag   content_length_flag ;

  char           recv_response_for_cseq_method_list[METHOD_LIST_LENGTH];

  message();
  ~message();
};

/* There are external variable containing the current scenario */

extern message   *   scenario[SCEN_MAX_MESSAGES];
extern CVariable *   scenVariableTable[SCEN_VARIABLE_SIZE][SCEN_MAX_MESSAGES];
extern int           scenario_len;
extern char          scenario_name[255];
extern int           toolMode;
extern unsigned long scenario_duration; /* include -d option if used */

extern message::ContentLengthFlag  content_length_flag;

void load_scenario(char * filename, 
                   int    deflt);

void computeSippMode();
void getActionForThisMessage();
int  createIntegerTable(char          * P_listeStr, 
                        unsigned int ** listeInteger, 
                        int           * sizeOfList);

int  isWellFormed(char * P_listeStr, 
                  int  * nombre);



extern char * default_scenario[10];
extern unsigned int  labelArray[20];

#endif
