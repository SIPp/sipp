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

#include <map>
#include <sys/socket.h>
#include "actions.hpp"
#include "variables.hpp"
#include "message.hpp"


/* MAX_RTD_INFO_LENGTH defines the number of RTD begin and end points a single
 * call can have.  If you need more than five, you can increase this number,
 * but you also need to insert entries into the E_CounterName enum in stat.hpp.
 */
#define MAX_RTD_INFO_LENGTH 5

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

/* 3pcc extended mode*/
#define MODE_MASTER             5 
#define MODE_MASTER_PASSIVE     6
#define MODE_SLAVE              7
#endif

#define OPTIONAL_TRUE      1
#define OPTIONAL_FALSE     0
#define OPTIONAL_GLOBAL    2
#define MAX_LABELS       100

class message {

public:
  /* If this is a pause */
  CSample        *pause_distribution;
  int		 pause_variable;
  /* This string is used for the display screen. */
  char		 *pause_desc;


  /* Number of sessions in a pause */
  int            sessions; 

  /* should collect route set? */
  bool           bShouldRecordRoutes;

#ifdef _USE_OPENSSL
  /* should collect authentication info? */
  bool           bShouldAuthenticate;
#endif

  /* If this is a send */
  SendingMessage *send_scheme;
  unsigned int   retrans_delay;
  /* The receive/send timeout. */
  unsigned int   timeout;

 /* 3pcc extended mode: if this is a sendCmd */
  char         * peer_dest;

 /* 3pcc extended mode: if this is a recvCmd */
  char         * peer_src;

  /* If this is a recv */
  int   	 recv_response;
  char         * recv_request;
  int            optional;
  int            regexp_match;
  regex_t      * regexp_compile;

  /* Anyway */
  int            start_rtd;
  int            stop_rtd;
  bool           repeat_rtd;
  int		 counter;
  double         lost;
  int            crlf;
  unsigned int   next;
  int            test;
  int            chance;/* 0=always, RAND_MAX+1=never (test rand() >= chance) */
  unsigned int   on_timeout;

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
extern CVariable *** scenVariableTable;
extern bool	     *variableUsed;
extern int	     maxVariableUsed;
extern int	     scenario_len;
extern char          scenario_name[255];
extern int           toolMode;
extern bool          rtd_stopped[MAX_RTD_INFO_LENGTH];
extern bool          rtd_started[MAX_RTD_INFO_LENGTH];


extern unsigned long scenario_duration; /* include -d option if used */

extern message::ContentLengthFlag  content_length_flag;

void load_scenario(char * filename, 
                   int    deflt);

/* 3pcc extended mode */
void parse_slave_cfg();

void computeSippMode();
void getActionForThisMessage();
CSample *parse_distribution(bool oldstyle);
int  createIntegerTable(char          * P_listeStr, 
                        unsigned int ** listeInteger, 
                        int           * sizeOfList);

int  isWellFormed(char * P_listeStr, 
                  int  * nombre);



int find_scenario(const char *scenario);
extern char * default_scenario[10];
extern unsigned int  labelArray[MAX_LABELS];

/* Useful utility functions for parsing integers, etc. */
long get_long(const char *ptr, const char *what);
long get_time(const char *ptr, const char *what, int multiplier);
double get_double(const char *ptr, const char *what);
bool get_bool(const char *ptr, const char *what);
int time_string(double ms, char *res, int reslen);

extern int get_cr_number(char *msg);

#endif
