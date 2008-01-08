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
#include "stat.hpp"


#define MSG_TYPE_SENDCMD   0
#define MSG_TYPE_RECVCMD   1

#define MSG_TYPE_SEND      2
#define MSG_TYPE_RECV      3
#define MSG_TYPE_PAUSE     4
#define MSG_TYPE_NOP       5

#define MODE_CLIENT        0
#define MODE_SERVER        1

#define MODE_3PCC_CONTROLLER_A  2
#define MODE_3PCC_CONTROLLER_B  3   
#define MODE_3PCC_A_PASSIVE     4

/* 3pcc extended mode*/
#define MODE_MASTER             5 
#define MODE_MASTER_PASSIVE     6
#define MODE_SLAVE              7

#define OPTIONAL_TRUE      1
#define OPTIONAL_FALSE     0
#define OPTIONAL_GLOBAL    2

class message {

public:
  /* If this is a pause */
  CSample        *pause_distribution;
  int		 pause_variable;
  /* This string is used for the display screen. */
  char		 *pause_desc;
  /* Is this a final pause, intended for catching retransmissions? */
  bool		timewait;

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
  bool           advance_state;
  int            regexp_match;
  regex_t      * regexp_compile;

  /* Anyway */
  int            start_rtd;
  int            stop_rtd;
  bool           repeat_rtd;
  int		 counter;
  double         lost;
  int            crlf;
  bool           hide;
  char *	 display_str;
  int		 next;
  int            test;
  int            chance;/* 0=always, RAND_MAX+1=never (test rand() >= chance) */
  int		 on_timeout;

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

  SendingMessage *M_sendCmdData;
  unsigned long   M_nbCmdSent;
  unsigned long   M_nbCmdRecv;

  typedef enum {
      ContentLengthNoPresent = 0,
      ContentLengthValueZero,
      ContentLengthValueNoZero
  }ContentLengthFlag;
  
  ContentLengthFlag   content_length_flag ;

  char           *recv_response_for_cseq_method_list;
  int            start_txn;
  int            response_txn;

  message();
  ~message();
};

class scenario {
public:
  scenario(char * filename, int deflt);
  ~scenario();

  message **messages;
  int length;
  char *name;
  int duration;
  int maxTxnUsed;
  int_str_map txnRevMap;
  int unexpected_jump;
  int retaddr;
  int pausedaddr;

  void computeSippMode();

  bool rtd_stopped[MAX_RTD_INFO_LENGTH];
  int get_var(const char *varName, const char *what);
  int find_var(const char *varName, const char *what);

  CStat *stats;
  AllocVariableTable *allocVars;

private:

  /* The mapping of labels to IDs. */
  str_int_map labelMap;
  /* The string label representations. */
  int_str_map nextLabels;
  int_str_map ontimeoutLabels;

  str_int_map txnMap;
  int_int_map txnStarted;
  int_int_map txnResponses;


  bool found_timewait;
  bool rtd_started[MAX_RTD_INFO_LENGTH];

  void getBookKeeping();
  void getCommonAttributes();
  void getActionForThisMessage();
  void handle_arithmetic(CAction *tmpAction, char *what);
  void handle_rhs(CAction *tmpAction, char *what);

  void apply_labels();
  void init_rtds();
  void validate_rtds();
  void validate_variable_usage();
  void validate_txn_usage();

  int get_txn(const char *txnName, const char *what, bool start);
  int xp_get_var(const char *name, const char *what);
  int xp_get_var(const char *name, const char *what, int defval);

  void expand(int length);

  bool hidedefault;
};

/* There are external variable containing the current scenario */
extern scenario      *main_scenario;
extern scenario      *ooc_scenario;
extern scenario      *display_scenario;
extern int           toolMode;

extern message::ContentLengthFlag  content_length_flag;

void load_scenario(char * filename, 
                   int    deflt);

/* 3pcc extended mode */
void parse_slave_cfg();

void getActionForThisMessage();
CSample *parse_distribution(bool oldstyle);
int  createIntegerTable(char          * P_listeStr, 
                        unsigned int ** listeInteger, 
                        int           * sizeOfList);

int  isWellFormed(char * P_listeStr, 
                  int  * nombre);

/* String table functions. */
int createStringTable(char * inputString, char *** stringList, int *sizeOfList);
void freeStringTable(char ** stringList, int sizeOfList);



int find_scenario(const char *scenario);
extern char * default_scenario[11];

/* Useful utility functions for parsing integers, etc. */
long get_long(const char *ptr, const char *what);
unsigned long long get_long_long(const char *ptr, const char *what);
long get_time(const char *ptr, const char *what, int multiplier);
double get_double(const char *ptr, const char *what);
bool get_bool(const char *ptr, const char *what);
int time_string(double ms, char *res, int reslen);
int get_var(const char *varName, const char *what);

extern int get_cr_number(char *msg);

#endif
