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

#ifndef __CALL__
#define __CALL__

#include <map>
#include <list>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include "scenario.hpp"
#ifdef _USE_OPENSSL
#include "sslcommon.h"
#endif
#ifdef PCAPPLAY
#include "send_packets.h"
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#define MAX_HEADER_LEN 2049
#define UDP_MAX_RETRANS_INVITE_TRANSACTION 5
#define UDP_MAX_RETRANS_NON_INVITE_TRANSACTION 9
#define UDP_MAX_RETRANS MAX(UDP_MAX_RETRANS_INVITE_TRANSACTION, UDP_MAX_RETRANS_NON_INVITE_TRANSACTION)
#define MAX_SUB_MESSAGE_LENGTH  2049
#define DEFAULT_T2_TIMER_VALUE  4000
#define SIP_TRANSACTION_TIMEOUT 32000

#ifdef __HPUX
  extern int createAuthHeader(char * user, char * password, char * method, char * uri, char * msgbody, char * auth, char * aka_OP, char * aka_AMF, char * aka_K, char * result);
#else
  extern "C" { extern int createAuthHeader(char * user, char * password, char * method, char * uri, char * msgbody, char * auth, char * aka_OP, char * aka_AMF, char * aka_K, char * result);  }
#endif

/* Forward declaration of call, so that we can define the call_list iterator
 * that is referenced from call. */
class call;

typedef std::list<call *> call_list;

/* This arrangement of wheels lets us support up to 32 bit timers.
 *
 * If we were to put a minimum bound on timer_resol (or do some kind of dynamic
 * allocation), then we could reduce the level one order by a factor of
 * timer_resol. */
#define LEVEL_ONE_ORDER 12
#define LEVEL_TWO_ORDER 10
#define LEVEL_THREE_ORDER 10
#define LEVEL_ONE_SLOTS (1 << LEVEL_ONE_ORDER)
#define LEVEL_TWO_SLOTS (1 << LEVEL_TWO_ORDER)
#define LEVEL_THREE_SLOTS (1 << LEVEL_THREE_ORDER)

/* A time wheel structure as defined in Varghese and Lauck's 1996 journal
 * article (based on their 1987 SOSP paper). */
class timewheel {
public:
	timewheel();

	int expire_paused_calls();
	/* Add a paused call and increment count. */
	void add_paused_call(call *call, bool increment);
	void remove_paused_call(call *call);
	int size();

private:
	/* How many calls are in this wheel. */
	int count;

	unsigned int wheel_base;

	/* The actual wheels. */
	call_list wheel_one[LEVEL_ONE_SLOTS];
	call_list wheel_two[LEVEL_TWO_SLOTS];
	call_list wheel_three[LEVEL_THREE_SLOTS];

	/* Calls that are paused indefinitely. */
	call_list forever_list;

	/* Turn a call into a list (based on wakeup). */
	call_list *call2list(call *call);
};

class call {
public:
  char         * id;
  unsigned int   number;
  unsigned int   tdm_map_number;

  int		msg_index;

  /* Last message sent from scenario step (retransmitions do not
   * change this index. Only message sent from the scenario
   * are kept in this index.) */
  int		 last_send_index;
  char         * last_send_msg;

  /* How long until sending this message times out. */
  unsigned int   send_timeout;

  /* Last received message (expected,  not optional, and not 
   * retransmitted) and the associated hash. Stills setted until a new
   * scenario steps sends a message */
  unsigned long    last_recv_hash;
  int		   last_recv_index;
  char           * last_recv_msg;

  /* Recv message characteristics when we sent a valid message
   *  (scneario, no retrans) just after a valid reception. This was
   * a cause relationship, so the next time this cookie will be recvd,
   * we will retransmit the same message we sent this time */
  unsigned long  recv_retrans_hash;
  unsigned int   recv_retrans_recv_index;
  unsigned int   recv_retrans_send_index;
  unsigned int   recv_timeout;

  /* holds the route set */
  char         * dialog_route_set;
  char         * next_req_url;

  /* cseq value for [cseq] keyword */
  unsigned int   cseq;

#ifdef PCAPPLAY
  int hasMediaInformation;
  pthread_t media_thread;
  play_args_t play_args_a;
  play_args_t play_args_v;
#endif

  
#ifdef _USE_OPENSSL
  /* holds the auth header and if the challenge was 401 or 407 */
  char         * dialog_authentication;
  int            dialog_challenge_type;
#endif

  unsigned int   next_retrans;
  int   	 nb_retrans;
  unsigned int   nb_last_delay;

  unsigned int   paused_until;

  unsigned long  start_time;
  unsigned long  long start_time_rtd[MAX_RTD_INFO_LENGTH];

  bool           rtd_done[MAX_RTD_INFO_LENGTH];
  
  char           *peer_tag;
  
  struct sipp_socket *call_remote_socket;
  int            call_port;

  void         * comp_state;

  int            deleted;

  bool           call_established; // == true when the call is established
                                   // ie ACK received or sent
                                   // => init to false
  bool           count_in_stats;   // == true if normal call to be counted
                                   // in statistics
  bool           ack_is_pending;   // == true if an ACK is pending
                                   // Needed to avoid abortCall sending a 
                                   // CANCEL instead of BYE in some extreme
                                   // cases for 3PCC scenario.
                                   // => init to false

  /* Call Variable Table */
  CCallVariable ** M_callVariableTable;

  /* result of execute action */
  enum T_ActionResult
    {
      E_AR_NO_ERROR = 0,
      E_AR_REGEXP_DOESNT_MATCH,
      E_AR_STOP_CALL,
      E_AR_HDR_NOT_FOUND
    };

  /* Store the last action result to allow  */
  /* call to continue and mark it as failed */
  T_ActionResult last_action_result;
  
  call(char * id, int userId, bool ipv6);
  call (char *id, int userId, bool ipv6 , bool isAutomatic);
  ~call();

  /* rc == true means call not deleted by processing */
  bool run(); 
  void formatNextReqUrl (char* next_req_url);
  void computeRouteSetAndRemoteTargetUri (char* rrList, char* contact, bool bRequestIncoming);
  bool matches_scenario(unsigned int index, int reply_code, char * request, char * responsecseqmethod);
  bool process_incoming(char * msg);

  T_ActionResult executeAction(char * msg, int scenarioIndex);
  void  extractSubMessage(char * msg, char * matchingString, char* result, bool case_indep, 
							     int occurrence, bool headers); 
  bool  rejectCall();
  double get_rhs(CAction *currentAction);

  // P_index use for message index in scenario and ctrl of CRLF
  // P_index = -2 No ctrl of CRLF
  // P_index = -1 Add crlf to end of message
  char* createSendingMessage(SendingMessage *src, int P_index);
  char* createSendingMessage(char * src, int P_index, bool skip_sanity = false);

  // method for the management of unexpected messages 
  bool  abortCall();                  // call aborted with BYE or CANCEL
  bool  checkInternalCmd(char* cmd);  // check of specific internal command
                                      // received from the twin socket
                                      // used for example to cancel the call
                                      // of the third party
  bool  check_peer_src(char* msg,
		int search_index);    // 3pcc extended mode:check if 
				      // the twin message received
				      // comes from the expected sender
  void   sendBuffer(char *buf);        // send a message out of a scenario
                                      // execution
  int   checkAutomaticResponseMode(char * P_recv);
  bool  automaticResponseMode(int P_case, char* P_recv);

#ifdef __3PCC__
  int   sendCmdMessage(int index); // 3PCC
  bool  process_twinSippCom(char * msg); // 3PCC

  int   sendCmdBuffer(char* cmd); // for 3PCC, send a command out of a 
                                  // scenario execution

#endif

  static void readInputFileContents(const char* fileName);
  static void dumpFileContents(void);

  void getFieldFromInputFile(const char* fileName, int field, char*& dest);
  void getFieldFromInputFile(const char* keyword, char*& dest);

  /* Associate/Dissociate this call with a socket. */
  struct sipp_socket *associate_socket(struct sipp_socket *socket);
  struct sipp_socket *dissociate_socket();

  /* Associate a user with this call. */
  void setUser(int userId);

  /* Is this call paused or running? */
  bool running;
  /* If we are running, the iterator to remove us from the running list. */
  call_list::iterator runit;
  /* If we are paused, the iterator to remove us from the paused list. */
  call_list::iterator pauseit;

private:
  /* rc == true means call not deleted by processing */
  bool next();
  bool process_unexpected(char * msg);
  void do_bookkeeping(int index);

  void  extract_cseq_method (char* responseCseq, char* msg);

  int   send_raw(char * msg, int index);
  char * send_scene(int index, int *send_status);
  void   connect_socket_if_needed();

  char * compute_cseq(char * src);
  char * get_header_field_code(char * msg, char * code);
  char * get_last_header(char * name);
  char * get_header_content(char* message, char * name);
  char * get_header(char* message, char * name, bool content);
  char * get_first_line(char* message);
  char * get_last_request_uri();

  typedef std::map <std::string, int> file_line_map;
  file_line_map *m_lineNumber;
  int    userId;

  bool   use_ipv6;
  struct sipp_socket *call_socket;

  void   get_remote_media_addr(char * message);

#ifdef _USE_OPENSSL
  SSL_CTX   *m_ctx_ssl ;
  BIO       *m_bio     ;
#endif
};

/* Call contexts interface */

typedef std::pair<std::string, call *> string_call_pair;
typedef std::map<std::string, call *> call_map;
call_map * get_calls();
call_list * get_running_calls();

/* These are wrappers for various circumstances. */
call * add_call(int userId, bool ipv6);
call * add_call(char * call_id , bool ipv6, int userId);
call * add_call(char * call_id , struct sipp_socket *socket);
call * add_call(char * call_id , struct sipp_socket *socket, bool isAutomatic);
/* This is the core function. */
call * add_call(char * call_id , bool ipv6, int userId, bool isAutomatic);

call * get_call(char *);
void   delete_call(char *);
void   delete_calls(void);

void add_running_call(call *call);
bool remove_running_call(call *call);
int expire_paused_calls();
int paused_calls_count();
void remove_paused_call(call *call);

typedef std::pair<struct sipp_socket *,call_map *> socket_map_pair;

typedef std::map<struct sipp_socket *, void *> socket_call_map_map;
call_list *get_calls_for_socket(struct sipp_socket *socket);
void add_call_to_socket(struct sipp_socket *socket, call *call);
void remove_call_from_socket(struct sipp_socket *socket, call *call);

#endif
