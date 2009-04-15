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
 *	     Charles P. Wright from IBM Research
 *           Andy Aicken
 */

#ifndef __CALL__
#define __CALL__

#include <map>
#include <list>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include "scenario.hpp"
#include "stat.hpp"
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

/* Retransmission check methods. */
#define RTCHECK_FULL	1
#define RTCHECK_LOOSE	2

#ifdef __HPUX
  extern int createAuthHeader(char * user, char * password, char * method, char * uri, char * msgbody, char * auth, char * aka_OP, char * aka_AMF, char * aka_K, char * result);
#else
  extern "C" { extern int createAuthHeader(char * user, char * password, char * method, char * uri, char * msgbody, char * auth, char * aka_OP, char * aka_AMF, char * aka_K, char * result);  }
  extern "C" { int verifyAuthHeader(char * user, char * password, char * method, char * auth); }
#endif

struct txnInstanceInfo {
  char *txnID;
  unsigned long txnResp;
  int ackIndex;
};

class call : virtual public task, virtual public listener, public virtual socketowner {
public:
  /* These are wrappers for various circumstances, (private) init does the real work. */
  //call(char * p_id, int userId, bool ipv6, bool isAutomatic);
  call(char *p_id, bool use_ipv6, int userId, struct sockaddr_storage *dest);
  call(char *p_id, struct sipp_socket *socket, struct sockaddr_storage *dest);
  static call *add_call(int userId, bool ipv6, struct sockaddr_storage *dest);
  call(scenario * call_scenario, struct sipp_socket *socket, struct sockaddr_storage *dest, char * p_id, int userId, bool ipv6, bool isAutomatic, bool isInitCall);

  virtual ~call();

  virtual bool process_incoming(char * msg, struct sockaddr_storage *src = NULL);
  virtual bool  process_twinSippCom(char * msg);

  virtual bool run();
  /* Terminate this call, depending on action results and timewait. */
  virtual void terminate(CStat::E_Action reason);
  virtual void tcpClose();

  /* When should this call wake up? */
  virtual unsigned int wake();
  virtual bool  abortCall(bool writeLog); // call aborted with BYE or CANCEL
  virtual void abort();

  /* Dump call info to error log. */
  virtual void dump();

  /* Automatic */
  enum T_AutoMode
    {
      E_AM_DEFAULT,
      E_AM_UNEXP_BYE,
      E_AM_UNEXP_CANCEL,
      E_AM_PING,
      E_AM_AA,
      E_AM_OOCALL,
    };

  void setLastMsg(const char *msg);
  bool  automaticResponseMode(T_AutoMode P_case, char* P_recv);
  const char *getLastReceived() { return last_recv_msg; };

private:
  /* This is the core constructor function. */
  void init(scenario * call_scenario, struct sipp_socket *socket, struct sockaddr_storage *dest, char * p_id, int userId, bool ipv6, bool isAutomatic, bool isInitCall);
  /* This this call for initialization? */
  bool initCall;

  struct sockaddr_storage call_peer;

  scenario *call_scenario;
  unsigned int   number;

public:
  static   int   maxDynamicId;    // max value for dynamicId; this value is reached !
  static   int   startDynamicId;  // offset for first dynamicId  FIXME:in CmdLine
  static   int   stepDynamicId;   // step of increment for dynamicId
  static   int   dynamicId;       // a counter for general use, incrementing  by  stepDynamicId starting at startDynamicId  wrapping at maxDynamicId  GLOBALY
private:


  unsigned int   tdm_map_number;

  int		msg_index;
  int		zombie;

  /* Last message sent from scenario step (retransmitions do not
   * change this index. Only message sent from the scenario
   * are kept in this index.) */
  int		 last_send_index;
  char         * last_send_msg;
  int        last_send_len;

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
  int   recv_retrans_recv_index;
  int   recv_retrans_send_index;
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
  unsigned long long *start_time_rtd;
  bool           *rtd_done;

  char           *peer_tag;
  
  struct sipp_socket *call_remote_socket;
  int            call_port;

  void         * comp_state;

  int            deleted;

  bool           call_established; // == true when the call is established
                                   // ie ACK received or sent
                                   // => init to false
  bool           ack_is_pending;   // == true if an ACK is pending
                                   // Needed to avoid abortCall sending a 
                                   // CANCEL instead of BYE in some extreme
                                   // cases for 3PCC scenario.
                                   // => init to false

  /* Call Variable Table */
  VariableTable *M_callVariableTable;

  /* Our transaction IDs. */
  struct txnInstanceInfo *transactions;

  /* result of execute action */
  enum T_ActionResult
    {
      E_AR_NO_ERROR = 0,
      E_AR_REGEXP_DOESNT_MATCH,
      E_AR_REGEXP_SHOULDNT_MATCH,
      E_AR_STOP_CALL,
      E_AR_CONNECT_FAILED,
      E_AR_HDR_NOT_FOUND
    };

  /* Store the last action result to allow  */
  /* call to continue and mark it as failed */
  T_ActionResult last_action_result;
  
  /* rc == true means call not deleted by processing */
  void formatNextReqUrl (char* next_req_url);
  void computeRouteSetAndRemoteTargetUri (char* rrList, char* contact, bool bRequestIncoming);
  bool matches_scenario(unsigned int index, int reply_code, char * request, char * responsecseqmethod, char *txn);

  bool executeMessage(message *curmsg);
  T_ActionResult executeAction(char * msg, message *message);
  void  extractSubMessage(char * msg, char * matchingString, char* result, bool case_indep, 
							     int occurrence, bool headers); 
  bool  rejectCall();
  double get_rhs(CAction *currentAction);

  // P_index use for message index in scenario and ctrl of CRLF
  // P_index = -2 No ctrl of CRLF
  // P_index = -1 Add crlf to end of message
  char* createSendingMessage(SendingMessage *src, int P_index, int *msgLen=NULL);
  char* createSendingMessage(char * src, int P_index, bool skip_sanity = false);
  char* createSendingMessage(SendingMessage *src, int P_index, char *msg_buffer, int buflen, int *msgLen=NULL);

  // method for the management of unexpected messages 
  bool  checkInternalCmd(char* cmd);  // check of specific internal command
                                      // received from the twin socket
                                      // used for example to cancel the call
                                      // of the third party
  bool  check_peer_src(char* msg,
		int search_index);    // 3pcc extended mode:check if 
				      // the twin message received
				      // comes from the expected sender
  void   sendBuffer(char *buf, int len = 0);     // send a message out of a scenario
                                      // execution

  T_AutoMode  checkAutomaticResponseMode(char * P_recv);

  int   sendCmdMessage(message *curmsg); // 3PCC

  int   sendCmdBuffer(char* cmd); // for 3PCC, send a command out of a 
                                  // scenario execution

  static void readInputFileContents(const char* fileName);
  static void dumpFileContents(void);

  void getFieldFromInputFile(const char* fileName, int field, SendingMessage *line, char*& dest);

  /* Associate a user with this call. */
  void setUser(int userId);

  /* Is this call just around for final retransmissions. */
  bool timewait;

  /* rc == true means call not deleted by processing */
  bool next();
  bool process_unexpected(char * msg);
  void do_bookkeeping(message *curmsg);

  void  extract_cseq_method (char* responseCseq, char* msg);
  void  extract_transaction (char* txn, char* msg);

  int   send_raw(char * msg, int index, int len);
  char * send_scene(int index, int *send_status, int *msgLen);
  bool   connect_socket_if_needed();

  char * compute_cseq(char * src);
  char * get_header_field_code(char * msg, char * code);
  char * get_last_header(char * name);
  char * get_header_content(char* message, char * name);
  char * get_header(char* message, char * name, bool content);
  char * get_first_line(char* message);
  char * get_last_request_uri();
  unsigned long hash(char * msg);

  typedef std::map <std::string, int> file_line_map;
  file_line_map *m_lineNumber;
  int    userId;

  bool   use_ipv6;

  void   get_remote_media_addr(char * message);

  bool lost(int index);

  void computeStat (CStat::E_Action P_action);
  void computeStat (CStat::E_Action P_action, unsigned long P_value);
  void computeStat (CStat::E_Action P_action, unsigned long P_value, int which);


  void queue_up(char *msg);
  char *queued_msg;


#ifdef _USE_OPENSSL
  SSL_CTX   *m_ctx_ssl ;
  BIO       *m_bio     ;
#endif

  int _callDebug(char *fmt, ...);
  char *debugBuffer;
  int debugLength;
};


/* Default Message Functions. */
void init_default_messages();
void free_default_messages();
SendingMessage *get_default_message(const char *which);
void set_default_message(const char *which, char *message);

#endif
