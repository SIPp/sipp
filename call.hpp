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

class call {

public:
  char         * id;
  unsigned int   number;
  unsigned int   tdm_map_number;

  unsigned int   msg_index;

  /* Last message sent from scenario step (retransmitions do not
   * change this index. Only message sent from the scenario
   * are kept in this index.) */
  unsigned int   last_send_index;
  char         * last_send_msg;

  /* Last received message (expected,  not optional, and not 
   * retransmitted) and the associated hash. Stills setted until a new
   * scenario steps sends a message */
  unsigned long    last_recv_hash;
  unsigned int     last_recv_index;
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
  unsigned int   nb_retrans;
  unsigned int   nb_last_delay;

  unsigned int   paused_until;

  unsigned long  start_time;
  unsigned long  start_time_rtd;

  bool           rtd_done;
  
  char           *peer_tag;
  
  int            call_socket;
  int            call_remote_socket;
  int            call_port;

  bool            poll_flag_write ;
  /* Index of the socket, only if the call locally created it
   * and must delete it on call deletion */
  int            pollset_index;
  
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
  CCallVariable * M_callVariableTable[SCEN_VARIABLE_SIZE];

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
  
  call(char * id, bool ipv6 = false);
  ~call();

  /* rc == true means call not deleted by processing */
  bool run(); 
  void formatNextReqUrl (char* next_req_url);
  void computeRouteSetAndRemoteTargetUri (char* rrList, char* contact, bool bRequestIncoming);
  bool process_incomming(char * msg);

  T_ActionResult executeAction(char * msg, int scenarioIndex);
  void  extractSubMessage(char * msg, char * matchingString, char* result);
  bool  rejectCall();

  // Get parameters from a [keyword]
  void getHexStringParam(char * dest, char * src, int * len);
  char* getKeywordParam(char * src, char * param, char * output);
 
  // P_index use for message index in scenario and ctrl of CRLF
  // P_index = -2 No ctrl of CRLF
  // P_index = -1 Add crlf to end of message
  char* createSendingMessage(char * src, int P_index);

  // method for the management of unexpected messages 
  bool  abortCall();                  // call aborted with BYE or CANCEL
  bool  checkInternalCmd(char* cmd);  // check of specific internal command
                                      // received from the twin socket
                                      // used for example to cancel the call
                                      // of the third party
  int   sendBuffer(char *buf);        // send a message out of a scenario 
                                      // execution
  int   checkAutomaticResponseMode(char * P_recv);
  bool  automaticResponseMode(int P_case, char* P_recv);

#ifdef __3PCC__
  int   sendCmdMessage(int index); // 3PCC
  bool  process_twinSippCom(char * msg); // 3PCC

  int   sendCmdBuffer(char* cmd); // for 3PCC, send a command out of a 
                                  // scenario execution

#endif

  typedef enum {
      InputFileSequentialOrder = 0,
      InputFileRandomOrder
  }InputFileUsage;

  static void readInputFileContents(const char* fileName);
  static void dumpFileContents(void);

  static void getFieldFromInputFile(const char* fieldName, int lineNum, char*& dest);
  static void getIpFieldFromInputFile(int fieldNr, int lineNum, char *dest);
  static int  m_counter; // used for sequential access

private:
  /* rc == true means call not deleted by processing */
  bool next();
  bool process_unexpected(char * msg);

  void  extract_cseq_method (char* responseCseq, char* msg);

  int   send_raw(char * msg, int index);
  char * send_scene(int index, int *send_status);
  void   connect_socket_if_needed();

  char * compute_cseq(char * src);
  char * get_header_field_code(char * msg, char * code);
  char * get_last_header(char * name);
  char * get_header_content(char* message, char * name);

  static InputFileUsage m_usage;

  int    m_localLineNumber;

  bool   use_ipv6;

  void   get_remote_media_addr(char * message);

#ifdef _USE_OPENSSL
  SSL_CTX   *m_ctx_ssl ;
  BIO       *m_bio     ;
#endif  

};

/* Call contexts interface */

typedef std::map<std::string, call *> call_map;
call_map * get_calls();

#ifdef _USE_OPENSSL
  call      * add_call(char * call_id , int P_pollset_indx, bool ipv6 = false);
#endif  

call * add_call(char * call_id , bool ipv6 = false);

call * add_call(bool ipv6 = false);
call * get_call(char *);
void   delete_call(char *);
void   delete_calls(void);

#endif
