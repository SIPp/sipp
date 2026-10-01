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
 *           Charles P. Wright from IBM Research
 *           Andy Aicken
 */

#ifndef __CALL__
#define __CALL__

#include <map>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include "scenario.hpp"
#include "stat.hpp"
#ifdef PCAPPLAY
#include "send_packets.h"
#endif
#include "rtpstream.hpp"
#include "srtp_channel.hpp"

#include <stdarg.h>

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#include "sip_parser.hpp"

struct remote_address;

#define UDP_MAX_RETRANS_INVITE_TRANSACTION 5
#define UDP_MAX_RETRANS_NON_INVITE_TRANSACTION 9
#define UDP_MAX_RETRANS MAX(UDP_MAX_RETRANS_INVITE_TRANSACTION, UDP_MAX_RETRANS_NON_INVITE_TRANSACTION)
#define DEFAULT_T2_TIMER_VALUE  4000
#define SIP_TRANSACTION_TIMEOUT 32000

/* Retransmission check methods. */
#define RTCHECK_FULL    1
#define RTCHECK_LOOSE   2


struct txnInstanceInfo {
    /* The branch of the request we sent that started it, none before */
    std::optional<std::string> txnID;
    unsigned long txnResp = 0;
    int ackIndex = 0;
    /* A transaction a received request starts: the request, its hash
     * and index, and the last response we sent in it */
    std::string request;
    unsigned long requestHash = 0;
    int requestIndex = 0;
    std::string response;
    int responseIndex = 0;
    /* The dialog of the message that started it, 0 before */
    int dialog = 0;
};

/* A dialog of a call whose scenario has dialog="N" messages */
struct call_dialog {
    /* Empty for dialog 1, the call's id, and until known */
    std::string call_id;
    /* The state of the dialog while another one is the call's */
    unsigned int cseq = 0;
    unsigned long int last_recv_invite_cseq = 0;
    std::optional<std::string> peer_tag;
    std::string last_recv_msg;
    std::optional<std::string> dialog_route_set;
    std::string next_req_url;
};

typedef enum
{
    eNoSession,
    eOfferReceived,
    eOfferSent,
    eOfferRejected,
    eAnswerReceived,
    eAnswerSent,
    eCompleted,
    eNumSessionStates
} SessionState;

class call : virtual public task, virtual public listener, public virtual socketowner
{
public:
    /* These are wrappers for various circumstances, (private) init does the real work. */
    //call(char * p_id, int userId, bool ipv6, bool isAutomatic);
    call(scenario *call_scenario, const char *p_id, bool use_ipv6, int userId, struct sockaddr_storage *dest);
    call(scenario *call_scenario, const char *p_id, SIPpSocket *socket, struct sockaddr_storage *dest);
    /* An outgoing call to dest; remote is its -round_robin address. */
    static call *add_call(int userId, bool ipv6, struct sockaddr_storage *dest,
                          remote_address *remote = nullptr);
    call(scenario * call_scenario, SIPpSocket *socket, struct sockaddr_storage *dest, const char * p_id, int userId, bool ipv6, bool isAutomatic, bool isInitCall);

    virtual ~call();

    virtual bool process_incoming(const char* msg, const struct sockaddr_storage* src = nullptr,
                                  SIPpSocket *socket = nullptr);
    virtual bool process_twinSippCom(char* msg);

    virtual bool run();
    /* Terminate this call, depending on action results and timewait. */
    virtual void terminate(CStat::E_Action reason);
    virtual bool tcpClose();
    virtual void tcpReconnected();
    /* The -3pcc twin connection is lost: fail the calls waiting for a
     * command. Returns how many failed. */
    static int close_twin_calls();
    /* Collect the <exec verify> commands that exited and wake the calls
     * that wait for them. */
    static void reap_verify_commands();
    /* The call that a request of a Call-ID no call has starts a new
     * dialog in, if one waits for it */
    static call *take_new_dialog(const char *msg);

    /* When should this call wake up? */
    virtual unsigned int wake();
    virtual bool  abortCall(bool writeLog); // call aborted with BYE or CANCEL
    bool  createsDialog();
    virtual void abort();

    /* Dump call info to error log. */
    virtual void dump();

    /* Automatic */
    enum T_AutoMode {
        E_AM_DEFAULT,
        E_AM_UNEXP_BYE,
        E_AM_UNEXP_CANCEL,
        E_AM_PING,
        E_AM_AA,
        E_AM_OOCALL
    };

    void setLastMsg(const char *msg);
    bool  automaticResponseMode(T_AutoMode P_case, const char* P_recv);
    const char *getLastReceived() {
        return last_recv_msg.empty() ? nullptr : last_recv_msg.c_str();
    };

    static void extract_cseq_method(char* responseCseq, size_t size, const char* msg);

private:
    /* This is the core constructor function. */
    void init(scenario * call_scenario, SIPpSocket *socket, struct sockaddr_storage *dest, const char * p_id, int userId, bool ipv6, bool isAutomatic, bool isInitCall);

    bool checkAckCSeq(const char* msg);

    /* This this call for initialization? */
    bool initCall;

    struct sockaddr_storage call_peer;

    /* A request that came from elsewhere than the call's destination (from
     * another address over UDP, on another connection otherwise) is
     * answered where it came from: the response with its top Via branch
     * goes there. Only the last few such requests are kept. */
    struct request_source {
        std::string branch;
        struct sockaddr_storage addr;
        SIPpSocket *socket; /* Held with ss_count; nullptr over UDP. */
    };
    void remember_request_source(const char *msg, const struct sockaddr_storage *src,
                                 SIPpSocket *socket);
    void forget_request_source(std::vector<request_source>::iterator it);

    /* The -round_robin address the call was made to, if any. */
    remote_address *remote;

    /* The state that most calls never have, made when first set: cold()
     * makes it, peekCold() reads it, or defaults if there is none. */
    struct call_cold {
        std::vector<request_source> request_sources;
        /* holds the route set, once recorded */
        std::optional<std::string> dialog_route_set;
        std::string next_req_url;
        /* holds the auth header and if the challenge was 401 or 407 */
        std::string dialog_authentication;
        int dialog_challenge_type = 0;
        unsigned int next_nonce_count = 1;
        /* A message that came before the call waited for one, kept for
         * its <recv>: empty when none, as a message is never empty */
        std::string queued_msg;
        bool queued_sdp_read = false;
        /* A command that came while the call waited for a SIP message,
         * kept for the <recvCmd> that follows. */
        std::string queued_cmd;
        /* The -trace_calldebug text */
        std::string debugBuffer;
    };
    std::unique_ptr<call_cold> cold_state;
    static const call_cold no_cold_state;
    call_cold &cold()
    {
        if (!cold_state) {
            cold_state = std::make_unique<call_cold>();
        }
        return *cold_state;
    }
    const call_cold &peekCold() const
    {
        return cold_state ? *cold_state : no_cold_state;
    }

    scenario *call_scenario;
    unsigned int   number;

public:
    static   int   maxDynamicId;    // max value for dynamicId; this value is reached !
    static   int   startDynamicId;  // offset for first dynamicId  FIXME:in CmdLine
    static   int   stepDynamicId;   // step of increment for dynamicId
    static   int   dynamicId;       // a counter for general use, incrementing  by  stepDynamicId starting at startDynamicId  wrapping at maxDynamicId  GLOBALY
protected:


    unsigned int   tdm_map_number;

    int            msg_index;
    int zombie;

    /* Last message sent from scenario step (retransmitions do not
     * change this index. Only message sent from the scenario
     * are kept in this index.) */
    int            last_send_index;
    /* As sent: it can hold a NUL */
    std::string last_send_msg;
    /* Is last_send_msg a request that a connection took, with no
     * response yet? */
    bool           last_send_unanswered;

    /* How long until sending this message times out. */
    unsigned int   send_timeout;

    /* Last received message (expected,  not optional, and not
     * retransmitted) and the associated hash. Stills setted until a new
     * scenario steps sends a message */
    unsigned long  last_recv_hash;
    int            last_recv_index;
    /* Empty until a message comes */
    std::string last_recv_msg;

    unsigned long int last_recv_invite_cseq;

    /* Recv message characteristics when we sent a valid message
     *  (scenario, no retrans) just after a valid reception. This was
     * a cause relationship, so the next time this cookie will be recvd,
     * we will retransmit the same message we sent this time */
    unsigned long  recv_retrans_hash;
    int            recv_retrans_recv_index;
    int            recv_retrans_send_index;
    /* The message to send again: last_send_msg while recv_retrans_last,
     * else one of its own, which a message sent after it leaves it */
    bool           recv_retrans_last;
    std::string recv_retrans_msg;
    void keepRecvRetransMsg();
    unsigned int   recv_timeout;

    /* cseq value for [cseq] keyword */
    unsigned int   cseq;

#ifdef PCAPPLAY
    int hasMediaInformation;
    /* The pcap plays of the call, per rtpstream_pcap_t stream, made on
     * first use: in a scenario with media only */
    std::unique_ptr<play_args_t> pcap_play_args[RTPSTREAM_PCAP_STREAMS];
    play_args_t& playArgs(rtpstream_pcap_t stream);
#endif

    rtpstream_callinfo_t rtpstream_callinfo;
    LazySrtpChannel _txUACAudio;
    LazySrtpChannel _rxUACAudio;
    LazySrtpChannel _txUASAudio;
    LazySrtpChannel _rxUASAudio;
    LazySrtpChannel _txUACVideo;
    LazySrtpChannel _rxUACVideo;
    LazySrtpChannel _txUASVideo;
    LazySrtpChannel _rxUASVideo;

    unsigned int   next_retrans;
    int            nb_retrans;
    unsigned int   nb_last_delay;

    unsigned int   paused_until;

    /* Waiting for the rtp_stream playback to end before the next message:
     * when to check it again (0: not waiting), when to give up (0: never)
     * and the message whose ontimeout label to jump to then */
    unsigned int   rtpstream_wait_check;
    unsigned int   rtpstream_wait_until;
    message       *rtpstream_wait_msg;

    /* How many <exec verify> commands the call waits for before its next
     * message */
    int            verify_pending;

    unsigned long  start_time;
    unsigned long long *start_time_rtd;
    bool           *rtd_done;

    /* The To tag of the last response that had one */
    std::optional<std::string> peer_tag;

    SIPpSocket *call_remote_socket;
    int            call_port;

    bool           call_established; // == true when the call is established
    // ie ACK received or sent
    // => init to false
    bool           ack_is_pending;   // == true if an ACK is pending
    // Needed to avoid abortCall sending a
    // CANCEL instead of BYE in some extreme
    // cases for 3PCC scenario.
    // => init to false
    bool           bye_after_peer_request; // abortCall() sends its BYE
    // after a request from the peer: [last_From] gives the To,
    // [last_To] the From and [last_cseq_number] our [cseq].

    /* Call Variable Table */
    VariableTable *M_callVariableTable;

    /* Our transaction IDs. */
    std::unique_ptr<txnInstanceInfo[]> transactions;

    /* result of execute action */
    enum T_ActionResult {
        E_AR_NO_ERROR = 0,
        E_AR_REGEXP_DOESNT_MATCH,
        E_AR_REGEXP_SHOULDNT_MATCH,
        E_AR_STOP_CALL,
        E_AR_CONNECT_FAILED,
        E_AR_HDR_NOT_FOUND,
        E_AR_TEST_DOESNT_MATCH,
        E_AR_TEST_SHOULDNT_MATCH,
        E_AR_STRCMP_DOESNT_MATCH,
        E_AR_STRCMP_SHOULDNT_MATCH,
        E_AR_RTPECHO_ERROR,
        E_AR_VERIFY_FAILED
    };

    /* Store the last action result to allow  */
    /* call to continue and mark it as failed */
    T_ActionResult last_action_result;

    /* rc == true means call not deleted by processing */
    void formatNextReqUrl(const char* contact);
    void computeRouteSetAndRemoteTargetUri(const char* rrList, const char* contact, bool bRequestIncoming);
    bool matches_scenario(unsigned int index, int reply_code, char * request, char * responsecseqmethod, char *txn);

    bool executeMessage(message *curmsg);
    T_ActionResult executeAction(const char* msg, message* message);
    bool  handleActionResult(T_ActionResult actionResult);
    std::string extractSubMessage(const char *msg, const char *matchingString, bool case_indep, int occurrence,
                                  bool headers);
    bool  rejectCall();
    double get_rhs(CAction *currentAction);
    double get_var_double(int varId);
    unsigned int recvTimeout(message *curmsg);
    void rtpstreamWaitNextCheck(unsigned long play_end);
    bool rtpstreamWaitTimeout();
    bool pastLastMessage();
    void startVerify(const char *command);
    void verifyDone(const char *command, int status);

    // P_index use for message index in scenario
    char* createSendingMessage(SendingMessage* src, int P_index=-1, int *msgLen=nullptr);
    char* createSendingMessage(char* src, int P_index, bool skip_sanity=false);
    char* createSendingMessage(SendingMessage*src, int P_index, char *msg_buffer, int buflen, int *msgLen=nullptr);
    /* The message in a string of its own, which the next one leaves alone */
    std::string createSendingString(SendingMessage *src, int P_index = -1);

    std::string buildSendingMessage(SendingMessage *src, int P_index, char *scratch, int buf_len, size_t reserve);

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

    T_AutoMode checkAutomaticResponseMode(char* P_recv);

    int   sendCmdMessage(message *curmsg); // 3PCC

    int   sendCmdBuffer(char* cmd); // for 3PCC, send a command out of a
    // scenario execution

    static void readInputFileContents(const char* fileName);
    static void dumpFileContents(void);

    int getFieldFromInputFile(const char* fileName, int field, SendingMessage *line, char* dest, int len);

    /* Associate a user with this call. */
    void setUser(int userId);

    /* Is this call just around for final retransmissions. */
    bool timewait;

    /* The dialogs, if the scenario has dialog="N" messages: the state of
     * the current one is in the call's members. incoming is the dialog
     * of the message being processed. */
    struct call_dialogs {
        std::map<int, call_dialog> dialogs;
        int current = 1;
        int incoming = 1;
        bool waits_new = false;
        std::list<call *>::iterator waiting;
    };
    std::unique_ptr<call_dialogs> dialogs;
    void switchDialog(int dialog);
    int msgDialog(const message *curmsg);
    int dialogOf(const char *msg);
    bool dialogKnown(int dialog);
    void setDialogCallId(int dialog, const char *call_id);
    const char *dialogCallId();
    std::vector<std::string> dialogIds();
    /* The dialog a request of a Call-ID no call has starts here, 0 if
     * none: the next message waited for is a <recv> of it */
    int newDialogFor(const char *msg);

    /* rc == true means call not deleted by processing */
    bool next();
    bool process_unexpected(const char* msg);
    void do_bookkeeping(message *curmsg);

    void  extract_transaction (char* txn, const char* msg);

    int   send_raw(const char * msg, int index, int len);
    char * send_scene(int index, int *send_status, int *msgLen);
    bool   connect_socket_if_needed();

    char * get_header_field_code(const char * msg, const char * code);
    char * get_last_header(const char * name);
    std::string get_last_request_uri();
    unsigned long hash(const char * msg);

    typedef std::map <std::string, int> file_line_map;
    file_line_map *m_lineNumber;
    int    userId;

    bool   use_ipv6;

    void get_remote_media_addr(std::string const &msg);

    void extract_rtp_remote_addr(const char* message, std::string &audio_host, int &audio_port,
                                 std::string &video_host, int &video_port);
    int extract_srtp_remote_info(const char * msg, SrtpInfoParams &pA, SrtpInfoParams &pV);
    void extract_rtp_remote_addr(const char* message);

    bool lost(int index);

    void setRtpEchoErrors(int value);
    int getRtpEchoErrors();

    void computeStat (CStat::E_Action P_action);
    void computeStat (CStat::E_Action P_action, unsigned long P_value);
    void computeStat (CStat::E_Action P_action, unsigned long P_value, int which);

    /* sdp_read: the message was queued for _unexp.main after its SDP was
     * read when it came; reading it again would count it twice. */
    bool process_incoming(const char* msg, const struct sockaddr_storage* src,
                          SIPpSocket *socket, bool sdp_read);
    void queue_up(const char *msg, bool sdp_read = false);
    bool recvCmdFollows(int index);

    int _callDebug(const char *fmt, ...) __attribute__((format(printf, 2, 3)));

    FILE* _srtpctxdebugfile;
    int logSrtpInfo(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
    void startUACSrtp(LazySrtpChannel& tx, LazySrtpChannel& rx, int payloadSize, const char* media);

    SessionState _sessionStateCurrent;
    SessionState _sessionStateOld;
    void setSessionState(SessionState state);
    SessionState getSessionStateCurrent();
    SessionState getSessionStateOld();
};


/* Default Message Functions. */
void init_default_messages();
void free_default_messages();
SendingMessage *get_default_message(const char *which);
void set_default_message(const char *which, char *message);

#endif
