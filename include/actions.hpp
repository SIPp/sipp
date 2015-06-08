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
 *  Authors : Benjamin GAUTHIER - 24 Mar 2004
 *            Joseph BANINO
 *            Olivier JACQUES
 *            Richard GAYRAUD
 *            From Hewlett Packard Company.
 */

#ifndef _CACTIONS
#define _CACTIONS

#include "variables.hpp"
#include "message.hpp"
class CSample;

#ifdef PCAPPLAY
#include "prepare_pcap.h"
#endif
#ifdef RTP_STREAM
#include "rtpstream.hpp"
#endif

#define MAX_ACTION_MESSAGE 3

class CAction
{
public:
    enum T_ActionType {
        E_AT_NO_ACTION = 0,
        E_AT_ASSIGN_FROM_REGEXP,
        E_AT_CHECK,
        E_AT_ASSIGN_FROM_VALUE,
        E_AT_ASSIGN_FROM_SAMPLE,
        E_AT_ASSIGN_FROM_STRING,
        E_AT_ASSIGN_FROM_INDEX,
        E_AT_ASSIGN_FROM_GETTIMEOFDAY,
        E_AT_JUMP,
        E_AT_LOOKUP,
        E_AT_INSERT,
        E_AT_REPLACE,
        E_AT_PAUSE_RESTORE,
        E_AT_LOG_TO_FILE,
        E_AT_LOG_WARNING,
        E_AT_LOG_ERROR,
        E_AT_EXECUTE_CMD,
        E_AT_EXEC_INTCMD,
        E_AT_VAR_ADD,
        E_AT_VAR_SUBTRACT,
        E_AT_VAR_MULTIPLY,
        E_AT_VAR_DIVIDE,
        E_AT_VAR_TEST,
        E_AT_VAR_TO_DOUBLE,
        E_AT_VAR_STRCMP,
        E_AT_VAR_TRIM,
        E_AT_VERIFY_AUTH,
        E_AT_SET_DEST,
        E_AT_CLOSE_CON,
#ifdef PCAPPLAY
        E_AT_PLAY_PCAP_AUDIO,
        E_AT_PLAY_PCAP_IMAGE,
        E_AT_PLAY_PCAP_VIDEO,
#endif
#ifdef RTP_STREAM
        E_AT_RTP_STREAM_PAUSE,
        E_AT_RTP_STREAM_RESUME,
        E_AT_RTP_STREAM_PLAY,
#endif
        E_AT_NB_ACTION
    };

    enum T_LookingPlace {
        E_LP_MSG = 0,
        E_LP_HDR,
        E_LP_BODY,
        E_LP_VAR,
        E_LP_NB_LOOKING_PLACE
    };

    enum T_Comparator {
        E_C_EQ,
        E_C_NE,
        E_C_GT,
        E_C_LT,
        E_C_GEQ,
        E_C_LEQ,
        E_C_NB_COMPARATOR
    };

    enum T_IntCmdType {
        E_INTCMD_INVALID = 0,
        E_INTCMD_STOPCALL,
        E_INTCMD_STOP_ALL,
        E_INTCMD_STOP_NOW
    };

    CAction(scenario* scenario)
      : M_action(E_AT_NO_ACTION),
        M_lookingPlace(E_LP_MSG),
        M_checkIt(false),
        M_checkItInverse(false),
        M_caseIndep(false),
        M_headersOnly(true),
        M_varId(0),
        M_varInId(0),
        M_varIn2Id(0),
        M_occurrence(1),
        M_lookingChar(NULL),
        M_IntCmd(E_INTCMD_INVALID),
        M_distribution(NULL),
        M_doubleValue(0),
        M_stringValue(NULL),
        M_scenario(scenario),
        M_nbSubVarId(0),
        M_maxNbSubVarId(0),
        M_subVarId(NULL),
        M_regExpSet(false),
        M_regularExpression(NULL)
    {
        for (int i = 0; i < MAX_ACTION_MESSAGE; i++) {
            M_message[i] = NULL;
            M_message_str[i] = NULL;
        }

#ifdef PCAPPLAY
        M_pcapArgs = NULL;
#endif

#ifdef RTP_STREAM
        memset(&M_rtpstream_actinfo, 0, sizeof(M_rtpstream_actinfo));
#endif
    }

    ~CAction();

    void afficheInfo();
    const char *comparatorToString(T_Comparator comp);
    bool compare(VariableTable *variableTable);

    char* getRegularExpression();
    SendingMessage* getMessage(int n = 0);  /* log specific function  */
#ifdef PCAPPLAY
    pcap_pkts* getPcapPkts(); /* send_packets specific function */
#endif
#ifdef RTP_STREAM
    rtpstream_actinfo_t* getRTPStreamActInfo(); /* return stored rtp stream playback params */
#endif

    void setLookingChar(char* P_value);
    void setAction(CAction P_action);
    void setRegExp(const char* P_value);  /* ereg specific function. */
    int executeRegExp(const char* P_string, VariableTable* P_callVarTable);
    void setMessage(char* P_value, int n = 0);  /* log specific function  */
#ifdef PCAPPLAY
    void setPcapArgs(char* P_value);  /* send_packets specific function */
    void setPcapArgs(pcap_pkts* P_value);  /* send_packets specific function */
#endif
#ifdef RTP_STREAM
    void setRTPStreamActInfo(char* P_value);  /* parse rtp stream playback values from string */
    void setRTPStreamActInfo(rtpstream_actinfo_t* P_value); /* copy stored rtp stream playback params */
#endif

    void setSubVarId(int P_value);
    int getSubVarId(int P_index);
    void setNbSubVarId(int P_value);
    int getNbSubVarId();
    int* getSubVarId();

    T_ActionType M_action;
    T_LookingPlace M_lookingPlace;
    T_Comparator M_comp;
    bool M_checkIt;
    bool M_checkItInverse;
    bool M_caseIndep;
    bool M_headersOnly;
    int M_varId;
    int M_varInId;
    int M_varIn2Id;
    int M_occurrence;
    char* M_lookingChar;
    T_IntCmdType M_IntCmd;

    /* sample specific member. */
    CSample* M_distribution;

    /* assign value specific member. */
    double M_doubleValue;
    /* strcmp specific member. */
    char* M_stringValue;

    /* what scenario we belong to. */
    scenario* M_scenario;

private:
    int M_nbSubVarId;
    int M_maxNbSubVarId;
    int* M_subVarId;

    /* log specific member  */
    SendingMessage* M_message[MAX_ACTION_MESSAGE];
    char* M_message_str[MAX_ACTION_MESSAGE];
    /* Our regular expression. */
    bool M_regExpSet;
    regex_t M_internalRegExp;
    char* M_regularExpression;
#ifdef PCAPPLAY
    /* pcap specific member */
    pcap_pkts* M_pcapArgs;
#endif
#ifdef RTP_STREAM
    rtpstream_actinfo_t M_rtpstream_actinfo;
#endif
    void setSubString(char** P_target, const char* P_source, int P_start, int P_stop);
};

class CActions
{
public:
    void afficheInfo();
    void setAction(CAction* P_action);
    void reset();
    int getActionSize();
    CAction* getAction(int i);
    CActions();
    ~CActions();

private:
    CAction ** M_actionList;
    int        M_nbAction;
};

#endif
