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
 *            Guillaume Teissier from FTR&D
 */

#include "sipp.hpp"
#include "fileutil.h"
#include <assert.h>
#ifdef PCAPPLAY
#include "prepare_pcap.h"
#endif


static const char* strIntCmd(CAction::T_IntCmdType type)
{
    switch (type) {
    case CAction::E_INTCMD_STOPCALL:
        return "stop_call";
    case CAction::E_INTCMD_STOP_ALL:
        return "stop_gracefully";
    case CAction::E_INTCMD_STOP_NOW:
        return "stop_now";

    default:
    case CAction::E_INTCMD_INVALID:
        return "invalid";
    }
    return "invalid";
}

const char * CAction::comparatorToString(T_Comparator comp)
{
    switch(comp) {
    case E_C_EQ:
        return "==";
    case E_C_NE:
        return "!=";
    case E_C_GT:
        return ">";
    case E_C_LT:
        return "<";
    case E_C_GEQ:
        return ">=";
    case E_C_LEQ:
        return "<=";
    default:
        return "invalid";
    }
}

bool CAction::compare(VariableTable *variableTable)
{
    double lhs = variableTable->getVar(M_varInId)->getDouble();
    double rhs = M_varIn2Id ? variableTable->getVar(M_varIn2Id)->getDouble() : M_doubleValue;

    switch(M_comp) {
    case E_C_EQ:
        return lhs == rhs;
    case E_C_NE:
        return lhs != rhs;
    case E_C_GT:
        return lhs > rhs;
    case E_C_LT:
        return lhs < rhs;
    case E_C_GEQ:
        return lhs >= rhs;
    case E_C_LEQ:
        return lhs <= rhs;
    default:
        ERROR("Internal error: Invalid comparison type %d", M_comp);
        return false; /* Shut up warning. */
    }
}

void CAction::printInfo(char* buf, int len)
{
    if (M_action == E_AT_ASSIGN_FROM_REGEXP) {
        if (M_lookingPlace == E_LP_MSG) {
            snprintf(buf, len, "Type[%d] - regexp[%s] where[%s] - checkIt[%d] - checkItInverse[%d] - $%s",
                   M_action,
                   M_regularExpression,
                   "Full Msg",
                   M_checkIt,
                   M_checkItInverse,
                   display_scenario->allocVars->getName(M_varId));
        } else {
            snprintf(buf, len, "Type[%d] - regexp[%s] where[%s-%s] - checkIt[%d] - checkItInverse[%d] - $%s",
                   M_action,
                   M_regularExpression,
                   "Header",
                   M_lookingChar,
                   M_checkIt,
                   M_checkItInverse, display_scenario->allocVars->getName(M_varId));
        }
    } else if (M_action == E_AT_EXECUTE_CMD) {
        snprintf(buf, len, "Type[%d] - command[%-32.32s]", M_action, M_message_str[0]);
    } else if (M_action == E_AT_EXEC_INTCMD) {
        snprintf(buf, len, "Type[%d] - intcmd[%-32.32s]", M_action, strIntCmd(M_IntCmd));
    } else if (M_action == E_AT_LOG_TO_FILE) {
        snprintf(buf, len, "Type[%d] - message[%-32.32s]", M_action, M_message_str[0]);
    } else if (M_action == E_AT_LOG_WARNING) {
        snprintf(buf, len, "Type[%d] - warning[%-32.32s]", M_action, M_message_str[0]);
    } else if (M_action == E_AT_LOG_ERROR) {
        snprintf(buf, len, "Type[%d] - error[%-32.32s]", M_action, M_message_str[0]);
    } else if (M_action == E_AT_ASSIGN_FROM_SAMPLE) {
        char tmp[40];
        M_distribution->textDescr(tmp, sizeof(tmp));
        snprintf(buf, len, "Type[%d] - sample varId[%s] %s", M_action, display_scenario->allocVars->getName(M_varId), tmp);
    } else if (M_action == E_AT_ASSIGN_FROM_VALUE) {
        snprintf(buf, len, "Type[%d] - assign varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
    } else if (M_action == E_AT_ASSIGN_FROM_INDEX) {
        snprintf(buf, len, "Type[%d] - assign index[%s]", M_action, display_scenario->allocVars->getName(M_varId));
    } else if (M_action == E_AT_ASSIGN_FROM_GETTIMEOFDAY) {
        snprintf(buf, len, "Type[%d] - assign gettimeofday[%s, %s]", M_action, display_scenario->allocVars->getName(M_varId), display_scenario->allocVars->getName(M_subVarId[0]));
    } else if (M_action == E_AT_ASSIGN_FROM_STRING) {
        snprintf(buf, len, "Type[%d] - string assign varId[%s] [%-32.32s]", M_action, display_scenario->allocVars->getName(M_varId), M_message_str[0]);
    } else if (M_action == E_AT_JUMP) {
        snprintf(buf, len, "Type[%d] - jump varInId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varInId), M_doubleValue);
    } else if (M_action == E_AT_PAUSE_RESTORE) {
        snprintf(buf, len, "Type[%d] - restore pause varInId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varInId), M_doubleValue);
    } else if (M_action == E_AT_VAR_ADD) {
        snprintf(buf, len, "Type[%d] - add varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
    } else if (M_action == E_AT_VAR_MULTIPLY) {
        snprintf(buf, len, "Type[%d] - multiply varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
    } else if (M_action == E_AT_VAR_DIVIDE) {
        snprintf(buf, len, "Type[%d] - divide varId[%s] %lf", M_action, display_scenario->allocVars->getName(M_varId), M_doubleValue);
    } else if (M_action == E_AT_VAR_TRIM) {
        snprintf(buf, len, "Type[%d] - trim varId[%s]", M_action, display_scenario->allocVars->getName(M_varId));
    } else if (M_action == E_AT_VAR_URLDECODE) {
        snprintf(buf, len, "Type[%d] - urldecode varId[%s]", M_action, display_scenario->allocVars->getName(M_varId));
    } else if (M_action == E_AT_VAR_URLENCODE) {
        snprintf(buf, len, "Type[%d] - urlencode varId[%s]", M_action, display_scenario->allocVars->getName(M_varId));
    } else if (M_action == E_AT_VAR_TEST) {
        snprintf(buf, len, "Type[%d] - divide varId[%s] varInId[%s] %s %lf", M_action, display_scenario->allocVars->getName(M_varId), display_scenario->allocVars->getName(M_varInId), comparatorToString(M_comp), M_doubleValue);
    } else if (M_action == E_AT_VAR_TO_DOUBLE) {
        snprintf(buf, len, "Type[%d] - toDouble varId[%s]", M_action, display_scenario->allocVars->getName(M_varId));
#ifdef PCAPPLAY
    } else if ((M_action == E_AT_PLAY_PCAP_AUDIO) || (M_action == E_AT_PLAY_PCAP_IMAGE) || (M_action == E_AT_PLAY_PCAP_VIDEO)) {
        snprintf(buf, len, "Type[%d] - file[%s]", M_action, M_pcapArgs->file);
    } else if (M_action == E_AT_PLAY_DTMF) {
        snprintf(buf, len, "Type[%d] - play DTMF digits [%s]", M_action, M_message_str[0]);
#endif
    } else if (M_action == E_AT_RTP_STREAM_PLAY) {
        snprintf(buf,
                 len,
                 "Type[%d] - rtp_stream playfile file %s pattern_id %d loop=%d payload %d bytes per packet=%d ms per packet=%d ticks per packet=%d",
                 M_action,
                 M_rtpstream_actinfo.filename,
                 M_rtpstream_actinfo.pattern_id,
                 M_rtpstream_actinfo.loop_count,
                 M_rtpstream_actinfo.payload_type,
                 M_rtpstream_actinfo.bytes_per_packet,
                 M_rtpstream_actinfo.ms_per_packet,
                 M_rtpstream_actinfo.ticks_per_packet);
    } else if (M_action == E_AT_RTP_STREAM_PAUSE) {
        snprintf(buf, len, "Type[%d] - rtp_stream pause", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RESUME) {
        snprintf(buf, len, "Type[%d] - rtp_stream resume", M_action);
    } else if (M_action == E_AT_RTP_STREAM_PLAYAPATTERN) {
        snprintf(buf,
                 len,
                 "Type[%d] - rtp_stream playapattern file %s pattern_id %d loop=%d payload %d bytes per packet=%d ms per packet=%d ticks per packet=%d",
                 M_action,
                 M_rtpstream_actinfo.filename,
                 M_rtpstream_actinfo.pattern_id,
                 M_rtpstream_actinfo.loop_count,
                 M_rtpstream_actinfo.payload_type,
                 M_rtpstream_actinfo.bytes_per_packet,
                 M_rtpstream_actinfo.ms_per_packet,
                 M_rtpstream_actinfo.ticks_per_packet);
    } else if (M_action == E_AT_RTP_STREAM_PAUSEAPATTERN) {
        snprintf(buf, len, "Type[%d] - rtp_stream pauseapattern", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RESUMEAPATTERN) {
        snprintf(buf, len, "Type[%d] - rtp_stream resumeapattern", M_action);
    } else if (M_action == E_AT_RTP_STREAM_PLAYVPATTERN) {
        snprintf(buf,
                 len,
                 "Type[%d] - rtp_stream playvpattern file %s pattern_id %d loop=%d payload %d bytes per packet=%d ms per packet=%d ticks per packet=%d",
                 M_action,
                 M_rtpstream_actinfo.filename,
                 M_rtpstream_actinfo.pattern_id,
                 M_rtpstream_actinfo.loop_count,
                 M_rtpstream_actinfo.payload_type,
                 M_rtpstream_actinfo.bytes_per_packet,
                 M_rtpstream_actinfo.ms_per_packet,
                 M_rtpstream_actinfo.ticks_per_packet);
    } else if (M_action == E_AT_RTP_STREAM_PAUSEVPATTERN) {
        snprintf(buf, len, "Type[%d] - rtp_stream pausevpattern", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RESUMEVPATTERN) {
        snprintf(buf, len, "Type[%d] - rtp_stream resumevpattern", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RTPECHO_STARTAUDIO) {
        snprintf(buf, len, "Type[%d] - rtp_stream rtpecho startaudio", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RTPECHO_UPDATEAUDIO) {
        snprintf(buf, len, "Type[%d] - rtp_stream rtpecho updateaudio", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RTPECHO_STOPAUDIO) {
        snprintf(buf, len, "Type[%d] - rtp_stream rtpecho stopaudio", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RTPECHO_STARTVIDEO) {
        snprintf(buf, len, "Type[%d] - rtp_stream rtpecho startvideo", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RTPECHO_UPDATEVIDEO) {
        snprintf(buf, len, "Type[%d] - rtp_stream rtpecho updatevideo", M_action);
    } else if (M_action == E_AT_RTP_STREAM_RTPECHO_STOPVIDEO) {
        snprintf(buf, len, "Type[%d] - rtp_stream rtpecho stopvideo", M_action);
    } else {
        snprintf(buf, len, "Type[%d] - unknown action type ... ", M_action);
    }
}


CAction::T_ActionType   CAction::getActionType()
{
    return(M_action);
}
CAction::T_LookingPlace CAction::getLookingPlace()
{
    return(M_lookingPlace);
}
CAction::T_IntCmdType   CAction::getIntCmd ()
{
    return(M_IntCmd);
}
CAction::T_Comparator   CAction::getComparator ()
{
    return(M_comp);
}

bool           CAction::getCheckIt()
{
    return(M_checkIt);
}
bool           CAction::getCheckItInverse()
{
    return(M_checkItInverse);
}
bool           CAction::getCaseIndep()
{
    return(M_caseIndep);
}
bool           CAction::getHeadersOnly()
{
    return(M_headersOnly);
}
int            CAction::getOccurrence()
{
    return(M_occurrence);
}
int            CAction::getVarId()
{
    return(M_varId);
}
int            CAction::getVarInId()
{
    return(M_varInId);
}
int            CAction::getVarIn2Id()
{
    return(M_varIn2Id);
}
char*          CAction::getLookingChar()
{
    return(M_lookingChar);
}
SendingMessage *CAction::getMessage(int n)
{
    return(M_message[n]);
}
CSample*       CAction::getDistribution()
{
    return(M_distribution);
}
double         CAction::getDoubleValue()
{
    return(M_doubleValue);
}
char*          CAction::getStringValue()
{
    return(M_stringValue);
}
#ifdef PCAPPLAY
pcap_pkts *CAction::getPcapPkts()
{
    return(M_pcapArgs);
}
#endif
rtpecho_actinfo_t* CAction::getRTPEchoActInfo()
{
    return &M_rtpecho_actinfo;
}

rtpstream_actinfo_t* CAction::getRTPStreamActInfo()
{
    return &M_rtpstream_actinfo;
}

void CAction::setActionType   (CAction::T_ActionType   P_value)
{
    M_action       = P_value;
}
void CAction::setLookingPlace (CAction::T_LookingPlace P_value)
{
    M_lookingPlace = P_value;
}
void CAction::setCheckIt      (bool           P_value)
{
    M_checkIt      = P_value;
}
void CAction::setCheckItInverse      (bool           P_value)
{
    M_checkItInverse      = P_value;
}
void CAction::setVarId        (int            P_value)
{
    M_varId        = P_value;
}
void CAction::setVarInId      (int            P_value)
{
    M_varInId        = P_value;
}
void CAction::setVarIn2Id      (int            P_value)
{
    M_varIn2Id        = P_value;
}
void CAction::setCaseIndep    (bool           P_value)
{
    M_caseIndep    = P_value;
}
void CAction::setOccurrence   (int            P_value)
{
    M_occurrence    = P_value;
}
void CAction::setHeadersOnly  (bool           P_value)
{
    M_headersOnly  = P_value;
}
void CAction::setIntCmd       (T_IntCmdType P_type)
{
    M_IntCmd       = P_type;
}
void CAction::setComparator   (T_Comparator P_value)
{
    M_comp         = P_value;
}

/* sample specific function. */
void CAction::setDistribution (CSample *P_value)
{
    M_distribution       = P_value;
}
/* assign from value specific function. */
void CAction::setDoubleValue (double P_value)
{
    M_doubleValue       = P_value;
}

/* strcmp specific function. */
void CAction::setStringValue (char *P_value)
{
    M_stringValue       = P_value;
}

void CAction::setSubVarId (int    P_value)
{
    if ( M_nbSubVarId < M_maxNbSubVarId ) {
        M_subVarId[M_nbSubVarId] = P_value;
        M_nbSubVarId++;
    }
}

int  CAction::getSubVarId(int P_index)
{
    return(M_subVarId[P_index]);
}

int*  CAction::getSubVarId()
{
    return(M_subVarId);
}

void CAction::setNbSubVarId (int            P_value)
{
    M_maxNbSubVarId        = P_value;
    if (M_subVarId != nullptr) {
        delete [] M_subVarId;
        M_subVarId      = nullptr;
    }
    M_subVarId = new int[M_maxNbSubVarId] ;
    M_nbSubVarId = 0 ;
}
int  CAction::getNbSubVarId ()
{
    return(M_nbSubVarId);
}


void CAction::setLookingChar(const char* P_value)
{
    if (M_lookingChar != nullptr) {
        delete [] M_lookingChar;
        M_lookingChar = nullptr;
    }

    if (P_value != nullptr) {
        M_lookingChar = new char[strlen(P_value)+1];
        strcpy(M_lookingChar, P_value);
    }
}

void CAction::setMessage(const char* P_value, int n)
{
    if (M_message[n] != nullptr) {
        delete M_message[n];
        M_message[n] = nullptr;
    }
    free(M_message_str[n]);
    M_message_str[n] = nullptr;

    if (P_value != nullptr) {
        M_message_str[n] = strdup(P_value);
        M_message[n] = new SendingMessage(M_scenario, P_value, true /* skip sanity */);
    }
}

void CAction::setRegExp(const char *P_value)
{
    int errorCode;

    free(M_regularExpression);
    M_regularExpression = strdup(P_value);
    M_regExpSet = true;

    errorCode = regcomp(&M_internalRegExp, P_value, REGCOMP_PARAMS);
    if (errorCode != 0) {
        char buffer[MAX_HEADER_LEN];
        regerror(errorCode, &M_internalRegExp, buffer, sizeof(buffer));
        ERROR("recomp error : regular expression '%s' - error '%s'", M_regularExpression, buffer);
    }
}

char *CAction::getRegularExpression()
{
    if (!M_regExpSet) {
        ERROR("Trying to get a regular expression for an action that does not have one!");
    }
    return M_regularExpression;
}

int CAction::executeRegExp(const char* P_string, VariableTable *P_callVarTable)
{
    regmatch_t pmatch[10];
    int error;
    int nbOfMatch = 0;
    char* result = nullptr ;

    if (!M_regExpSet) {
        ERROR("Trying to perform regular expression match on action that does not have one!");
    }

    if (getNbSubVarId() > 9) {
        ERROR("You can only have nine sub expressions!");
    }

    memset((void*)pmatch, 0, sizeof(regmatch_t)*10);

    error = regexec(&M_internalRegExp, P_string, 10, pmatch, REGEXEC_PARAMS);
    if (error == 0) {
        CCallVariable* L_callVar = P_callVarTable->getVar(getVarId());

        for (int i = 0; i <= getNbSubVarId(); i++) {
            if (pmatch[i].rm_eo != -1) {
                setSubString(&result, P_string, pmatch[i].rm_so, pmatch[i].rm_eo);
                L_callVar->setMatchingValue(result);
                nbOfMatch++;
            }
            if (i == getNbSubVarId()) {
                break;
            }
            L_callVar = P_callVarTable->getVar(getSubVarId(i));
        }
    }
    return(nbOfMatch);
}

void CAction::setSubString(char** P_target, const char* P_source, int P_start, int P_stop)
{
    int sizeOf;

    if (P_source != nullptr) {
        sizeOf = P_stop - P_start;
        (*P_target) = new char[sizeOf + 1];

        if (sizeOf > 0) {
            memcpy((*P_target), &(P_source[P_start]), sizeOf);
        }

        (*P_target)[sizeOf] = '\0';
    } else {
        *P_target = nullptr ;
    }
}


#ifdef PCAPPLAY
void CAction::setPcapArgs (pcap_pkts  *  P_value)
{
    if (M_pcapArgs != nullptr) {
        free(M_pcapArgs);
        M_pcapArgs = nullptr;
    }

    if (P_value != nullptr) {
        M_pcapArgs = (pcap_pkts *)malloc(sizeof(*M_pcapArgs));
        memcpy(M_pcapArgs, P_value, sizeof(*M_pcapArgs));
    }
}

void CAction::setPcapArgs(const char* P_value)
{
    if (M_pcapArgs != nullptr) {
        free(M_pcapArgs);
        M_pcapArgs = nullptr;
    }

    if (P_value != nullptr) {
        M_pcapArgs = (pcap_pkts *) malloc(sizeof(*M_pcapArgs));
        if (parse_play_args(P_value, M_scenario->getPath().c_str(), M_pcapArgs) == -1) {
            ERROR("Play pcap error");
        }
        if (access(M_pcapArgs->file, F_OK)) {
            ERROR("Cannot read file %s", M_pcapArgs->file);
        }
    }
}
#endif

void CAction::setRTPEchoActInfo(const char* P_value)
{
    char* param_str;
    char* next_comma;
    char actionstring[RTPECHO_MAX_FILENAMELEN];

    if (strlen(P_value) >= 512) {
        ERROR("RTPEcho keyword %s is too long -- maximum supported length %u\n", P_value, 512);
    }

    memset(actionstring, 0, sizeof(actionstring));

    // Initialize M_rtpecho_actinfo struct members
    M_rtpecho_actinfo.payload_type = rtp_default_payload;
    memset(M_rtpecho_actinfo.payload_name, 0, sizeof(M_rtpecho_actinfo.payload_name));
    M_rtpecho_actinfo.bytes_per_packet = 0;
    M_rtpecho_actinfo.audio_active = 0;
    M_rtpecho_actinfo.video_active = 0;

    strcpy (actionstring,P_value);
    param_str = strchr(actionstring,',');
    next_comma = nullptr;

    // Comma found for payload_type parameter
    if (param_str) {
        *(param_str++) = 0; // skip comma

        /* we have a payload type parameter */
        next_comma = strchr (param_str, ',');
        if (next_comma) {
            *(next_comma++) = 0;
        }
        M_rtpecho_actinfo.payload_type = atoi(param_str);
        param_str = next_comma;
    }

    // Comma found for payload_name parameter
    if (param_str) {
        /* we have a payload_name parameter */
        next_comma = strchr(param_str, ',');
        if (next_comma) {
            *(next_comma++) = 0;
        }
        strcpy(M_rtpecho_actinfo.payload_name, param_str);
        param_str = next_comma;
    }

    if (!strcmp(M_rtpecho_actinfo.payload_name, "")) {
        static const std::map<int, const char *> default_parameters{
            {0, "PCMU/8000"}, {8, "PCMA/8000"},
            {9, "G722/8000"}, {18, "G729/8000"}};
        auto const it = default_parameters.find(M_rtpecho_actinfo.payload_type);
        if (it != default_parameters.end()) {
            strncat(M_rtpecho_actinfo.payload_name, it->second,
                    sizeof(M_rtpecho_actinfo.payload_name) - 1);
        } else {
            ERROR("Missing mandatory payload_name parameter in rtp_echo action");
        }
    }

    /* Setup based on what we know of payload types */
    switch (M_rtpecho_actinfo.payload_type) {
    case 0:
        if (!strcmp(M_rtpecho_actinfo.payload_name, "PCMU/8000")) {
            M_rtpecho_actinfo.bytes_per_packet = 160;
            M_rtpecho_actinfo.audio_active = 1;
        }
        break;
    case 8:
        if (!strcmp(M_rtpecho_actinfo.payload_name, "PCMA/8000")) {
            M_rtpecho_actinfo.bytes_per_packet = 160;
            M_rtpecho_actinfo.audio_active = 1;
        }
        break;
    case 9:
        if (!strcmp(M_rtpecho_actinfo.payload_name, "G722/8000")) {
            M_rtpecho_actinfo.bytes_per_packet = 160;
            M_rtpecho_actinfo.audio_active = 1;
        }
        break;
    case 13: // audio/CN - Comfort noise
        M_rtpecho_actinfo.bytes_per_packet = 1;
        M_rtpecho_actinfo.audio_active = 1;
        break;
    case 18:
        if (!strcmp(M_rtpecho_actinfo.payload_name, "G729/8000")) {
            M_rtpecho_actinfo.bytes_per_packet = 20;
            M_rtpecho_actinfo.audio_active = 1;
        }
        break;
    default:
        if (M_rtpecho_actinfo.payload_type >= 0 &&
                M_rtpecho_actinfo.payload_type <= 95) {
            M_rtpecho_actinfo.bytes_per_packet = -1;
            M_rtpecho_actinfo.audio_active = 0;
            M_rtpecho_actinfo.video_active = 0;
            ERROR("Unknown static rtp payload type %d - cannot set playback parameters\n",
                M_rtpecho_actinfo.payload_type);
        } else if (M_rtpecho_actinfo.payload_type >= 96 &&
                M_rtpecho_actinfo.payload_type <= 127) {
            if (!strcmp(M_rtpecho_actinfo.payload_name, "H264/90000")) {
                M_rtpecho_actinfo.bytes_per_packet = 1280;  // ARBITRARY H264 PACKET SIZE
                M_rtpecho_actinfo.video_active = 1;
            } else if (!strcmp(M_rtpecho_actinfo.payload_name, "iLBC/8000")) {
                M_rtpecho_actinfo.bytes_per_packet = 50;
                M_rtpecho_actinfo.audio_active = 1;
            } else {
                M_rtpecho_actinfo.bytes_per_packet = -1;
                M_rtpecho_actinfo.audio_active = 0;
                M_rtpecho_actinfo.video_active = 0;
                ERROR("Unknown dynamic rtp payload type %d - cannot set playback parameters\n",M_rtpecho_actinfo.payload_type);
            }
        } else {
            ERROR("Invalid rtp payload type %d - cannot set playback parameters\n",M_rtpecho_actinfo.payload_type);
        }
    }
}

void CAction::setRTPEchoActInfo(rtpecho_actinfo_t *P_value)
{
    /* At this stage the entire rtpecho action info structure can simply be */
    /* copied. No members need to be individually duplicated/processed. */
    memcpy(&M_rtpecho_actinfo, P_value, sizeof(M_rtpecho_actinfo));
}

void CAction::setRTPStreamActInfo(const char *P_value)
{
    char* param_str;
    char* next_comma;
    int pattern_mode = 0;
    int stream_type = 0; /* 0: AUDIO / 1: VIDEO */
    char argument_buf[sizeof(M_rtpstream_actinfo.filename)];
    const char* found_file;

    if (strlen(P_value) >= sizeof(argument_buf)) {
        ERROR("Filename/Pattern keyword %s is too long -- maximum supported length %zu",
            P_value, sizeof(argument_buf) - 1);
    }

    // Initialize M_rtpstream_actinfo struct members
    M_rtpstream_actinfo.filename[0] = '\0';
    M_rtpstream_actinfo.pattern_id = -1;
    M_rtpstream_actinfo.loop_count = -1;
    M_rtpstream_actinfo.bytes_per_packet = 0;
    M_rtpstream_actinfo.ms_per_packet = 0;
    M_rtpstream_actinfo.ticks_per_packet = 0;
    M_rtpstream_actinfo.payload_type = 0;
    M_rtpstream_actinfo.payload_name[0] = '\0';
    M_rtpstream_actinfo.audio_active = 0;
    M_rtpstream_actinfo.video_active = 0;

    if (!strncmp(P_value, "apattern", 8) || !strncmp(P_value, "vpattern", 8)) {
        pattern_mode = 1;
    }

    // Extract filename
    strcpy(argument_buf, P_value);
    if ((param_str = strchr(argument_buf, ','))) {
        *param_str++ = '\0';
    }

    // Lookup best file match
    if (pattern_mode == 0) {
        found_file = find_file(argument_buf, M_scenario->getPath().c_str());
        if (found_file) {
            if (strlen(found_file) >= sizeof(M_rtpstream_actinfo.filename)) {
                ERROR("Filename/Pattern keyword %s is too long -- maximum supported length %zu",
                    found_file, sizeof(M_rtpstream_actinfo.filename) - 1);
            }
            strcpy(M_rtpstream_actinfo.filename, found_file);
            free(const_cast<char*>(found_file));
        }
    }

    // Set default values of pattern_id/loop_count depending on whether we are in PATTERN or FILE mode
    if (pattern_mode) {
        M_rtpstream_actinfo.pattern_id = 1;
        M_rtpstream_actinfo.loop_count = -1;
    } else {
        M_rtpstream_actinfo.pattern_id = -1;
        M_rtpstream_actinfo.loop_count = 1;
    }

    // Comma found for loop_count (FILE MODE) or pattern_id (PATTERN MODE)
    if (param_str) {
        /* we have a loop count parameter (FILE MODE) or pattern id parameter (PATTERN MODE) */
        next_comma = strchr(param_str, ',');
        if (next_comma) {
            *(next_comma++) = 0;
        }

        if (pattern_mode) {
            M_rtpstream_actinfo.pattern_id = atoi(param_str);
        } else {
            M_rtpstream_actinfo.loop_count = atoi(param_str);
        }
        param_str = next_comma;
    }

    // Set default RTP payload type value
    M_rtpstream_actinfo.payload_type = rtp_default_payload;

    // Comma found for payload_type parameter
    if (param_str) {
        /* we have a payload type parameter */
        next_comma = strchr(param_str, ',');
        if (next_comma)
        {
            *(next_comma++) = 0;
        }
        M_rtpstream_actinfo.payload_type = atoi(param_str);
        param_str = next_comma;
    }

    // Comma found for payload_name parameter
    if (param_str) {
        /* we have a payload_name parameter */
        next_comma = strchr(param_str, ',');
        if (next_comma) {
            *(next_comma++) = 0;
        }
        strcpy(M_rtpstream_actinfo.payload_name, param_str);
        param_str = next_comma;
    }

    if (!strcmp(M_rtpstream_actinfo.payload_name, "")) {
        static const std::map<int, const char *> default_parameters {
            {0, "PCMU/8000"}, {8, "PCMA/8000"},
            {9, "G722/8000"}, {18, "G729/8000"}};
        auto const it = default_parameters.find(M_rtpstream_actinfo.payload_type);
        if (it != default_parameters.end())
        {
            strncat(M_rtpstream_actinfo.payload_name, it->second,
                    sizeof(M_rtpstream_actinfo.payload_name) - 1);
        } else {
            ERROR("Missing mandatory payload_name parameter in rtp_stream action");
        }
    }

    // JLTAG NOTE:
    // Reworked code from commit
    // "f3b6fe8cd60dd3d1dcca0ab373dc9d289f123f43" which violated the RFC
    // standards for payload_type IDs by using dynamic payload type 98
    // incorrectly as a static one for the iLBC audio codec which rather
    // uses dynamic payload types and should rather be determined by
    // payload_name (0-95 is the payload_type range reserved for static
    // codecs, 96-127 is the payload_type range is reserved for dynamic
    // codecs)

    /* Setup based on what we know of payload types */
    switch (M_rtpstream_actinfo.payload_type) {
    case 0:
        if (!strcmp(M_rtpstream_actinfo.payload_name, "PCMU/8000")) {
            M_rtpstream_actinfo.ms_per_packet = 20;
            M_rtpstream_actinfo.bytes_per_packet = 160;
            M_rtpstream_actinfo.ticks_per_packet = 160;
            M_rtpstream_actinfo.audio_active = 1;
            stream_type = 0;
        }
        break;
    case 8:
        if (!strcmp(M_rtpstream_actinfo.payload_name, "PCMA/8000")) {
            M_rtpstream_actinfo.ms_per_packet = 20;
            M_rtpstream_actinfo.bytes_per_packet = 160;
            M_rtpstream_actinfo.ticks_per_packet = 160;
            M_rtpstream_actinfo.audio_active = 1;
            stream_type = 0;
        }
        break;
    case 9:
        if (!strcmp(M_rtpstream_actinfo.payload_name, "G722/8000")) {
            M_rtpstream_actinfo.ms_per_packet = 20;
            M_rtpstream_actinfo.bytes_per_packet = 160;
            M_rtpstream_actinfo.ticks_per_packet = 160;
            M_rtpstream_actinfo.audio_active = 1;
            stream_type = 0;
        }
        break;
    case 13: // audio/CN - Comfort noise
        M_rtpstream_actinfo.ms_per_packet = 150;
        M_rtpstream_actinfo.bytes_per_packet = 1;
        M_rtpstream_actinfo.ticks_per_packet = 1200;
        M_rtpstream_actinfo.audio_active = 1;
        break;
    case 18:
        if (!strcmp(M_rtpstream_actinfo.payload_name, "G729/8000")) {
            M_rtpstream_actinfo.ms_per_packet = 20;
            M_rtpstream_actinfo.bytes_per_packet = 20;
            M_rtpstream_actinfo.ticks_per_packet = 160;
            M_rtpstream_actinfo.audio_active = 1;
            stream_type = 0;
        }
        break;
    default:
        if ((M_rtpstream_actinfo.payload_type >= 0) &&
                (M_rtpstream_actinfo.payload_type <= 95)) {
            M_rtpstream_actinfo.ms_per_packet = -1;
            M_rtpstream_actinfo.bytes_per_packet = -1;
            M_rtpstream_actinfo.ticks_per_packet = -1;
            M_rtpstream_actinfo.audio_active = 0;
            M_rtpstream_actinfo.video_active = 0;
            ERROR("Unknown static rtp payload type %d - cannot set playback parameters\n",
                M_rtpstream_actinfo.payload_type);
        } else if (M_rtpstream_actinfo.payload_type >= 96 &&
                M_rtpstream_actinfo.payload_type <= 127) {
            if (!strcmp(M_rtpstream_actinfo.payload_name, "H264/90000")) {
                M_rtpstream_actinfo.ms_per_packet = 160;   // ARBITRARY H264 PACKET TIME
                M_rtpstream_actinfo.bytes_per_packet = 1280;  // ARBITRARY H264 PACKET SIZE
                M_rtpstream_actinfo.ticks_per_packet = 1280;  // ARBITRARY H264 PACKET TICKS
                M_rtpstream_actinfo.video_active = 1;
                stream_type = 1;
            } else if (!strcmp(M_rtpstream_actinfo.payload_name, "iLBC/8000")) {
                M_rtpstream_actinfo.ms_per_packet = 30;
                M_rtpstream_actinfo.bytes_per_packet = 50;
                M_rtpstream_actinfo.ticks_per_packet = 240;
                M_rtpstream_actinfo.audio_active = 1;
                stream_type = 0;
            } else  {
                M_rtpstream_actinfo.ms_per_packet = -1;
                M_rtpstream_actinfo.bytes_per_packet = -1;
                M_rtpstream_actinfo.ticks_per_packet = -1;
                M_rtpstream_actinfo.audio_active = 0;
                M_rtpstream_actinfo.video_active = 0;
                ERROR("Unknown dynamic rtp payload type %d - cannot set playback parameters\n",
                    M_rtpstream_actinfo.payload_type);
            }
        } else {
            ERROR("Invalid rtp payload type %d - cannot set playback parameters\n",
                M_rtpstream_actinfo.payload_type);
        }
        break;
    }

    if (rtpstream_cache_file(
            M_rtpstream_actinfo.filename,
            pattern_mode /* 0: FILE - 1: PATTERN */,
            M_rtpstream_actinfo.pattern_id,
            M_rtpstream_actinfo.bytes_per_packet,
            stream_type) < 0) {
        ERROR("Cannot read/cache rtpstream file %s", M_rtpstream_actinfo.filename);
    }
}

void CAction::setRTPStreamActInfo(rtpstream_actinfo_t *P_value)
{
    /* At this stage the entire rtpstream action info structure can simply be */
    /* copied. No members need to be individually duplicated/processed. */
    memcpy(&M_rtpstream_actinfo, P_value, sizeof(M_rtpstream_actinfo));
}

void CAction::setScenario(scenario *     P_scenario)
{
    M_scenario = P_scenario;
}

void CAction::setAction(CAction P_action)
{
    if (P_action.getActionType() == CAction::E_AT_ASSIGN_FROM_SAMPLE) {
        assert(P_action.getDistribution() != nullptr);
    }
    int L_i;
    setActionType   ( P_action.getActionType()   );
    setLookingPlace ( P_action.getLookingPlace() );
    setVarId        ( P_action.getVarId()        );
    setVarInId      ( P_action.getVarInId()      );
    setDoubleValue  ( P_action.getDoubleValue()  );
    setDistribution ( P_action.getDistribution() );
    setScenario     ( P_action.M_scenario        );

    setNbSubVarId   ( P_action.getNbSubVarId()   );
    for (L_i = 0; L_i < P_action.getNbSubVarId() ; L_i++ ) {
        setSubVarId (P_action.getSubVarId(L_i));
    }

    setLookingChar  ( P_action.getLookingChar()  );
    setCheckIt      ( P_action.getCheckIt()      );
    setCheckItInverse      ( P_action.getCheckItInverse()      );
    setCaseIndep    ( P_action.getCaseIndep()    );
    setOccurrence   ( P_action.getOccurrence()   );
    setHeadersOnly  ( P_action.getHeadersOnly()  );
    for (L_i = 0; L_i < MAX_ACTION_MESSAGE; L_i++) {
        setMessage(P_action.M_message_str[L_i], L_i);
    }
    setRegExp       ( P_action.M_regularExpression);
    setIntCmd       ( P_action.M_IntCmd          );
#ifdef PCAPPLAY
    setPcapArgs     ( P_action.M_pcapArgs        );
#endif
    setRTPEchoActInfo(&(P_action.M_rtpecho_actinfo));
    setRTPStreamActInfo(&(P_action.M_rtpstream_actinfo));
}

CAction::CAction(scenario *scenario)
{
    M_action       = E_AT_NO_ACTION;
    M_varId        = 0;
    M_varInId        = 0;
    M_varIn2Id        = 0;

    M_nbSubVarId    = 0;
    M_maxNbSubVarId = 0;
    M_subVarId      = nullptr;

    M_checkIt      = false;
    M_checkItInverse      = false;
    M_lookingPlace = E_LP_MSG;
    M_lookingChar  = nullptr;
    M_caseIndep    = false;
    M_occurrence   = 1;
    M_headersOnly  = true;
    for (int i = 0; i < MAX_ACTION_MESSAGE; i++) {
        M_message[i]   = nullptr;
        M_message_str[i] = nullptr;
    }
    M_IntCmd       = E_INTCMD_INVALID;
    M_doubleValue  = 0;
    M_stringValue  = nullptr;
    M_distribution = nullptr;
#ifdef PCAPPLAY
    M_pcapArgs     = nullptr;
#endif

    memset(&M_rtpecho_actinfo, 0, sizeof(M_rtpecho_actinfo));
    memset(&M_rtpstream_actinfo, 0, sizeof(M_rtpstream_actinfo));

    M_scenario     = scenario;
    M_regExpSet    = false;
    M_regularExpression = nullptr;
}

CAction::~CAction()
{
    if (M_lookingChar != nullptr) {
        delete [] M_lookingChar;
        M_lookingChar = nullptr;
    }
    for (int i = 0; i < MAX_ACTION_MESSAGE; i++) {
        if (M_message[i] != nullptr) {
            delete M_message[i];
            M_message[i] = nullptr;
        }
        free(M_message_str[i]);
        M_message_str[i] = nullptr;
    }
    if (M_subVarId != nullptr) {
        delete [] M_subVarId;
        M_subVarId      = nullptr;
    }
    free(M_stringValue);
#ifdef PCAPPLAY
    if (M_pcapArgs != nullptr) {
        free_pcaps(M_pcapArgs);
        M_pcapArgs = nullptr;
    }
#endif
    if (M_regExpSet) {
        regfree(&M_internalRegExp);
        free(M_regularExpression);
    }
    if (M_distribution) {
        delete M_distribution;
    }
}

/****************************** CActions class ************************/

void CActions::printInfo()
{
    printf("Action Size = [%d]\n", M_nbAction);
    for (int i = 0; i < M_nbAction; i++) {
        printf("actionlist[%d] : \n", i);
        char buf[80];
        M_actionList[i]->printInfo(buf, 80);
        printf("%s\n", buf);
    }
}

void CActions::reset()
{
    for (int i = 0; i < M_nbAction; i++) {
        delete M_actionList[i];
        M_actionList[i] = nullptr;
    }
    M_nbAction = 0;
}

int CActions::getActionSize()
{
    return(M_nbAction);
}

void CActions::setAction(CAction *P_action)
{
    CAction **newActions = new CAction*[M_nbAction + 1];
    for (int i = 0; i < M_nbAction; i++) {
        newActions[i] = M_actionList[i];
    }
    if (M_actionList) {
        delete [] M_actionList;
    }
    M_actionList = newActions;
    M_actionList[M_nbAction] = P_action;
    M_nbAction++;
}

CAction* CActions::getAction(int i)
{
    if (i < M_nbAction) {
        return(M_actionList[i]);
    } else
        return(nullptr);
}


CActions::CActions()
{
    M_nbAction = 0;
    M_actionList = nullptr;
}


CActions::~CActions()
{
    for (int i = 0; i < M_nbAction; i++) {
        delete M_actionList[i];
    }
    delete [] M_actionList;
    M_actionList = nullptr;
}

#ifdef GTEST
#include "gtest/gtest.h"

TEST(actions, MatchingRegexp) {
    AllocVariableTable vt(nullptr);
    int id = vt.find("1", true);
    int sub1_id = vt.find("2", true);
    int sub2_id = vt.find("3", true);
    int sub3_id = vt.find("4", true);
    int sub4_id = vt.find("5", true);
    CAction re(nullptr);
    re.setVarId(id);
    re.setNbSubVarId(4);
    re.setSubVarId(sub1_id);
    re.setSubVarId(sub2_id);
    re.setSubVarId(sub3_id);
    re.setSubVarId(sub4_id);
    re.setRegExp("(.+)(o) (.+)(d)");
    int results = re.executeRegExp("hello world", &vt);

    ASSERT_EQ(5, results);
    ASSERT_STREQ("hello world", vt.getVar(id)->getString());
    ASSERT_STREQ("hell", vt.getVar(sub1_id)->getString());
    ASSERT_STREQ("o", vt.getVar(sub2_id)->getString());
    ASSERT_STREQ("worl", vt.getVar(sub3_id)->getString());
    ASSERT_STREQ("d", vt.getVar(sub4_id)->getString());
}

TEST(actions, NonMatchingRegexp) {
    AllocVariableTable vt(nullptr);
    int id = vt.find("1", true);
    int sub1_id = vt.find("2", true);
    int sub2_id = vt.find("3", true);
    int sub3_id = vt.find("4", true);
    int sub4_id = vt.find("5", true);
    CAction re(nullptr);
    re.setVarId(id);
    re.setNbSubVarId(4);
    re.setSubVarId(sub1_id);
    re.setSubVarId(sub2_id);
    re.setSubVarId(sub3_id);
    re.setSubVarId(sub4_id);
    re.setRegExp("(.+)(o) (.+)(d)");
    int results = re.executeRegExp("", &vt);

    ASSERT_EQ(0, results);
    ASSERT_STREQ("", vt.getVar(id)->getString());
    ASSERT_STREQ("", vt.getVar(sub1_id)->getString());
}

#endif
