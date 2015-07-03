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
 *            Wolfgang Beck
 *
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <assert.h>

#include "sipp.hpp"
#include "scenario.hpp"
#include "screen.hpp"
#ifdef HAVE_GSL
#include <gsl/gsl_rng.h>
#include <gsl/gsl_randist.h>
#include <gsl/gsl_cdf.h>
#endif

/*
** Local definitions (macros)
*/

/*
** Warning! All DISPLAY_ macros must be called where f FILE is
**          defined. This is to allow printing to stdout or a file.
*/
#define DISPLAY_DLINE()\
  fprintf(f,"================================================================================\r\n")
#define DISPLAY_CROSS_LINE()\
  fprintf(f,"-------------------------+---------------------------+--------------------------\r\n")

#define DISPLAY_HEADER()\
  fprintf(f,"  Counter Name           | Periodic value            | Cumulative value\r\n")
#define DISPLAY_TXT_COL(T1, V1, V2)\
  fprintf(f,"  %-22.22s | %-25.25s |", T1, V1); fprintf(f," %-24.24s \r\n", V2)
#define DISPLAY_VAL_RATEF_COL(T1, V1, V2)\
  fprintf(f,"  %-22.22s | %8.3f cps              | %8.3f cps             \r\n", T1, V1, V2)
#define DISPLAY_2VAL(T1, V1, V2)\
  fprintf(f,"  %-22.22s | %8llu                  | %8llu                 \r\n", T1, V1, V2)
#define DISPLAY_CUMUL(T1, V1)\
  fprintf(f,"  %-22.22s |                           | %8llu                 \r\n", T1, V1)
#define DISPLAY_PERIO(T1, V1)\
  fprintf(f,"  %-22.22s | %8llu                  |                          \r\n", T1, V1)
#define DISPLAY_TXT(T1, V1)\
  fprintf(f,"  %-22.22s | %-52.52s \r\n", T1, V1)
#define DISPLAY_INFO(T1)\
  fprintf(f,"  %-77.77s \r\n", T1)
#define DISPLAY_REPART(T1, T2, V1)\
  fprintf(f,"    %8zu ms <= n <  %8zu ms : %10zu  %-29.29s \r\n", T1, T2, V1, "")
#define DISPLAY_LAST_REPART(T1, V1)\
  fprintf(f,"    %14.14s n >= %8zu ms : %10zu  %-29.29s \r\n", "", T1, V1, "")

bool operator==(const repartition& lhs, const repartition& rhs)
{
    return lhs.max == rhs.max && lhs.count == rhs.count;
}

std::array<unsigned long long, CStat::E_NB_G_COUNTER - CStat::E_NB_COUNTER> CStat::M_G_counters = {};

void CStat::resetCCounters()
{
    for (int i = CStat::CPT_G_C_OutOfCallMsgs; i <= CStat::CPT_G_C_AutoAnswered; i++) {
        M_G_counters[i - E_NB_COUNTER - 1] = 0L;
    }
    for (int i = CStat::CPT_C_IncomingCallCreated; i <= CStat::CPT_C_Retransmissions; i++) {
        M_counters[i] = 0L;
    }
    for (size_t j = 0; j < M_genericMap.size(); j++) {
        M_genericCounters[j * GENERIC_TYPES + GENERIC_C] = 0;
    }
    for (size_t j = 0; j < M_rtdMap.size(); j++) {
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_COUNT] = 0;
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_SUM] = 0;
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_SUMSQ] = 0;
    }
}

void CStat::resetPDCounters()
{
    for (int i = CStat::CPT_G_PD_OutOfCallMsgs; i <= CStat::CPT_G_PD_AutoAnswered; i++) {
        M_G_counters[i - E_NB_COUNTER - 1] = (unsigned long) 0;
    }
    for (int i = CStat::CPT_PD_IncomingCallCreated; i <= CStat::CPT_PD_Retransmissions; i++) {
        M_counters[i] = (unsigned long) 0;
    }
    for (size_t j = 0; j < M_genericMap.size(); j++) {
        M_genericCounters[j * GENERIC_TYPES + GENERIC_PD] = 0;
    }
    for (size_t j = 0; j < M_rtdMap.size(); j++) {
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_COUNT] = 0;
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_SUM] = 0;
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_SUMSQ] = 0;
    }
}

void CStat::resetPLCounters()
{
    for (int i = CStat::CPT_G_PL_OutOfCallMsgs; i <= CStat::CPT_G_PL_AutoAnswered; i++) {
        M_G_counters[i - E_NB_COUNTER - 1] = (unsigned long) 0;
    }
    for (int i = CStat::CPT_PL_IncomingCallCreated; i <= CStat::CPT_PL_Retransmissions; i++) {
        M_counters[i] = (unsigned long) 0;
    }
    for (size_t j = 0; j < M_genericMap.size(); j++) {
        M_genericCounters[j * GENERIC_TYPES + GENERIC_PL] = 0;
    }
    for (size_t j = 0; j < M_rtdMap.size(); j++) {
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_COUNT] = 0;
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_SUM] = 0;
        M_rtdInfo[(j * GENERIC_TYPES * RTD_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_SUMSQ] = 0;
    }
}

/*
  __________________________________________________________________________

  C L A S S    CS t a t
  __________________________________________________________________________
*/

int is_well_formed(std::string const &data, int* count)
{
    *count = 0;
    if (data.empty()) {
        return 1;
    }

    bool in_number = false;
    for (auto p = data.begin(); p != data.end(); ++p) {
        switch (*p) {
        case ',':
            if (!in_number) {
                return 0;
            }
            (*count)++;
            in_number = false;
            break;
        case '\t':
        case ' ' :
            break;
        default:
            if (!std::isdigit(*p)) {
                return 0;
            }
            in_number = true;
            break;
        }
    }

    if (!in_number) {
        return 0;
    }

    (*count)++;
    return 1;
}

static std::vector<unsigned int> integer_table(std::string const& data)
{
    unsigned int current_int;
    std::vector<unsigned int> list;

    int count = 0, ret;
    ret = is_well_formed(data, &count);

    if (ret == 1 && count > 0) {
        std::string::size_type pos, offset = 0;

        while ((pos = data.find(',', offset)) != std::string::npos) {
            std::string token = data.substr(offset, pos - offset);
            sscanf(token.c_str(), "%u", &current_int);
            list.emplace_back(current_int);
            offset = ++pos;
        }

        std::string token = data.substr(offset);
        sscanf(token.c_str(), "%u", &current_int);
        list.emplace_back(current_int);
    }

    return list;
}

static repartition_list make_repartitions(std::vector<unsigned int>& repartitions)
{
    repartition_list tab;
    if (repartitions.empty()) {
        return tab;
    }

    // copying the repartition table in the local table
    for (const unsigned int& value : repartitions) {
        tab.push_back(repartition(value));
    }

    std::sort(tab.begin(), tab.end(), [](const repartition& a, const repartition& b) -> bool {
        return a.max < b.max;
    });

    // setting the range for max <= value < infinity
    tab.push_back(tab.back());
    return tab;
}

static void reset_repartition(repartition_list& tab)
{
    for (auto& node : tab) {
        node.count = 0;
    }
}

static void update_repartition(repartition_list &tab, unsigned long value)
{
    if (tab.empty()) {
        return;
    }

    for (auto& node : tab) {
        if (value < node.max) {
            node.count++;
            return;
        }
    }

    /* If this is not true, we never should have gotten here. */
    assert(value >= tab.back().max);
    tab.back().count++;
}

static __attribute__((format(printf, 1, 2))) std::string string_format(const char *fmt, ...)
{
    va_list ap;
    std::string str;

    va_start(ap, fmt);
    int len = vsnprintf(const_cast<char*>(str.data()), str.size(), fmt, ap);
    va_end(ap);

    if (len < 0) {
        ERROR_NO("Failed to format string");
    } else if (len >= str.size()) {
        str.reserve(len + 1);

        va_start(ap, fmt);
        vsnprintf(const_cast<char*>(str.data()), str.size(), fmt, ap);
        va_end(ap);
    }

    return str;
}

static std::string repartition_header(const repartition_list& tab,
                                      const std::string& name)
{
    if (tab.empty()) {
        return "";
    }

    std::string header;
    for (auto& node : tab) {
        header += string_format("%s_<%zu%s", name.c_str(), node.max, stat_delimiter);
    }

    return header + string_format("%s_>=%zu%s", name.c_str(), tab.back().max, stat_delimiter);
}

static std::string repartition_info(const repartition_list& tab)
{
    if (tab.empty()) {
        return "";
    }

    std::string header;
    for (auto& node : tab) {
        header += string_format("%lu%s", node.count, stat_delimiter);
    }

    return header + string_format("%lu%s", tab.back().count, stat_delimiter);
}

static void display_repartition(FILE* f, const repartition_list& tab)
{
    if (!tab.empty()) {
        auto it = tab.begin();
        DISPLAY_REPART(0L, it->max, it->count);

        ++it;
        for (; it != tab.end() - 1; ++it) {
            DISPLAY_REPART(it[-1].max,
                           it->max,
                           it->count);
        }
        DISPLAY_LAST_REPART(it->max, it->count);
    } else {
        DISPLAY_INFO("  <No repartion defined>");
    }
}

static std::string set_filename(std::string const& name, std::string const& extension)
{
    if (name.empty()) {
        WARNING("New filename is NULL, keeping the default: %s", DEFAULT_FILE_NAME);
        return std::string("");
    }

    if (extension.empty()) {
        return string_format("%s_%d_%s", name.c_str(), getpid(), DEFAULT_EXTENSION);
    }
    return string_format("%s_%d_%s", name.c_str(), getpid(), extension.c_str());
}

void CStat::setFileName(const char* name, const char* extension)
{
    M_fileName = set_filename(name, extension);
}

void CStat::setFileName(const char* name)
{
    M_fileName = set_filename(name, NULL);
}

void CStat::initRtt(const char* name, const char* extension,
                    unsigned long report_freq_dumpRtt)
{
    M_fileNameRtt = set_filename(name, extension);

    // initiate the table dump response time
    M_report_freq_dumpRtt = report_freq_dumpRtt;

    M_dumpRespTime = new T_value_rtt[report_freq_dumpRtt];
    if (M_dumpRespTime == NULL) {
        ERROR_NO("Memory allocation failure");
        exit(EXIT_FATAL_ERROR);
    }

    for (unsigned L_i = 0; L_i < report_freq_dumpRtt; L_i++) {
        M_dumpRespTime[L_i].date = 0.0;
        M_dumpRespTime[L_i].rtd_no = 0;
        M_dumpRespTime[L_i].rtt = 0.0;
    }
}

void CStat::setRepartitionCallLength(char* P_listeStr)
{
    auto table = integer_table(P_listeStr);
    if (!table.empty()) {
        M_CallLengthRepartition = make_repartitions(table);
    } else {
        ERROR("Could not create table for call length repartition '%s'\n", P_listeStr);
    }
}

void CStat::setRepartitionResponseTime(char* P_listeStr)
{
    auto table = integer_table(P_listeStr);
    if (table.empty()) {
        ERROR("Could not create table for response time repartition '%s'\n", P_listeStr);
    }

    M_ResponseTimeRepartition.clear();
    for (int i = 0; i < nRtds(); ++i) {
        M_ResponseTimeRepartition.emplace_back(make_repartitions(table));
    }
}

void CStat::setRepartitionCallLength(unsigned int* repartition,
                                     int nombre)
{
    auto table = std::vector<unsigned int>(repartition, repartition + nombre);
    M_CallLengthRepartition = make_repartitions(table);
}

void CStat::setRepartitionResponseTime(unsigned int* repartition,
                                       int nombre)
{
    auto table = std::vector<unsigned int>(repartition, repartition + nombre);
    M_ResponseTimeRepartition.clear();
    for (int i = 0; i < nRtds(); ++i) {
        M_ResponseTimeRepartition.emplace_back(make_repartitions(table));
    }
}

int CStat::computeStat(E_Action P_action)
{
    switch (P_action) {
    case E_CREATE_OUTGOING_CALL:
        M_counters[CPT_C_OutgoingCallCreated]++;
        M_counters[CPT_PD_OutgoingCallCreated]++;
        M_counters[CPT_PL_OutgoingCallCreated]++;
        M_counters [CPT_C_CurrentCall]++;
        if (M_counters[CPT_C_CurrentCall] > M_counters[CPT_C_CurrentCallPeak]) {
            M_counters[CPT_C_CurrentCallPeak] = M_counters[CPT_C_CurrentCall];
            M_counters[CPT_C_CurrentCallPeakTime] = clock_tick / 1000;
        }
        if (M_counters[CPT_C_CurrentCall] > M_counters[CPT_PD_CurrentCallPeak]) {
            M_counters[CPT_PD_CurrentCallPeak] = M_counters[CPT_C_CurrentCall];
            M_counters[CPT_PD_CurrentCallPeakTime] = clock_tick / 1000;
        }
        if (M_counters[CPT_C_CurrentCall] > M_counters[CPT_PL_CurrentCallPeak]) {
            M_counters[CPT_PL_CurrentCallPeak] = M_counters[CPT_C_CurrentCall];
            M_counters[CPT_PL_CurrentCallPeakTime] = clock_tick / 1000;
        }
        break;
    case E_CREATE_INCOMING_CALL:
        M_counters[CPT_C_IncomingCallCreated]++;
        M_counters[CPT_PD_IncomingCallCreated]++;
        M_counters[CPT_PL_IncomingCallCreated]++;
        M_counters[CPT_C_CurrentCall]++;
        if (M_counters[CPT_C_CurrentCall] > M_counters[CPT_C_CurrentCallPeak]) {
            M_counters[CPT_C_CurrentCallPeak] = M_counters[CPT_C_CurrentCall];
            M_counters[CPT_C_CurrentCallPeakTime] = clock_tick / 1000;
        }
        if (M_counters[CPT_C_CurrentCall] > M_counters[CPT_PD_CurrentCallPeak]) {
            M_counters[CPT_PD_CurrentCallPeak] = M_counters[CPT_C_CurrentCall];
            M_counters[CPT_PD_CurrentCallPeakTime] = clock_tick / 1000;
        }
        if (M_counters[CPT_C_CurrentCall] > M_counters[CPT_PL_CurrentCallPeak]) {
            M_counters[CPT_PL_CurrentCallPeak] = M_counters[CPT_C_CurrentCall];
            M_counters[CPT_PL_CurrentCallPeakTime] = clock_tick / 1000;
        }
        break;
    case E_CALL_FAILED:
        M_counters[CPT_C_FailedCall]++;
        M_counters[CPT_PD_FailedCall]++;
        M_counters[CPT_PL_FailedCall]++;
        M_counters[CPT_C_CurrentCall]--;
        break;
    case E_CALL_SUCCESSFULLY_ENDED:
        M_counters[CPT_C_SuccessfulCall]++;
        M_counters[CPT_PD_SuccessfulCall]++;
        M_counters[CPT_PL_SuccessfulCall]++;
        M_counters[CPT_C_CurrentCall]--;
        break;
    case E_FAILED_CANNOT_SEND_MSG:
        M_counters[CPT_C_FailedCallCannotSendMessage]++;
        M_counters[CPT_PD_FailedCallCannotSendMessage]++;
        M_counters[CPT_PL_FailedCallCannotSendMessage]++;
        break;
    case E_FAILED_MAX_UDP_RETRANS:
        M_counters[CPT_C_FailedCallMaxUdpRetrans]++;
        M_counters[CPT_PD_FailedCallMaxUdpRetrans]++;
        M_counters[CPT_PL_FailedCallMaxUdpRetrans]++;
        break;
    case E_FAILED_TCP_CONNECT:
        M_counters[CPT_C_FailedCallTcpConnect]++;
        M_counters[CPT_PD_FailedCallTcpConnect]++;
        M_counters[CPT_PL_FailedCallTcpConnect]++;
        break;
    case E_FAILED_TCP_CLOSED:
        M_counters[CPT_C_FailedCallTcpClosed]++;
        M_counters[CPT_PD_FailedCallTcpClosed]++;
        M_counters[CPT_PL_FailedCallTcpClosed]++;
        break;
    case E_FAILED_UNEXPECTED_MSG:
        M_counters[CPT_C_FailedCallUnexpectedMessage]++;
        M_counters[CPT_PD_FailedCallUnexpectedMessage]++;
        M_counters[CPT_PL_FailedCallUnexpectedMessage]++;
        break;
    case E_FAILED_CALL_REJECTED:
        M_counters[CPT_C_FailedCallCallRejected]++;
        M_counters[CPT_PD_FailedCallCallRejected]++;
        M_counters[CPT_PL_FailedCallCallRejected]++;
        break;
    case E_FAILED_CMD_NOT_SENT:
        M_counters[CPT_C_FailedCallCmdNotSent]++;
        M_counters[CPT_PD_FailedCallCmdNotSent]++;
        M_counters[CPT_PL_FailedCallCmdNotSent]++;
        break;
    case E_FAILED_REGEXP_DOESNT_MATCH:
        M_counters[CPT_C_FailedCallRegexpDoesntMatch]++;
        M_counters[CPT_PD_FailedCallRegexpDoesntMatch]++;
        M_counters[CPT_PL_FailedCallRegexpDoesntMatch]++;
        break;
    case E_FAILED_REGEXP_SHOULDNT_MATCH:
        M_counters[CPT_C_FailedCallRegexpShouldntMatch]++;
        M_counters[CPT_PD_FailedCallRegexpShouldntMatch]++;
        M_counters[CPT_PL_FailedCallRegexpShouldntMatch]++;
        break;
    case E_FAILED_REGEXP_HDR_NOT_FOUND:
        M_counters[CPT_C_FailedCallRegexpHdrNotFound]++;
        M_counters[CPT_PD_FailedCallRegexpHdrNotFound]++;
        M_counters[CPT_PL_FailedCallRegexpHdrNotFound]++;
        break;
    case E_FAILED_OUTBOUND_CONGESTION:
        M_counters[CPT_C_FailedOutboundCongestion]++;
        M_counters[CPT_PD_FailedOutboundCongestion]++;
        M_counters[CPT_PL_FailedOutboundCongestion]++;
        break;
    case E_FAILED_TIMEOUT_ON_RECV:
        M_counters[CPT_C_FailedTimeoutOnRecv]++;
        M_counters[CPT_PD_FailedTimeoutOnRecv]++;
        M_counters[CPT_PL_FailedTimeoutOnRecv]++;
        break;
    case E_FAILED_TIMEOUT_ON_SEND:
        M_counters[CPT_C_FailedTimeoutOnSend]++;
        M_counters[CPT_PD_FailedTimeoutOnSend]++;
        M_counters[CPT_PL_FailedTimeoutOnSend]++;
        break;
    case E_RETRANSMISSION:
        M_counters[CPT_C_Retransmissions]++;
        M_counters[CPT_PD_Retransmissions]++;
        M_counters[CPT_PL_Retransmissions]++;
        break;
    case E_RESET_C_COUNTERS:
        resetCCounters();
        GET_TIME(&M_startTime);
        break;
    case E_RESET_PD_COUNTERS:
        //DEBUG(C_Debug::E_LEVEL_4, "ENTER CASE", "%s",
        //      "CStat::computeStat : RESET_PD_COUNTERS");
        resetPDCounters();
        GET_TIME(&M_pdStartTime);
        break;
    case E_RESET_PL_COUNTERS:
        //DEBUG(C_Debug::E_LEVEL_4, "ENTER CASE", "%s",
        //      "C_Stat::computeStat : RESET_PL_COUNTERS");
        resetPLCounters();
        GET_TIME(&M_plStartTime);
        if (periodic_rtd) {
            reset_repartition(M_CallLengthRepartition);
            for (int i = 0; i < nRtds(); i++) {
                reset_repartition(M_ResponseTimeRepartition[i]);
            }
        }
        break;
    default :
        ERROR("CStat::ComputeStat() - Unrecognized Action %d\n", P_action);
        return -1;
    }
    return 0;
}

int CStat::globalStat(E_Action P_action)
{
    switch (P_action) {
    case E_OUT_OF_CALL_MSGS:
        M_G_counters[CPT_G_C_OutOfCallMsgs - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PD_OutOfCallMsgs - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PL_OutOfCallMsgs - E_NB_COUNTER - 1]++;
        break;
    case E_WATCHDOG_MAJOR:
        M_G_counters[CPT_G_C_WatchdogMajor - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PD_WatchdogMajor - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PL_WatchdogMajor - E_NB_COUNTER - 1]++;
        break;
    case E_WATCHDOG_MINOR:
        M_G_counters[CPT_G_C_WatchdogMinor - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PD_WatchdogMinor - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PL_WatchdogMinor - E_NB_COUNTER - 1]++;
        break;
    case E_DEAD_CALL_MSGS:
        M_G_counters[CPT_G_C_DeadCallMsgs - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PD_DeadCallMsgs - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PL_DeadCallMsgs - E_NB_COUNTER - 1]++;
        break;
    case E_FATAL_ERRORS:
        M_G_counters[CPT_G_C_FatalErrors - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PD_FatalErrors - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PL_FatalErrors - E_NB_COUNTER - 1]++;
        break;
    case E_WARNING:
        M_G_counters[CPT_G_C_Warnings - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PD_Warnings - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PL_Warnings - E_NB_COUNTER - 1]++;
        break;
    case E_AUTO_ANSWERED:
        // Let's count the automatic answered calls
        M_G_counters[CPT_G_C_AutoAnswered - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PD_AutoAnswered - E_NB_COUNTER - 1]++;
        M_G_counters[CPT_G_PL_AutoAnswered - E_NB_COUNTER - 1]++;
        break;
    default :
        ERROR("CStat::ComputeStat() - Unrecognized Action %d\n", P_action);
        return -1;
    }
    return 0;
}

void CStat::computeRtt(unsigned long long P_start_time, unsigned long long P_stop_time, int which)
{
    M_dumpRespTime[M_counterDumpRespTime].date = (double)P_stop_time / (double)1000;
    M_dumpRespTime[M_counterDumpRespTime].rtd_no = which;
    M_dumpRespTime[M_counterDumpRespTime].rtt = ((double)(P_stop_time - P_start_time)) / (double)1000;
    M_counterDumpRespTime++ ;

    if (M_counterDumpRespTime > M_report_freq_dumpRtt - 1) {
        dumpDataRtt() ;
    }
}

unsigned long long CStat::GetStat(E_CounterName P_counter)
{
    if (P_counter < E_NB_COUNTER) {
        return M_counters[P_counter];
    } else {
        return M_G_counters[P_counter - E_NB_COUNTER - 1];
    }
}

/* Get the current start time. */
void CStat::getStartTime(struct timeval* t)
{
    memcpy(t, &M_startTime, sizeof(M_startTime));
}

/* Use the short form standard deviation formula given the sum of the squares
 * and the sum. */
double CStat::computeStdev(E_CounterName P_SumCounter,
                           E_CounterName P_NbOfCallUsed,
                           E_CounterName P_Squares)
{
    if (M_counters[P_NbOfCallUsed] <= 0)
        return 0.0;

    double numerator = ((double)(M_counters[P_NbOfCallUsed]) * (double)(M_counters[P_Squares])) - ((double)(M_counters[P_SumCounter] * M_counters[P_SumCounter]));
    double denominator = (double)(M_counters[P_NbOfCallUsed]) * (((double)(M_counters[P_NbOfCallUsed])) - 1.0);

    return sqrt(numerator / denominator);
}

double CStat::computeMean(E_CounterName P_SumCounter,
                          E_CounterName P_NbOfCallUsed)
{
    if (M_counters[P_NbOfCallUsed] == 0)
        return 0.0;
    return (double)(M_counters[P_SumCounter]) / (double)(M_counters[P_NbOfCallUsed]);
}

double CStat::computeRtdMean(int which, int type)
{
    unsigned long long count = M_rtdInfo[((which - 1) * RTD_TYPES * GENERIC_TYPES) + (type * RTD_TYPES) +  RTD_COUNT];
    unsigned long long sum = M_rtdInfo[((which - 1) * RTD_TYPES * GENERIC_TYPES) + (type * RTD_TYPES) +  RTD_SUM];

    if (count == 0)
        return 0.0;
    return (double)(sum) / (double)(count);
}

double CStat::computeRtdStdev(int which, int type)
{
    unsigned long long count = M_rtdInfo[((which - 1) * RTD_TYPES * GENERIC_TYPES) + (type * RTD_TYPES) +  RTD_COUNT];
    unsigned long long sum = M_rtdInfo[((which - 1) * RTD_TYPES * GENERIC_TYPES) + (type * RTD_TYPES) +  RTD_SUM];
    unsigned long long sumsq = M_rtdInfo[((which - 1) * RTD_TYPES * GENERIC_TYPES) + (type * RTD_TYPES) +  RTD_SUMSQ];

    if (count <= 1)
        return 0.0;

    double numerator = ((double)count * (double)sumsq) - (double)(sum * sum);
    double denominator = (double)(count) * ((double)(count) - 1.0);

    return sqrt(numerator / denominator);
}

void CStat::updateAverageCounter(E_CounterName P_SumCounter,
                                 E_CounterName P_NbOfCallUsed,
                                 E_CounterName P_Squares,
                                 unsigned long P_value)
{
    if (M_counters [P_NbOfCallUsed] <= 0) {
        M_counters [P_NbOfCallUsed]++;
        M_counters [P_SumCounter] = P_value;
        M_counters [P_Squares] = P_value * P_value;
    } else {
        M_counters [P_NbOfCallUsed]++;
        M_counters [P_SumCounter] += P_value;
        M_counters [P_Squares] += P_value * P_value;
    }
}

int CStat::computeStat(E_Action P_action,
                       unsigned long P_value)
{
    return computeStat(P_action, P_value, 0);
}

int CStat::findCounter(const char* counter)
{
    str_int_map::iterator it = M_genericMap.find(str_int_map::key_type(counter));
    if (it != M_genericMap.end()) {
        return it->second;
    }
    int ret = M_genericMap.size() + 1;
    M_genericMap[str_int_map::key_type(counter)] = ret;

    bool numeric = true;
    const char *p = counter;
    while (*p) {
        if (!isdigit(*p)) {
            numeric = false;
            break;
        }
        p++;
    }

    if (numeric) {
        char *s = new char[20];
        snprintf(s, 20, "GenericCounter%s", counter);
        M_revGenericMap[ret] = s;
        M_genericDisplay[ret] = strdup(counter);
    } else {
        M_revGenericMap[ret] = strdup(counter);
        M_genericDisplay[ret] = strdup(counter);
    }

    M_genericCounters = (unsigned long long*)realloc(M_genericCounters, sizeof(unsigned long long) * GENERIC_TYPES * M_genericMap.size());
    if (!M_genericCounters) {
        ERROR("Could not allocate generic counters!\n");
    }

    M_genericCounters[(ret - 1) * GENERIC_TYPES + GENERIC_C] = 0;
    M_genericCounters[(ret - 1) * GENERIC_TYPES + GENERIC_PD] = 0;
    M_genericCounters[(ret - 1) * GENERIC_TYPES + GENERIC_PL] = 0;

    return ret;
}

int CStat::findRtd(std::string const& name, bool start)
{
    str_int_map::iterator it = M_rtdMap.find(str_int_map::key_type(name));
    if (it != M_rtdMap.end()) {
        if (start) {
            rtd_started[it->first] = true;
        } else {
            rtd_stopped[it->first] = true;
        }
        return it->second;
    }

    int ret = M_rtdMap.size() + 1;
    M_rtdMap.emplace(name, ret);
    M_revRtdMap.emplace(ret, name);
    M_rtdInfo.resize(sizeof(unsigned long long) * RTD_TYPES * GENERIC_TYPES * M_rtdMap.size());

    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_COUNT] = 0;
    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_SUM] = 0;
    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_SUMSQ] = 0;

    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_COUNT] = 0;
    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_SUM] = 0;
    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_SUMSQ] = 0;

    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_COUNT] = 0;
    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_SUM] = 0;
    M_rtdInfo[((ret - 1) * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_SUMSQ] = 0;

    M_ResponseTimeRepartition.resize(M_rtdMap.size());

    if (start) {
        rtd_started[name] = true;
    } else {
        rtd_stopped[name] = true;
    }
    return ret;
}

int CStat::nRtds()
{
    return M_rtdMap.size();
}

/* If you start an RTD, then you should be interested in collecting statistics for it. */
void CStat::validateRtds()
{
    for (str_int_map::iterator it = rtd_started.begin(); it != rtd_started.end(); it++) {
        str_int_map::iterator stopit = rtd_stopped.find(it->first);
        if (stopit == rtd_stopped.end() || !stopit->second) {
            ERROR("You have started Response Time Duration %s, but have never stopped it!", it->first.c_str());
        }
    }
}

int CStat::computeStat(E_Action P_action,
                       unsigned long P_value,
                       int which)
{
    switch (P_action) {
    case E_ADD_CALL_DURATION:
        // Updating Cumulative Counter
        updateAverageCounter(CPT_C_AverageCallLength_Sum,
                             CPT_C_NbOfCallUsedForAverageCallLength,
                             CPT_C_AverageCallLength_Squares, P_value);
        update_repartition(M_CallLengthRepartition, P_value);
        // Updating Periodical Diplayed counter
        updateAverageCounter(CPT_PD_AverageCallLength_Sum,
                             CPT_PD_NbOfCallUsedForAverageCallLength,
                             CPT_PD_AverageCallLength_Squares, P_value);
        // Updating Periodical Logging counter
        updateAverageCounter(CPT_PL_AverageCallLength_Sum,
                             CPT_PL_NbOfCallUsedForAverageCallLength,
                             CPT_PL_AverageCallLength_Squares, P_value);
        break;
    case E_ADD_GENERIC_COUNTER:
        M_genericCounters[which * GENERIC_TYPES + GENERIC_C] += P_value;
        M_genericCounters[which * GENERIC_TYPES + GENERIC_PD] += P_value;
        M_genericCounters[which * GENERIC_TYPES + GENERIC_PL] += P_value;
        break;
    case E_ADD_RESPONSE_TIME_DURATION:
        // Updating Cumulative Counter
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_COUNT]++;
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_SUM] += P_value;
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_C * RTD_TYPES) + RTD_SUMSQ] += P_value * P_value;
        update_repartition(M_ResponseTimeRepartition[which], P_value);

        // Updating Periodical Diplayed counter
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_COUNT]++;
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_SUM] += P_value;
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PD * RTD_TYPES) + RTD_SUMSQ] += P_value * P_value;

        // Updating Periodical Logging counter
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_COUNT]++;
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_SUM] += P_value;
        M_rtdInfo[(which * RTD_TYPES * GENERIC_TYPES) + (GENERIC_PL * RTD_TYPES) + RTD_SUMSQ] += P_value * P_value;
        break;
    default:
        ERROR("CStat::ComputeStat() - Unrecognized Action %d\n", P_action);
        return -1;
    } /* end switch */
    return 0;
}

CStat::CStat()
  : M_counters({}),
    M_genericCounters(NULL),
    M_rtdInfo(),
    M_SizeOfResponseTimeRepartition(0),
    M_SizeOfCallLengthRepartition(0),
    M_headerAlreadyDisplayed(false),
    M_fileName(string_format("%s_%s", DEFAULT_FILE_NAME, DEFAULT_EXTENSION)),
    M_outputStream(NULL),
    M_headerAlreadyDisplayedRtt(false),
    M_fileNameRtt(),
    M_outputStreamRtt(NULL),
    M_time_ref(0.0),
    M_dumpRespTime(NULL),
    M_counterDumpRespTime(0)
{
    // reset of all counter
    GET_TIME(&M_startTime);
    M_pdStartTime = M_startTime;
    M_plStartTime = M_startTime;
}

CStat::~CStat()
{
    delete [] M_dumpRespTime;

    if (M_outputStream != NULL) {
        M_outputStream->close();
        delete M_outputStream;
    }

    if (M_outputStreamRtt != NULL) {
        M_outputStreamRtt->close();
        delete M_outputStreamRtt;
    }
}

void CStat::displayData(FILE* f)
{
    long localElapsedTime, globalElapsedTime ;
    struct timeval currentTime;
    float averageCallRate;
    float realInstantCallRate;
    unsigned long numberOfCall;

    GET_TIME(&currentTime);
    // computing the real call rate
    globalElapsedTime = computeDiffTimeInMs(&currentTime, &M_startTime);
    localElapsedTime = computeDiffTimeInMs(&currentTime, &M_pdStartTime);

    // the call rate is for all the call : incoming and outgoing
    numberOfCall = M_counters[CPT_C_IncomingCallCreated] + M_counters[CPT_C_OutgoingCallCreated];
    averageCallRate = globalElapsedTime > 0 ? 1000 * (float)numberOfCall / (float)globalElapsedTime : 0.0;
    numberOfCall = M_counters[CPT_PD_IncomingCallCreated] + M_counters[CPT_PD_OutgoingCallCreated];
    realInstantCallRate = localElapsedTime > 0 ? 1000 * (float)numberOfCall / (float)localElapsedTime : 0.0;

    // display info
    DISPLAY_DLINE();
    // build and display header info
    DISPLAY_TXT("Start Time  ", formatTime(&M_startTime));
    DISPLAY_TXT("Last Reset Time", formatTime(&M_pdStartTime));
    DISPLAY_TXT("Current Time", formatTime(&currentTime));

    // printing the header in the middle
    DISPLAY_CROSS_LINE();
    DISPLAY_HEADER();
    DISPLAY_CROSS_LINE();

    DISPLAY_TXT_COL("Elapsed Time",
                    msToHHMMSSus(localElapsedTime),
                    msToHHMMSSus(globalElapsedTime));

    DISPLAY_VAL_RATEF_COL("Call Rate",
                          realInstantCallRate,
                          averageCallRate);
    DISPLAY_CROSS_LINE();

    DISPLAY_2VAL("Incoming call created",
                 M_counters[CPT_PD_IncomingCallCreated],
                 M_counters[CPT_C_IncomingCallCreated]);
    DISPLAY_2VAL("OutGoing call created",
                 M_counters[CPT_PD_OutgoingCallCreated],
                 M_counters[CPT_C_OutgoingCallCreated]);
    DISPLAY_CUMUL("Total Call created", M_counters[CPT_C_IncomingCallCreated] +
                  M_counters[CPT_C_OutgoingCallCreated]);
    DISPLAY_PERIO("Current Call", M_counters[CPT_C_CurrentCall]);

    if (M_genericMap.size()) {
        DISPLAY_CROSS_LINE();
    }
    for (unsigned int i = 1; i < M_genericMap.size() + 1; i++) {
        std::string s = string_format("Counter %s", M_genericDisplay[i].c_str());
        DISPLAY_2VAL(s.c_str(),
                     M_genericCounters[(i - 1) * GENERIC_TYPES + GENERIC_PD],
                     M_genericCounters[(i - 1) * GENERIC_TYPES + GENERIC_C]);
    }

    DISPLAY_CROSS_LINE();
    DISPLAY_2VAL("Successful call",
                 M_counters[CPT_PD_SuccessfulCall],
                 M_counters[CPT_C_SuccessfulCall]);
    DISPLAY_2VAL("Failed call",
                 M_counters[CPT_PD_FailedCall],
                 M_counters[CPT_C_FailedCall]);
    // DISPLAY_2VAL("Unexpected msg",
    //              M_counters[CPT_PD_UnexpectedMessage],
    //              M_counters[CPT_C_UnexpectedMessage]);


    DISPLAY_CROSS_LINE();
    for (int i = 1; i <= nRtds(); i++) {
        char s[80];

        /* Skip if we aren't stopped. */
        assert(rtd_stopped[M_revRtdMap[i]] == true);

        sprintf(s, "Response Time %s", M_revRtdMap[i].c_str());
        DISPLAY_TXT_COL(s,
                        msToHHMMSSus((unsigned long)computeRtdMean(i, GENERIC_PD)),
                        msToHHMMSSus((unsigned long)computeRtdMean(i, GENERIC_C)));
    }
    /* I Broke this!
      DISPLAY_TXT_COL("Call Length",
                      msToHHMMSSus((unsigned long)computeMean(CPT_PD_AverageCallLength_Sum, CPT_PD_NbOfCallUsedForAverageCallLength)),
                      msToHHMMSSus((unsigned long)computeMean(CPT_C_AverageCallLength_Sum, CPT_C_NbOfCallUsedForAverageCallLength) ));
    */
    DISPLAY_CROSS_LINE();

    for (int i = 1; i <= nRtds(); i++) {
        displayRtdRepartition(f, i);
    }
    DISPLAY_INFO("Average Call Length Repartition");
    display_repartition(f, M_CallLengthRepartition);

    //  DISPLAY_VAL("NbCall Average RT(P)",
    //              M_counters[CPT_PD_NbOfCallUsedForAverageResponseTime]);
    //  DISPLAY_VAL("NbCall Average RT",
    //              M_counters[CPT_C_NbOfCallUsedForAverageResponseTime]);
    //  DISPLAY_VAL("NbCall Average CL",
    //              M_counters[CPT_C_NbOfCallUsedForAverageCallLength]);
    //  DISPLAY_VAL("NbCall Average CL(P)",
    //              M_counters[CPT_PD_NbOfCallUsedForAverageCallLength]);
    DISPLAY_DLINE();
    fflush(f);
} /* end of displayData () */

void CStat::displayStat (FILE *f)
{
    long localElapsedTime, globalElapsedTime;
    struct timeval currentTime;
    float averageCallRate;
    float realInstantCallRate;
    unsigned long numberOfCall;

    GET_TIME(&currentTime);
    // computing the real call rate
    globalElapsedTime = computeDiffTimeInMs (&currentTime, &M_startTime);
    localElapsedTime = computeDiffTimeInMs (&currentTime, &M_pdStartTime);
    // the call rate is for all the call : incoming and outgoing
    numberOfCall = M_counters[CPT_C_IncomingCallCreated] + M_counters[CPT_C_OutgoingCallCreated];
    averageCallRate = globalElapsedTime > 0 ? 1000 * (float)numberOfCall/(float)globalElapsedTime : 0.0;
    numberOfCall = M_counters[CPT_PD_IncomingCallCreated] + M_counters[CPT_PD_OutgoingCallCreated];
    realInstantCallRate = localElapsedTime  > 0 ? 1000 * (float)numberOfCall / (float)localElapsedTime : 0.0;

    // build and display header info
    DISPLAY_TXT("Start Time  ", formatTime(&M_startTime));
    DISPLAY_TXT("Last Reset Time", formatTime(&M_pdStartTime));
    DISPLAY_TXT("Current Time", formatTime(&currentTime));

    // printing the header in the middle
    DISPLAY_CROSS_LINE();
    DISPLAY_HEADER();
    DISPLAY_CROSS_LINE();

    DISPLAY_TXT_COL("Elapsed Time",
                    msToHHMMSSus(localElapsedTime),
                    msToHHMMSSus(globalElapsedTime));

    DISPLAY_VAL_RATEF_COL("Call Rate", realInstantCallRate, averageCallRate);
    DISPLAY_CROSS_LINE();

    DISPLAY_2VAL("Incoming call created",
                 M_counters[CPT_PD_IncomingCallCreated],
                 M_counters[CPT_C_IncomingCallCreated]);
    DISPLAY_2VAL("OutGoing call created",
                 M_counters[CPT_PD_OutgoingCallCreated],
                 M_counters[CPT_C_OutgoingCallCreated]);
    DISPLAY_CUMUL("Total Call created",
                  M_counters[CPT_C_IncomingCallCreated] + M_counters[CPT_C_OutgoingCallCreated]);
    DISPLAY_PERIO("Current Call",
                  M_counters[CPT_C_CurrentCall]);

    if (M_genericMap.size()) {
        DISPLAY_CROSS_LINE ();
    }
    for (unsigned int i = 1; i < M_genericMap.size() + 1; i++) {
        std::string s = string_format("Counter %s", M_genericDisplay[i].c_str());
        DISPLAY_2VAL(s.c_str(),
                     M_genericCounters[(i - 1) * GENERIC_TYPES + GENERIC_PD],
                     M_genericCounters[(i - 1) * GENERIC_TYPES + GENERIC_C]);
    }

    DISPLAY_CROSS_LINE ();
    DISPLAY_2VAL("Successful call",
                 M_counters[CPT_PD_SuccessfulCall],
                 M_counters[CPT_C_SuccessfulCall]);
    DISPLAY_2VAL("Failed call",
                 M_counters[CPT_PD_FailedCall],
                 M_counters[CPT_C_FailedCall]);
    //DISPLAY_2VAL("Unexpected msg",
    //             M_counters[CPT_PD_UnexpectedMessage],
    //             M_counters[CPT_C_UnexpectedMessage]);

    DISPLAY_CROSS_LINE();
    for (int i = 1; i <= nRtds(); i++) {
        char s[80];

        sprintf(s, "Response Time %s", M_revRtdMap[i].c_str());
        DISPLAY_TXT_COL(s,
                        msToHHMMSSus((unsigned long)computeRtdMean(i, GENERIC_PD)),
                        msToHHMMSSus((unsigned long)computeRtdMean(i, GENERIC_C)));
    }
    DISPLAY_TXT_COL("Call Length",
                    msToHHMMSSus((unsigned long)computeMean(CPT_PD_AverageCallLength_Sum, CPT_PD_NbOfCallUsedForAverageCallLength ) ),
                    msToHHMMSSus((unsigned long)computeMean(CPT_C_AverageCallLength_Sum, CPT_C_NbOfCallUsedForAverageCallLength) ));
    fflush(f);
}

void CStat::displayRepartition(FILE* f)
{
    displayRtdRepartition(f, 1);
    DISPLAY_INFO("Average Call Length Repartition");
    display_repartition(f, M_CallLengthRepartition);
}

void CStat::displayRtdRepartition(FILE* f, int which)
{
    if (which > nRtds()) {
        DISPLAY_INFO("  <No repartion defined>");
        return;
    }

    char s[80];
    snprintf(s, sizeof(s), "Average Response Time Repartition %s", M_revRtdMap[which].c_str());
    DISPLAY_INFO(s);
    display_repartition(f, M_ResponseTimeRepartition.at(which - 1));
}

void CStat::dumpData()
{
    long localElapsedTime, globalElapsedTime;
    struct timeval currentTime;
    float averageCallRate;
    float realInstantCallRate;
    unsigned long numberOfCall;

    // computing the real call rate
    GET_TIME(&currentTime);
    globalElapsedTime = computeDiffTimeInMs (&currentTime, &M_startTime);
    localElapsedTime = computeDiffTimeInMs (&currentTime, &M_plStartTime);

    // the call rate is for all the call : incoming and outgoing
    numberOfCall = M_counters[CPT_C_IncomingCallCreated] + M_counters[CPT_C_OutgoingCallCreated];
    averageCallRate = globalElapsedTime > 0 ? 1000 * (float)numberOfCall / (float)globalElapsedTime : 0.0;
    numberOfCall = M_counters[CPT_PL_IncomingCallCreated] + M_counters[CPT_PL_OutgoingCallCreated];
    realInstantCallRate = localElapsedTime  > 0 ? 1000 * (float)numberOfCall / (float)localElapsedTime : 0.0;

    if (M_outputStream == NULL) {
        // if the file is still not opened, we opened it now
        M_outputStream = new ofstream(M_fileName);
        M_headerAlreadyDisplayed = false;

        if (M_outputStream == NULL) {
            ERROR_NO("Unable to open stat file %s!", M_fileName.c_str());
        }

#ifndef __osf__
        if (!M_outputStream->is_open()) {
            ERROR_NO("Unable to open stat file %s!", M_fileName.c_str());
        }
#endif

    }

    if (M_headerAlreadyDisplayed == false) {
        // header - it's dump in file only one time at the beginning of the file
        *M_outputStream << "StartTime" << stat_delimiter
                        << "LastResetTime" << stat_delimiter
                        << "CurrentTime" << stat_delimiter
                        << "ElapsedTime(P)" << stat_delimiter
                        << "ElapsedTime(C)" << stat_delimiter
                        << "TargetRate" << stat_delimiter
                        << "CallRate(P)" << stat_delimiter
                        << "CallRate(C)" << stat_delimiter
                        << "IncomingCall(P)" << stat_delimiter
                        << "IncomingCall(C)" << stat_delimiter
                        << "OutgoingCall(P)" << stat_delimiter
                        << "OutgoingCall(C)" << stat_delimiter
                        << "TotalCallCreated" << stat_delimiter
                        << "CurrentCall" << stat_delimiter
                        << "SuccessfulCall(P)" << stat_delimiter
                        << "SuccessfulCall(C)" << stat_delimiter
                        << "FailedCall(P)" << stat_delimiter
                        << "FailedCall(C)" << stat_delimiter
                        << "FailedCannotSendMessage(P)" << stat_delimiter
                        << "FailedCannotSendMessage(C)" << stat_delimiter
                        << "FailedMaxUDPRetrans(P)" << stat_delimiter
                        << "FailedMaxUDPRetrans(C)" << stat_delimiter
                        << "FailedTcpConnect(P)" << stat_delimiter
                        << "FailedTcpConnect(C)" << stat_delimiter
                        << "FailedTcpClosed(P)" << stat_delimiter
                        << "FailedTcpClosed(C)" << stat_delimiter
                        << "FailedUnexpectedMessage(P)" << stat_delimiter
                        << "FailedUnexpectedMessage(C)" << stat_delimiter
                        << "FailedCallRejected(P)" << stat_delimiter
                        << "FailedCallRejected(C)" << stat_delimiter
                        << "FailedCmdNotSent(P)" << stat_delimiter
                        << "FailedCmdNotSent(C)" << stat_delimiter
                        << "FailedRegexpDoesntMatch(P)" << stat_delimiter
                        << "FailedRegexpDoesntMatch(C)" << stat_delimiter
                        << "FailedRegexpShouldntMatch(P)" << stat_delimiter
                        << "FailedRegexpShouldntMatch(C)" << stat_delimiter
                        << "FailedRegexpHdrNotFound(P)" << stat_delimiter
                        << "FailedRegexpHdrNotFound(C)" << stat_delimiter
                        << "FailedOutboundCongestion(P)" << stat_delimiter
                        << "FailedOutboundCongestion(C)" << stat_delimiter
                        << "FailedTimeoutOnRecv(P)" << stat_delimiter
                        << "FailedTimeoutOnRecv(C)" << stat_delimiter
                        << "FailedTimeoutOnSend(P)" << stat_delimiter
                        << "FailedTimeoutOnSend(C)" << stat_delimiter
                        << "OutOfCallMsgs(P)" << stat_delimiter
                        << "OutOfCallMsgs(C)" << stat_delimiter
                        << "DeadCallMsgs(P)" << stat_delimiter
                        << "DeadCallMsgs(C)" << stat_delimiter
                        << "Retransmissions(P)" << stat_delimiter
                        << "Retransmissions(C)" << stat_delimiter
                        << "AutoAnswered(P)" << stat_delimiter
                        << "AutoAnswered(C)" << stat_delimiter
                        << "Warnings(P)" << stat_delimiter
                        << "Warnings(C)" << stat_delimiter
                        << "FatalErrors(P)" << stat_delimiter
                        << "FatalErrors(C)" << stat_delimiter
                        << "WatchdogMajor(P)" << stat_delimiter
                        << "WatchdogMajor(C)" << stat_delimiter
                        << "WatchdogMinor(P)" << stat_delimiter
                        << "WatchdogMinor(C)" << stat_delimiter;

        for (int i = 1; i <= nRtds(); i++) {
            char s_P[80];
            char s_C[80];

            sprintf(s_P, "ResponseTime%s(P)%s", M_revRtdMap[i].c_str(), stat_delimiter);
            sprintf(s_C, "ResponseTime%s(C)%s", M_revRtdMap[i].c_str(), stat_delimiter);

            *M_outputStream << s_P << s_C;

            sprintf(s_P, "ResponseTime%sStDev(P)%s", M_revRtdMap[i].c_str(), stat_delimiter);
            sprintf(s_C, "ResponseTime%sStDev(C)%s", M_revRtdMap[i].c_str(), stat_delimiter);

            *M_outputStream << s_P << s_C;
        }

        *M_outputStream << "CallLength(P)" << stat_delimiter
                        << "CallLength(C)" << stat_delimiter;
        *M_outputStream << "CallLengthStDev(P)" << stat_delimiter
                        << "CallLengthStDev(C)" << stat_delimiter;
        for (unsigned int i = 1; i < M_genericMap.size() + 1; i++) {
            *M_outputStream << M_revGenericMap[i] << "(P)" << stat_delimiter;
            *M_outputStream << M_revGenericMap[i] << "(C)" << stat_delimiter;
        }
        for (int i = 1; i <= nRtds(); i++) {
            char s[80];

            sprintf(s, "ResponseTimeRepartition%s", M_revRtdMap[i].c_str());
            *M_outputStream << repartition_header(M_ResponseTimeRepartition[i - 1], s);
        }
        *M_outputStream << repartition_header(M_CallLengthRepartition,
                                              "CallLengthRepartition");
        *M_outputStream << endl;
        M_headerAlreadyDisplayed = true;
    }

    // content
    *M_outputStream << formatTime(&M_startTime) << stat_delimiter;
    *M_outputStream << formatTime(&M_plStartTime) << stat_delimiter;
    *M_outputStream << formatTime(&currentTime) << stat_delimiter
                    << msToHHMMSS(localElapsedTime) << stat_delimiter;
    *M_outputStream << msToHHMMSS(globalElapsedTime) << stat_delimiter;
    if (users >= 0) {
        *M_outputStream << users << stat_delimiter;
    } else {
        *M_outputStream << rate << stat_delimiter;
    }
    *M_outputStream << realInstantCallRate                    << stat_delimiter
                    << averageCallRate                        << stat_delimiter
                    << M_counters[CPT_PL_IncomingCallCreated] << stat_delimiter
                    << M_counters[CPT_C_IncomingCallCreated]  << stat_delimiter
                    << M_counters[CPT_PL_OutgoingCallCreated] << stat_delimiter
                    << M_counters[CPT_C_OutgoingCallCreated]  << stat_delimiter
                    << M_counters[CPT_C_IncomingCallCreated] + M_counters[CPT_C_OutgoingCallCreated] << stat_delimiter
                    << M_counters[CPT_C_CurrentCall]          << stat_delimiter
                    << M_counters[CPT_PL_SuccessfulCall]      << stat_delimiter
                    << M_counters[CPT_C_SuccessfulCall]       << stat_delimiter
                    << M_counters[CPT_PL_FailedCall]          << stat_delimiter
                    << M_counters[CPT_C_FailedCall]           << stat_delimiter
                    << M_counters[CPT_PL_FailedCallCannotSendMessage]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallCannotSendMessage]    << stat_delimiter
                    << M_counters[CPT_PL_FailedCallMaxUdpRetrans]       << stat_delimiter
                    << M_counters[CPT_C_FailedCallMaxUdpRetrans     ]   << stat_delimiter
                    << M_counters[CPT_PL_FailedCallTcpConnect]          << stat_delimiter
                    << M_counters[CPT_C_FailedCallTcpConnect]           << stat_delimiter
                    << M_counters[CPT_PL_FailedCallTcpClosed]          << stat_delimiter
                    << M_counters[CPT_C_FailedCallTcpClosed]           << stat_delimiter
                    << M_counters[CPT_PL_FailedCallUnexpectedMessage]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallUnexpectedMessage]    << stat_delimiter
                    << M_counters[CPT_PL_FailedCallCallRejected]        << stat_delimiter
                    << M_counters[CPT_C_FailedCallCallRejected]         << stat_delimiter
                    << M_counters[CPT_PL_FailedCallCmdNotSent]          << stat_delimiter
                    << M_counters[CPT_C_FailedCallCmdNotSent]           << stat_delimiter
                    << M_counters[CPT_PL_FailedCallRegexpDoesntMatch]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallRegexpDoesntMatch]    << stat_delimiter
                    << M_counters[CPT_PL_FailedCallRegexpShouldntMatch] << stat_delimiter
                    << M_counters[CPT_C_FailedCallRegexpShouldntMatch]  << stat_delimiter
                    << M_counters[CPT_PL_FailedCallRegexpHdrNotFound]   << stat_delimiter
                    << M_counters[CPT_C_FailedCallRegexpHdrNotFound]    << stat_delimiter
                    << M_counters[CPT_PL_FailedOutboundCongestion]      << stat_delimiter
                    << M_counters[CPT_C_FailedOutboundCongestion]       << stat_delimiter
                    << M_counters[CPT_PL_FailedTimeoutOnRecv]           << stat_delimiter
                    << M_counters[CPT_C_FailedTimeoutOnRecv]            << stat_delimiter
                    << M_counters[CPT_PL_FailedTimeoutOnSend]           << stat_delimiter
                    << M_counters[CPT_C_FailedTimeoutOnSend]            << stat_delimiter
                    << M_G_counters[CPT_G_PL_OutOfCallMsgs - E_NB_COUNTER - 1]                << stat_delimiter
                    << M_G_counters[CPT_G_C_OutOfCallMsgs - E_NB_COUNTER - 1]                 << stat_delimiter
                    << M_G_counters[CPT_G_PL_DeadCallMsgs - E_NB_COUNTER - 1]                 << stat_delimiter
                    << M_G_counters[CPT_G_C_DeadCallMsgs - E_NB_COUNTER - 1]                  << stat_delimiter
                    << M_counters[CPT_PL_Retransmissions]               << stat_delimiter
                    << M_counters[CPT_C_Retransmissions]                << stat_delimiter
                    << M_G_counters[CPT_G_PL_AutoAnswered - E_NB_COUNTER - 1]                  << stat_delimiter
                    << M_G_counters[CPT_G_C_AutoAnswered - E_NB_COUNTER - 1]                   << stat_delimiter
                    << M_G_counters[CPT_G_PL_Warnings - E_NB_COUNTER - 1]                  << stat_delimiter
                    << M_G_counters[CPT_G_C_Warnings - E_NB_COUNTER - 1]                   << stat_delimiter
                    << M_G_counters[CPT_G_PL_FatalErrors - E_NB_COUNTER - 1]                  << stat_delimiter
                    << M_G_counters[CPT_G_C_FatalErrors - E_NB_COUNTER - 1]                   << stat_delimiter
                    << M_G_counters[CPT_G_PL_WatchdogMajor - E_NB_COUNTER - 1]                  << stat_delimiter
                    << M_G_counters[CPT_G_C_WatchdogMajor - E_NB_COUNTER - 1]                   << stat_delimiter
                    << M_G_counters[CPT_G_PL_WatchdogMinor - E_NB_COUNTER - 1]                  << stat_delimiter
                    << M_G_counters[CPT_G_C_WatchdogMinor - E_NB_COUNTER - 1]                   << stat_delimiter;

    // SF917289 << M_counters[CPT_C_UnexpectedMessage]    << stat_delimiter;
    for (int i = 1; i <= nRtds(); i++) {
        *M_outputStream << msToHHMMSSus((unsigned long)computeRtdMean(i, GENERIC_PL)) << stat_delimiter;
        *M_outputStream << msToHHMMSSus((unsigned long)computeRtdMean(i, GENERIC_C)) << stat_delimiter;
        *M_outputStream << msToHHMMSSus((unsigned long)computeRtdStdev(i, GENERIC_PL)) << stat_delimiter;
        *M_outputStream << msToHHMMSSus((unsigned long)computeRtdStdev(i, GENERIC_C)) << stat_delimiter;
    }
    *M_outputStream << msToHHMMSSus((unsigned long)computeMean(CPT_PL_AverageCallLength_Sum, CPT_PL_NbOfCallUsedForAverageCallLength) ) << stat_delimiter;
    *M_outputStream << msToHHMMSSus((unsigned long)computeMean(CPT_C_AverageCallLength_Sum, CPT_C_NbOfCallUsedForAverageCallLength) ) << stat_delimiter;
    *M_outputStream << msToHHMMSSus((unsigned long)computeStdev(CPT_PL_AverageCallLength_Sum,
                                                                CPT_PL_NbOfCallUsedForAverageCallLength,
                                                                CPT_PL_AverageCallLength_Squares)) << stat_delimiter;
    *M_outputStream << msToHHMMSSus((unsigned long)computeStdev(CPT_C_AverageCallLength_Sum,
                                                                CPT_C_NbOfCallUsedForAverageCallLength,
                                                                CPT_C_AverageCallLength_Squares)) << stat_delimiter;

    for (unsigned int i = 0; i < M_genericMap.size(); i++) {
        *M_outputStream << M_genericCounters[GENERIC_TYPES * i + GENERIC_PL] << stat_delimiter;
        *M_outputStream << M_genericCounters[GENERIC_TYPES * i + GENERIC_C] << stat_delimiter;
    }

    for (int i = 0; i < nRtds(); i++) {
        *M_outputStream << repartition_info(M_ResponseTimeRepartition[i]);
    }
    *M_outputStream << repartition_info(M_CallLengthRepartition);
    *M_outputStream << endl;

    // flushing the output file to let the tail -f working !
    M_outputStream->flush();
}

void CStat::dumpDataRtt ()
{
    if (M_outputStreamRtt == NULL) {
        // if the file is still not opened, we opened it now
        M_outputStreamRtt = new ofstream(M_fileNameRtt);
        M_headerAlreadyDisplayedRtt = false;

        if (M_outputStreamRtt == NULL) {
            ERROR_NO("Unable to open rtt file %s!", M_fileNameRtt.c_str());
        }

#ifndef __osf__
        if(!M_outputStreamRtt->is_open()) {
            ERROR_NO("Unable to open rtt file %s!", M_fileNameRtt.c_str());
        }
#endif
    }

    if(M_headerAlreadyDisplayedRtt == false) {
        *M_outputStreamRtt << "Date_ms" << stat_delimiter
                           << "response_time_ms" << stat_delimiter
                           << "rtd_no" << endl;
        M_headerAlreadyDisplayedRtt = true;
    }

    for (unsigned int L_i = 0; L_i < M_counterDumpRespTime; L_i++) {
        *M_outputStreamRtt <<  M_dumpRespTime[L_i].date << stat_delimiter;
        *M_outputStreamRtt <<  M_dumpRespTime[L_i].rtt << stat_delimiter;
        *M_outputStreamRtt <<  M_revRtdMap[M_dumpRespTime[L_i].rtd_no] << endl;
        M_outputStreamRtt->flush();
        M_dumpRespTime[L_i].date = 0.0;
        M_dumpRespTime[L_i].rtt = 0.0;
        M_dumpRespTime[L_i].rtd_no = 0;
    }

    // flushing the output file
    M_outputStreamRtt->flush();
    M_counterDumpRespTime = 0;
}

/* Time Gestion */
char* CStat::msToHHMMSS(unsigned long P_ms)
{
    static char L_time[TIME_LENGTH];
    unsigned long hh, mm, ss;

    P_ms = P_ms / 1000;
    hh = P_ms / 3600;
    mm = (P_ms - hh * 3600) / 60;
    ss = P_ms - (hh * 3600) - (mm * 60);
    sprintf(L_time, "%2.2lu:%2.2lu:%2.2lu", hh, mm, ss);
    return L_time;
}

char* CStat::msToHHMMSSus(unsigned long P_ms)
{
    static char L_time[TIME_LENGTH];
    unsigned long sec, hh, mm, ss, us;

    sec = P_ms / 1000;
    hh = sec / 3600;
    mm = (sec - hh * 3600) / 60;
    ss = sec - (hh * 3600) - (mm * 60);
    us = 1000*(P_ms - (hh * 3600000) - (mm * 60000) - (ss*1000));
    sprintf(L_time, "%2.2lu:%2.2lu:%2.2lu:%06lu", hh, mm, ss, us);
    return  L_time;
}

char* CStat::formatTime(struct timeval* P_tv, bool with_epoch)
{
    static char L_time[TIME_LENGTH];
    struct tm* L_currentDate;

    // Get the current date and time
    L_currentDate = localtime((const time_t*)&P_tv->tv_sec);

    // Format the time
    if (L_currentDate == NULL) {
        memset(L_time, 0, TIME_LENGTH);
    } else {
        if (with_epoch) {
            sprintf(L_time, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d.%06ld",
                    L_currentDate->tm_year + 1900,
                    L_currentDate->tm_mon + 1,
                    L_currentDate->tm_mday,
                    L_currentDate->tm_hour,
                    L_currentDate->tm_min,
                    L_currentDate->tm_sec,
                    (long)P_tv->tv_usec);
        } else {
            sprintf(L_time, "%4.4d-%2.2d-%2.2d\t%2.2d:%2.2d:%2.2d.%06ld\t%10.10ld.%06ld",
                    L_currentDate->tm_year + 1900,
                    L_currentDate->tm_mon + 1,
                    L_currentDate->tm_mday,
                    L_currentDate->tm_hour,
                    L_currentDate->tm_min,
                    L_currentDate->tm_sec,
                    (long)P_tv->tv_usec,
                    P_tv->tv_sec,
                    (long)P_tv->tv_usec);
        }
    }
    return L_time;
}

long CStat::computeDiffTimeInMs(struct timeval* tf, struct timeval* ti)
{
    long v1, v2;

    v1 = tf->tv_sec - ti->tv_sec;
    v2 = tf->tv_usec - ti->tv_usec;
    if (v2 < 0) {
        v2 += 1000000;
        v1--;
    }
    return v1 * 1000 + v2 / 1000;
}

/* Implementation of a fixed distribution. */
CFixed::CFixed(double value)
{
    this->value = value;
}
double CFixed::sample()
{
    return value;
}
int CFixed::textDescr(char *s, int len)
{
    return snprintf(s, len, "%lf", value);
}
int CFixed::timeDescr(char *s, int len)
{
    return time_string(value, s, len);
}
double CFixed::cdfInv(double /*percentile*/)
{
    return value;
}

/* Implementation of the default pause time. */
CDefaultPause::CDefaultPause()
{
}
double CDefaultPause::sample()
{
    return (double)duration;
}
int CDefaultPause::textDescr(char* s, int len)
{
    return snprintf(s, len, "%d", duration);
}
int CDefaultPause::timeDescr(char* s, int len)
{
    return time_string(duration, s, len);
}
double CDefaultPause::cdfInv(double /*percentile*/)
{
    return duration;
}

/* Implementation of a uniform distribution. */
static bool uniform_init = false;
CUniform::CUniform(double min, double max)
{
    if (!uniform_init) {
        uniform_init = true;
        srand(time(NULL));
    }
    this->min = min;
    this->max = max;
}
double CUniform::sample()
{
    double rval = ((double)rand())/((double)RAND_MAX);
    return min + (rval * (max - min));
}
int CUniform::textDescr(char *s, int len)
{
    return snprintf(s, len, "%lf/%lf", min, max);
}
int CUniform::timeDescr(char *s, int len)
{
    int used = time_string(min, s, len);
    used += snprintf(s + used, len - used, "/");
    used += time_string(max, s + used, len - used);
    return used;
}
double CUniform::cdfInv(double percentile)
{
    return min + (max * percentile);
}

#ifdef HAVE_GSL
gsl_rng *gsl_init()
{
    static gsl_rng *rng = NULL;

    if (rng) {
        return rng;
    }

    gsl_rng_env_setup();
    rng = gsl_rng_alloc(gsl_rng_default);
    if (!rng) {
        ERROR("Could not initialize GSL random number generator.\n");
    }

    return rng;
}

/* Normal distribution. */
CNormal::CNormal(double mean, double stdev)
{
    this->mean = mean;
    this->stdev = stdev;
    rng = gsl_init();
}

double CNormal::sample()
{
    double val = gsl_ran_gaussian(rng, stdev);
    return val + mean;
}

int CNormal::textDescr(char* s, int len)
{
    return snprintf(s, len, "N(%.3lf,%.3lf)", mean, stdev);
}
int CNormal::timeDescr(char* s, int len)
{
    int used = 0;

    used += snprintf(s, len, "N(");
    used += time_string(mean, s + used, len - used);
    used += snprintf(s + used, len - used, ",");
    used += time_string(stdev, s + used, len - used);
    used += snprintf(s + used, len - used, ")");

    return used;
}
double CNormal::cdfInv(double percentile)
{
    return mean + gsl_cdf_gaussian_Pinv(percentile, stdev);
}

/* Lognormal distribution. */
double CLogNormal::sample()
{
    return gsl_ran_lognormal(rng, mean, stdev);
}
int CLogNormal::textDescr(char* s, int len)
{
    if (len == 0)
        return 0;
    s[0] = 'L';
    return 1 + this->CNormal::textDescr(s + 1, len - 1);
}
int CLogNormal::timeDescr(char* s, int len)
{
    if (len == 0)
        return 0;
    s[0] = 'L';
    return 1 + this->CNormal::timeDescr(s + 1, len - 1);
}
double CLogNormal::cdfInv(double percentile)
{
    return gsl_cdf_lognormal_Pinv(percentile, mean, stdev);
}

/* Exponential distribution. */
CExponential::CExponential(double mean)
{
    this->mean = mean;
    rng = gsl_init();
}

double CExponential::sample()
{
    return gsl_ran_exponential(rng, mean);
}

int CExponential::textDescr(char* s, int len)
{
    return snprintf(s, len, "Exp(%lf)", mean);
}
int CExponential::timeDescr(char* s, int len)
{
    int used = snprintf(s, len, "Exp(");
    used += time_string(mean, s + used, len - used);
    used += snprintf(s + used, len - used, ")");
    return used;
}
double CExponential::cdfInv(double percentile)
{
    return gsl_cdf_exponential_Pinv(percentile, mean);
}

/* Weibull distribution. */
CWeibull::CWeibull(double lambda, double k)
{
    this->lambda = lambda;
    this->k = k;
    rng = gsl_init();
}

double CWeibull::sample()
{
    return gsl_ran_weibull(rng, lambda, k);
}

int CWeibull::textDescr(char* s, int len)
{
    return snprintf(s, len, "Wb(%.3lf,%.3lf)", lambda, k);
}
int CWeibull::timeDescr(char* s, int len)
{
    int used = 0;

    used += snprintf(s, len, "Wb(");
    used += time_string(lambda, s + used, len - used);
    used += snprintf(s + used, len - used, ",");
    used += time_string(k, s + used, len - used);
    used += snprintf(s + used, len - used, ")");

    return used;
}
double CWeibull::cdfInv(double percentile)
{
    return gsl_cdf_weibull_Pinv(percentile, lambda, k);
}

/* Pareto distribution. */
CPareto::CPareto(double k, double xsubm)
{
    this->k = k;
    this->xsubm = xsubm;
    rng = gsl_init();
}

double CPareto::sample()
{
    return gsl_ran_pareto(rng, k, xsubm);
}

int CPareto::textDescr(char* s, int len)
{
    return snprintf(s, len, "P(%.3lf,%.3lf)", k, xsubm);
}
int CPareto::timeDescr(char* s, int len)
{
    int used = 0;

    used += snprintf(s, len, "P(");
    used += time_string(k, s + used, len - used);
    used += snprintf(s + used, len - used, ",");
    used += time_string(xsubm, s + used, len - used);
    used += snprintf(s + used, len - used, ")");

    return used;
}
double CPareto::cdfInv(double percentile)
{
    return gsl_cdf_pareto_Pinv(percentile, k, xsubm);
}

/* Generalized Pareto distribution. */
CGPareto::CGPareto(double shape, double scale, double location)
{
    this->shape = shape;
    this->scale = scale;
    this->location = location;
    rng = gsl_init();
}

double CGPareto::sample()
{
    return cdfInv(gsl_ran_flat(rng, 0.0, 1.0));
}

int CGPareto::textDescr(char* s, int len)
{
    return snprintf(s, len, "P(%.3lf,%.3lf,%.3f)", shape, scale, location);
}
int CGPareto::timeDescr(char* s, int len)
{
    int used = 0;

    used += snprintf(s, len, "P(");
    used += time_string(shape, s + used, len - used);
    used += snprintf(s + used, len - used, ",");
    used += time_string(scale, s + used, len - used);
    used += snprintf(s + used, len - used, ",");
    used += time_string(location, s + used, len - used);
    used += snprintf(s + used, len - used, ")");

    return used;
}
double CGPareto::cdfInv(double percentile)
{
    return location + ((scale * (pow(percentile, -shape) - 1))/shape);
}

/* Gamma distribution. */
CGamma::CGamma(double k, double theta)
{
    this->k = k;
    this->theta = theta;
    rng = gsl_init();
}

double CGamma::sample()
{
    return gsl_ran_gamma(rng, k, theta);
}

int CGamma::textDescr(char *s, int len)
{
    return snprintf(s, len, "G(%.3lf,%.3lf)", k, theta);
}
int CGamma::timeDescr(char *s, int len)
{
    int used = 0;

    used += snprintf(s, len, "G(");
    used += time_string(k, s + used, len - used);
    used += snprintf(s + used, len - used, ",");
    used += time_string(theta, s + used, len - used);
    used += snprintf(s + used, len - used, ")");

    return used;
}
double CGamma::cdfInv(double percentile)
{
    return gsl_cdf_gamma_Pinv(percentile, k, theta);
}

/* NegBin distribution. */
CNegBin::CNegBin(double p, double n)
{
    this->p = p;
    this->n = n;
    rng = gsl_init();
}

double CNegBin::sample()
{
    return gsl_ran_negative_binomial(rng, n, p);
}

int CNegBin::textDescr(char* s, int len)
{
    return snprintf(s, len, "NB(%.3lf,%.3lf)", p, n);
}
int CNegBin::timeDescr(char* s, int len)
{
    int used = 0;

    used += snprintf(s, len, "NB(");
    used += time_string(p, s + used, len - used);
    used += snprintf(s + used, len - used, ",");
    used += time_string(n, s + used, len - used);
    used += snprintf(s + used, len - used, ")");

    return used;
}
/* We really don't implement this, but should so that sanity checking will
 * work. For now, just return zero. */
double CNegBin::cdfInv(double percentile)
{
    return 0;
}
#endif


#ifdef GTEST
#include "gtest/gtest.h"
#include "gmock/gmock.h"

using ::testing::ElementsAre;
using ::testing::IsEmpty;

TEST(utility, is_well_formed) {
    int count;

    ASSERT_EQ(1, is_well_formed("", &count));
    ASSERT_EQ(count, 0);
    ASSERT_EQ(1, is_well_formed("1", &count));
    ASSERT_EQ(count, 1);
    ASSERT_EQ(1, is_well_formed("1,23", &count));
    ASSERT_EQ(count, 2);
    ASSERT_EQ(1, is_well_formed("1,23,345", &count));
    ASSERT_EQ(count, 3);
    ASSERT_EQ(1, is_well_formed("1,23,345,6789", &count));
    ASSERT_EQ(count, 4);

    ASSERT_EQ(0, is_well_formed("123,abc", &count));
    ASSERT_EQ(count, 1);

    // Whitespace is allowed between numbers
    ASSERT_EQ(1, is_well_formed("\t1, 23,   345,\t6789     ", &count));
    ASSERT_EQ(count, 4);

    // Whitespace is apparently allowed between digits, and only the
    // first digit is parsed
    ASSERT_EQ(1, is_well_formed("1 3   4 6", &count));
    ASSERT_EQ(count, 1);

    // Stray commas aren't valid, they must seperate numbers
    ASSERT_EQ(0, is_well_formed("1,", &count));
    ASSERT_EQ(count, 1);
    ASSERT_EQ(0, is_well_formed(",", &count));
    ASSERT_EQ(count, 0);

    // Here because of the explicit '\0' handling / strlen call
    ASSERT_EQ(1, is_well_formed("1,23\0,345,6789,", &count));
    ASSERT_EQ(count, 2);
}

TEST(utility, integer_table) {
    ASSERT_THAT(integer_table("1"), ElementsAre(1));
    ASSERT_THAT(integer_table("1,23"), ElementsAre(1, 23));

    // Whitespace is allowed between numbers
    ASSERT_THAT(integer_table("\t1, 23,   345,\t6789     "), ElementsAre(1, 23, 345, 6789));

    // Whitespace is apparently allowed between digits, and only the
    // first digit is parsed
    ASSERT_THAT(integer_table("1 3   4 6"), ElementsAre(1));

    // Empty and invalid strings should return an empty vector
    ASSERT_THAT(integer_table(""), IsEmpty());
    ASSERT_THAT(integer_table(","), IsEmpty());
}

TEST(utility, make_repartitions) {
    /* <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>\n */
    auto data = integer_table("10,20,30,40,50,100,150,200");
    ASSERT_THAT(make_repartitions(data),
                ElementsAre(repartition(10),
                            repartition(20),
                            repartition(30),
                            repartition(40),
                            repartition(50),
                            repartition(100),
                            repartition(150),
                            repartition(200),
                            repartition(200)));

    /* <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/> */
    data = integer_table("10,50,100,500,1000,5000,10000");
    ASSERT_THAT(make_repartitions(data),
                ElementsAre(repartition(10),
                            repartition(50),
                            repartition(100),
                            repartition(500),
                            repartition(1000),
                            repartition(5000),
                            repartition(10000),
                            repartition(10000)));

    /* The repartition array should be sorted */
    data = integer_table("10000,5000,1000,500,100,50,10");
    ASSERT_THAT(make_repartitions(data),
                ElementsAre(repartition(10),
                            repartition(50),
                            repartition(100),
                            repartition(500),
                            repartition(1000),
                            repartition(5000),
                            repartition(10000),
                            repartition(10000)));
}
#endif
