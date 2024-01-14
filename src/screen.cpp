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

#include <curses.h>

#include "screen.hpp"
#include "sipp.hpp"

/* Export these so others needn't include curses.h */
int key_backspace = KEY_BACKSPACE;
int key_dc = KEY_DC;

int           screen_inited = 0;

ScreenPrinter* sp;

double last_artpstream_rate_out = 0;
double last_vrtpstream_rate_out = 0;
double last_artpstream_rate_in = 0;
double last_vrtpstream_rate_in = 0;

/* ERR is actually -1, but this prevents us from needing to use curses.h in
 * sipp.cpp. */
int screen_readkey()
{
    int c = getch();
    if (c == ERR) {
        return -1;
    }
    return c;
}

void screen_exit()
{
    if (!screen_inited) {
        return;
    }

    clear();
    refresh();
    endwin();
    screen_inited = 0;
}

void screen_init()
{
    if (backgroundMode || screen_inited) {
        return;
    }

    screen_inited = 1;

    setlocale(LC_ALL, "");
    initscr();
    cbreak();
    noecho();
    clear();
}

void print_statistics(int last)
{
    if (backgroundMode == false && display_scenario) {
      sp->redraw();
    }
}

void ScreenPrinter::print_closing_stats() {
    M_last = true;
    get_lines();
    for (auto line : lines) {
        printf("%s\n", line.c_str());
    }

    if (currentScreenToDisplay != DISPLAY_STAT_SCREEN) {
        currentScreenToDisplay = DISPLAY_STAT_SCREEN;
        get_lines();
        for (auto line : lines) {
            printf("%s\n", line.c_str());
        }
    }

}

void ScreenPrinter::print_to_file(FILE* f)
{
    get_lines();
    for (auto line : lines) {
        fprintf(f, "%s\n", line.c_str());
    }
}

extern int command_mode;
extern char* command_buffer;


void ScreenPrinter::redraw()
{
    if (!M_headless) {
        get_lines();
        erase();
        for (auto line : lines) {
            printw("%s\n", line.c_str());
        }

        if (command_mode) {
            printw("\nCommand: %s", command_buffer ? command_buffer : "");
        }

        refresh();
    }
}

void ScreenPrinter::get_lines()
{
    lines.clear();
    switch (currentScreenToDisplay) {
    case DISPLAY_STAT_SCREEN:
        lines.push_back("----------------------------- Statistics Screen "
                        "------- [1-9]: Change Screen --");
        draw_stats_screen();
        break;
    case DISPLAY_REPARTITION_SCREEN:
        lines.push_back("---------------------------- Repartition Screen "
                        "------- [1-9]: Change Screen --");
        draw_repartition_screen(1);
        break;
    case DISPLAY_VARIABLE_SCREEN:
        lines.push_back("----------------------------- Variables Screen "
                        "-------- [1-9]: Change Screen --");
        draw_vars_screen();
        break;
    case DISPLAY_TDM_MAP_SCREEN:
        lines.push_back("------------------------------ TDM map Screen "
                        "--------- [1-9]: Change Screen --");
        draw_tdm_screen();
        break;
    case DISPLAY_SECONDARY_REPARTITION_SCREEN:
        lines.push_back("--------------------------- Repartition " +
                        std::to_string(currentRepartitionToDisplay) +
                        " Screen ------ [1-9]: Change Screen --");
        draw_repartition_screen(currentRepartitionToDisplay);
        break;
    case DISPLAY_SCENARIO_SCREEN:
    default:
        lines.push_back("------------------------------ Scenario Screen "
                        "-------- [1-9]: Change Screen --");
        draw_scenario_screen();
        break;
    }

    unsigned const bufsiz = 80;
    char buf[bufsiz];
    if (!M_last && screen_last_error[0]) {
      char* errstart = screen_last_error;
      int colonsleft = 3; /* We want to skip the time. */
      while (*errstart && colonsleft) {
        if (*errstart == ':') {
          colonsleft--;
        }
        errstart++;
      }
      while (isspace(*errstart)) {
        errstart++;
      }
      snprintf(buf, bufsiz, "Last Error: %.60s...", errstart);
      lines.push_back(buf);
    }

    if (M_last) {
        lines.push_back("------------------------------ Test Terminated "
                   "--------------------------------");
    } else if (quitting) {
        lines.push_back(
            "------- Waiting for active calls to end. Press [q] again "
            "to force exit. -------");
    } else if (paused) {
        lines.push_back("----------------- Traffic Paused - Press [p] again to "
                        "resume ------------------");
    } else if (cpu_max) {
        lines.push_back("-------------------------------- CPU CONGESTED "
                        "---------------------------------");
    } else if (outbound_congestion) {
        lines.push_back("------------------------------ OUTBOUND CONGESTION "
                        "-----------------------------");
    } else {
        if (creationMode == MODE_CLIENT) {
            switch (thirdPartyMode) {
            case MODE_MASTER:
                lines.push_back(
                    "-----------------------3PCC extended mode - Master "
                    "side -------------------------");
                break;
            case MODE_3PCC_CONTROLLER_A:
                lines.push_back(
                    "----------------------- 3PCC Mode - Controller A "
                    "side -------------------------");
                break;
            case MODE_3PCC_NONE:
                lines.push_back(
                    "------ [+|-|*|/]: Adjust rate ---- [q]: Soft exit "
                    "---- [p]: Pause traffic -----");
                break;
            default:
                ERROR("Internal error: creationMode=%d, thirdPartyMode=%d",
                      creationMode, thirdPartyMode);
            }
        } else {
            assert(creationMode == MODE_SERVER);
            switch (thirdPartyMode) {
            case MODE_3PCC_A_PASSIVE:
                lines.push_back(
                    "------------------ 3PCC Mode - Controller A side "
                    "(passive) --------------------");
                break;
            case MODE_3PCC_CONTROLLER_B:
                lines.push_back(
                    "----------------------- 3PCC Mode - Controller B "
                    "side -------------------------");
                break;
            case MODE_MASTER_PASSIVE:
                lines.push_back(
                    "------------------ 3PCC extended mode - Master "
                    "side (passive) --------------------");
                break;
            case MODE_SLAVE:
                lines.push_back(
                    "----------------------- 3PCC extended mode - Slave "
                    "side -------------------------");
                break;
            case MODE_3PCC_NONE:
                lines.push_back(
                    "------------------------------ SIPp Server Mode "
                    "-------------------------------");
                break;
            default:
                ERROR("Internal error: creationMode=%d, thirdPartyMode=%d",
                      creationMode, thirdPartyMode);
            }
        }
    }
}

bool do_hide = true;

void ScreenPrinter::draw_scenario_screen()
{
    unsigned const bufsiz = 100;
    char buf[bufsiz];
    char left_buf[40];
    char left_buf_long[60];
    char right_buf[bufsiz];
    extern int pollnfds;

    unsigned long long total_calls =
        display_scenario->stats->GetStat(CStat::CPT_C_IncomingCallCreated) +
        display_scenario->stats->GetStat(CStat::CPT_C_OutgoingCallCreated);
    if (creationMode == MODE_SERVER) {
        lines.push_back("  Port   Total-time  Total-calls  Transport");
        snprintf(buf, bufsiz, "  %-5d %6lu.%02lu s     %8llu  %s", local_port,
                 clock_tick / 1000, (clock_tick % 1000) / 10, total_calls,
                 TRANSPORT_TO_STRING(transport));
        lines.push_back(buf);
    } else {
        assert(creationMode == MODE_CLIENT);
        if (users >= 0) {
            lines.push_back("  Users (length)   Port   Total-time  "
                            "Total-calls  Remote-host");
            snprintf(buf, bufsiz,
                     "  %d (%d ms)   %-5d %6lu.%02lu s     %8llu  %.20s:%d(%s)",
                     users, duration, local_port, clock_tick / 1000,
                     (clock_tick % 1000) / 10, total_calls, remote_ip,
                     remote_port, TRANSPORT_TO_STRING(transport));
            lines.push_back(buf);
        } else {
            lines.push_back("  Call rate (length)   Port   Total-time  "
                            "Total-calls  Remote-host");
            snprintf(
                buf, bufsiz,
                "  %3.1f(%d ms)/%5.3fs   %-5d %6lu.%02lu s     %8llu  %.20s:%d(%s)",
                rate, duration, (double)rate_period_ms / 1000.0, local_port,
                clock_tick / 1000, (clock_tick % 1000) / 10, total_calls,
                remote_ip, remote_port, TRANSPORT_TO_STRING(transport));
            lines.push_back(buf);
        }
    }
    lines.push_back("");
    /* 1st line */
    unsigned long ms_since_last_tick = clock_tick - last_report_time;
    if (total_calls < stop_after) {
        snprintf(left_buf_long, 60, "%llu new calls during %lu.%03lu s period",
                 display_scenario->stats->GetStat(
                     CStat::CPT_PD_IncomingCallCreated) +
                     display_scenario->stats->GetStat(
                         CStat::CPT_PD_OutgoingCallCreated),
                 ms_since_last_tick / 1000, ms_since_last_tick % 1000);
    } else {
        snprintf(left_buf_long, 60,
                 "Call limit %lu hit, %0.1f s period ", stop_after,
                 (double)ms_since_last_tick / 100.0);
    }
    snprintf(right_buf, 40, "%lu ms scheduler resolution",
             ms_since_last_tick / std::max(scheduling_loops, 1ul));
    snprintf(buf, bufsiz, "  %-38.38s  %-37.37s", left_buf_long, right_buf);
    lines.push_back(buf);

    /* 2nd line */
    if (creationMode == MODE_SERVER) {
        snprintf(left_buf, 40, "%llu calls",
                 display_scenario->stats->GetStat(CStat::CPT_C_CurrentCall));
    } else {
        snprintf(left_buf, 40, "%llu calls (limit %u)",
                 display_scenario->stats->GetStat(CStat::CPT_C_CurrentCall),
                 open_calls_allowed);
    }
    snprintf(
        buf, bufsiz, "  %-38s  Peak was %llu calls, after %llu s", left_buf,
        display_scenario->stats->GetStat(CStat::CPT_C_CurrentCallPeak),
        display_scenario->stats->GetStat(CStat::CPT_C_CurrentCallPeakTime));
    lines.push_back(buf);

    snprintf(buf, bufsiz, "  %d Running, %d Paused, %d Woken up",
             last_running_calls, last_paused_calls, last_woken_calls);
    last_woken_calls = 0;
    lines.push_back(buf);

    /* 3rd line dead call msgs, and optional out-of-call msg */
    snprintf(left_buf, 40, "%llu dead call msg (discarded)",
             display_scenario->stats->GetStat(CStat::CPT_G_C_DeadCallMsgs));
    if (creationMode == MODE_CLIENT) {
        snprintf(
            buf, bufsiz, "  %-38s  %llu out-of-call msg (discarded)", left_buf,
            display_scenario->stats->GetStat(CStat::CPT_G_C_OutOfCallMsgs));
    } else {
        snprintf(buf, bufsiz, "  %-38s", left_buf);
    }
    lines.push_back(buf);

    if (compression) {
        snprintf(buf, bufsiz, "  Comp resync: %d sent, %d recv", resynch_send,
                 resynch_recv);
        lines.push_back(buf);
    }

    if (auto_answer) {
        snprintf(buf, 80, "  %llu requests auto-answered",
                 display_scenario->stats->GetStat(CStat::CPT_G_C_AutoAnswered));
        lines.push_back(buf);
    }

    /* 4th line , sockets and optional errors */
    snprintf(left_buf, 40, "%d open sockets", pollnfds);
    snprintf(buf, bufsiz, "  %-38s  %lu/%lu/%lu %s errors (send/recv/cong)",
             left_buf, nb_net_send_errors, nb_net_recv_errors, nb_net_cong,
             TRANSPORT_TO_STRING(transport));
    lines.push_back(buf);

#ifdef PCAPPLAY
    /* if has media abilities */
    if (hasMedia != 5) {
        snprintf(left_buf, 40, "%lu Total RTP pckts sent ",
                rtp_pckts_pcap);
        if (ms_since_last_tick) {
            snprintf(buf, bufsiz, "  %-38s  %lu.%03lu last period RTP rate (kB/s)",
                    left_buf,
                    rtp_bytes_pcap / ms_since_last_tick,
                    rtp_bytes_pcap % ms_since_last_tick);
        }
        rtp_bytes_pcap = 0;
        rtp2_bytes_pcap = 0;
        lines.push_back(buf);
    }
#endif
    /* if we have rtp stream thread running */
    if (rtpstream_numthreads) {
        unsigned long TempABytes;
        unsigned long TempVBytes;
        if (ms_since_last_tick) {
            TempABytes= rtpstream_abytes_out;
            TempVBytes= rtpstream_vbytes_out;
            /* Calculate integer and fraction parts of rtp bandwidth; this value
             * will be saved and reused in the case where last_tick==last_report_time
             */
            last_artpstream_rate_out= ((double)TempABytes)/ ms_since_last_tick;
            last_vrtpstream_rate_out= ((double)TempVBytes)/ ms_since_last_tick;
            /* Potential race condition between multiple threads updating the
             * rtpstream_bytes value. We subtract the saved TempBytes value
             * rather than setting it to zero to minimise the chances of missing
             * an update to rtpstream_bytes [update between printing stats and
             * zeroing the counter]. Ideally we would atomically subtract
             * TempBytes from rtpstream_bytes.
             */
            rtpstream_abytes_out -= TempABytes;
            rtpstream_vbytes_out -= TempVBytes;
            TempABytes= rtpstream_abytes_in;
            TempVBytes= rtpstream_vbytes_in;
            last_artpstream_rate_in= ((double)TempABytes)/ ms_since_last_tick;
            last_vrtpstream_rate_in= ((double)TempVBytes)/ ms_since_last_tick;
            rtpstream_abytes_in -= TempABytes;
            rtpstream_vbytes_in -= TempVBytes;
        }

        snprintf(left_buf, 40, "%lu Total AUDIO RTP pckts sent", rtpstream_apckts);
        snprintf(buf, bufsiz, "  %-38s  %.3f kB/s AUDIO RTP OUT", left_buf, last_artpstream_rate_out);
        lines.push_back(buf);
        snprintf(left_buf, 40, "%lu Total VIDEO RTP pckts sent", rtpstream_vpckts);
        snprintf(buf, bufsiz, "  %-38s  %.3f KB/s VIDEO RTP OUT", left_buf, last_vrtpstream_rate_out);
        lines.push_back(buf);

        snprintf(left_buf, 40, "%lu RTP sending threads active", rtpstream_numthreads);
        snprintf(buf, bufsiz, "  %-38s  %.3f kB/s AUDIO RTP IN", left_buf, last_artpstream_rate_in);
        lines.push_back(buf);
        snprintf(buf, bufsiz, "  %-38s  %.3f KB/s VIDEO RTP IN", left_buf, last_vrtpstream_rate_in);
        lines.push_back(buf);
    }

    /* 5th line, RTP echo statistics */
    if (rtp_echo_enabled && media_socket_audio > 0) {
        snprintf(left_buf, 40, "%lu Total echo RTP pckts 1st stream",
                rtp_pckts);

        if (ms_since_last_tick) {
            snprintf(buf, bufsiz, "  %-38s  %lu.%03lu last period RTP rate (kB/s)",
                    left_buf,
                    rtp_bytes / ms_since_last_tick,
                    rtp_bytes % ms_since_last_tick);
            lines.push_back(buf);
        }

        snprintf(left_buf, 40, "%lu Total echo RTP pckts 2nd stream",
                rtp2_pckts);
        if (ms_since_last_tick) {
            snprintf(buf, bufsiz, "  %-38s  %lu.%03lu last period RTP rate (kB/s)",
                    left_buf,
                    rtp2_bytes / ms_since_last_tick,
                    rtp2_bytes % ms_since_last_tick);
            lines.push_back(buf);
        }
        rtp_bytes = 0;
        rtp2_bytes = 0;
    }

    /* Scenario counters */
    lines.push_back("");
    if (!lose_packets) {
        snprintf(buf, bufsiz,
                 "                                 "
                 "Messages  Retrans   Timeout   Unexpected-Msg");
    } else {
        snprintf(buf, bufsiz,
                 "                                 "
                 "Messages  Retrans   Timeout   Unexp.    Lost");
    }
    lines.push_back(buf);

    for (unsigned long index = 0; index < display_scenario->messages.size();
         index++) {
        buf[0] = 0;
        message* curmsg = display_scenario->messages[index];

        if (do_hide && curmsg->hide) {
            continue;
        }
        int buf_len = 0;

        if (SendingMessage* src = curmsg->send_scheme) {
            if (creationMode == MODE_SERVER) {
                if (src->isResponse()) {
                    buf_len += snprintf(buf + buf_len, bufsiz - buf_len,
                                        "  <---------- %-10d ", src->getCode());
                } else {
                    buf_len +=
                        snprintf(buf + buf_len, bufsiz - buf_len,
                                 "  <---------- %-10s ", src->getMethod());
                }
            } else {
                if (src->isResponse()) {
                    buf_len += snprintf(buf + buf_len, bufsiz - buf_len,
                                        "  %10d ----------> ", src->getCode());
                } else {
                    buf_len +=
                        snprintf(buf + buf_len, bufsiz - buf_len,
                                 "  %10s ----------> ", src->getMethod());
                }
            }

            if (curmsg->start_rtd) {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, " B-RTD%d ",
                                    curmsg->start_rtd);
            } else if (curmsg->stop_rtd) {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, " E-RTD%d ",
                                    curmsg->stop_rtd);
            } else {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, "        ");
            }

            if (curmsg->retrans_delay) {
                buf_len += snprintf(
                    buf + buf_len, bufsiz - buf_len, "%-9lu %-9lu %-9lu %-9s %-9s",
                    curmsg->nb_sent, curmsg->nb_sent_retrans,
                    curmsg->nb_timeout, "" /* Unexpected */,
                    (lose_packets && curmsg->nb_lost)
                        ? std::to_string(curmsg->nb_lost).c_str()
                        : "");
            } else {
                buf_len += snprintf(
                    buf + buf_len, bufsiz - buf_len, "%-9lu %-9lu %-9s %-9s %-9s",
                    curmsg->nb_sent, curmsg->nb_sent_retrans, "", /* Timeout. */
                    "" /* Unexpected. */,
                    (lose_packets && curmsg->nb_lost)
                        ? std::to_string(curmsg->nb_lost).c_str()
                        : "");
            }
        } else if (curmsg->recv_response) {
            if (creationMode == MODE_SERVER) {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len,
                                    "  ----------> %-10d ", curmsg->recv_response);
            } else {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len,
                                    "  %10d <---------- ", curmsg->recv_response);
            }

            if (curmsg->start_rtd) {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, " B-RTD%d ",
                                    curmsg->start_rtd);
            } else if (curmsg->stop_rtd) {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, " E-RTD%d ",
                                    curmsg->stop_rtd);
            } else {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, "        ");
            }

            buf_len += snprintf(buf + buf_len, bufsiz - buf_len,
                                "%-9ld %-9ld %-9ld %-9ld %-9s", curmsg->nb_recv,
                                curmsg->nb_recv_retrans, curmsg->nb_timeout,
                                curmsg->nb_unexp,
                                (lose_packets && curmsg->nb_lost)
                                    ? std::to_string(curmsg->nb_lost).c_str()
                                    : "");
        } else if (curmsg->pause_distribution ||
                   (curmsg->pause_variable != -1)) {
            char* desc = curmsg->pause_desc;
            if (!desc) {
                desc = (char*)malloc(24);
                if (curmsg->pause_distribution) {
                    desc[0] = '\0';
                    curmsg->pause_distribution->timeDescr(desc, 23);
                } else {
                    snprintf(desc, 23, "$%s",
                             display_scenario->allocVars->getName(
                                 curmsg->pause_variable));
                }
                desc[23] = '\0';
                curmsg->pause_desc = desc;
            }
            int len = strlen(desc) < 9 ? 9 : strlen(desc);

            if (creationMode == MODE_SERVER) {
                snprintf(left_buf, 40, "  [%9s] Pause%*s", desc,
                        23 - len > 0 ? 23 - len : 0, "");
            } else {
                snprintf(left_buf, 40, "       Pause [%9s]%*s", desc,
                        18 - len > 0 ? 18 - len : 0, "");
            }

            snprintf(buf, bufsiz, "%s%-9d                     %-9lu",
                     left_buf,
                     curmsg->sessions,
                     curmsg->nb_unexp);
        } else if (curmsg->recv_request) {
            if (creationMode == MODE_SERVER) {
                buf_len +=
                    snprintf(buf + buf_len, bufsiz - buf_len,
                             "  ----------> %-10s ", curmsg->recv_request);
            } else {
                buf_len +=
                    snprintf(buf + buf_len, bufsiz - buf_len, "  %10s <---------- ",
                             curmsg->recv_request);
            }

            if (curmsg->start_rtd) {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, " B-RTD%d ",
                                    curmsg->start_rtd);
            } else if (curmsg->stop_rtd) {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, " E-RTD%d ",
                                    curmsg->stop_rtd);
            } else {
                buf_len += snprintf(buf + buf_len, bufsiz - buf_len, "        ");
            }

            buf_len += snprintf(buf + buf_len, bufsiz - buf_len,
                                "%-9ld %-9ld %-9ld %-9ld %-9s", curmsg->nb_recv,
                                curmsg->nb_recv_retrans, curmsg->nb_timeout,
                                curmsg->nb_unexp,
                                (lose_packets && curmsg->nb_lost)
                                    ? std::to_string(curmsg->nb_lost).c_str()
                                    : "");
        } else if (curmsg->M_type == MSG_TYPE_NOP) {
            if (curmsg->display_str) {
                snprintf(buf, bufsiz, " %s", curmsg->display_str);
            } else {
                snprintf(buf, bufsiz, "              [ NOP ]              ");
            }
        } else if (curmsg->M_type == MSG_TYPE_RECVCMD) {
            snprintf(left_buf, 40, "    [ Received Command ]         ");
            snprintf(buf, bufsiz, "%s%-9ld %-9s %-9s %-9s",
                     left_buf,
                     curmsg->M_nbCmdRecv,
                     "",
                     curmsg->retrans_delay ? std::to_string(curmsg->nb_timeout).c_str() : "",
                     "");
        } else if (curmsg->M_type == MSG_TYPE_SENDCMD) {
            snprintf(left_buf, 40, "        [ Sent Command ]         ");
            snprintf(buf, bufsiz, "%s%-9lu %-9s           %-9s",
                     left_buf,
                     curmsg->M_nbCmdSent,
                     "",
                     "");
        } else if (curmsg->M_type == MSG_TYPE_RECV) {
            WARNING("<recv> without request/response?");
            snprintf(buf, bufsiz, "            [ recv? ]              ");
        } else {
            ERROR("Scenario command %d not implemented in display", curmsg->M_type);
        }

        char buf_with_index[121];
        snprintf(buf_with_index, 121, "%-2lu:%s", index, buf);
        lines.push_back(buf_with_index);
        if (curmsg->crlf) {
            lines.push_back("");
        }
    }
}

// Warning! All DISPLAY_ macros must be called where 'bufsiz', 'buf' and 'lines' are defined.
#define DISPLAY_CROSS_LINE() \
    snprintf(buf, bufsiz, "-------------------------+---------------------------+--------------------------"); \
    lines.push_back(buf);

#define DISPLAY_HEADER() \
    snprintf(buf, bufsiz, "  Counter Name           | Periodic value            | Cumulative value"); \
    lines.push_back(buf);
#define DISPLAY_TXT_COL(T1, V1, V2) \
    snprintf(buf, bufsiz, "  %-22.22s | %-25.25s | %-24.24s ", T1, V1, V2); \
    lines.push_back(buf);
#define DISPLAY_VAL_RATEF_COL(T1, V1, V2) \
    snprintf(buf, bufsiz, "  %-22.22s | %8.3f cps              | %8.3f cps             ", T1, V1, V2); \
    lines.push_back(buf);
#define DISPLAY_2VAL(T1, V1, V2) \
    snprintf(buf, bufsiz, "  %-22.22s | %8llu                  | %8llu                 ", T1, V1, V2); \
    lines.push_back(buf);
#define DISPLAY_CUMUL(T1, V1) \
    snprintf(buf, bufsiz, "  %-22.22s |                           | %8llu                 ", T1, V1); \
    lines.push_back(buf);
#define DISPLAY_PERIO(T1, V1) \
    snprintf(buf, bufsiz, "  %-22.22s | %8llu                  |                          ", T1, V1); \
    lines.push_back(buf);
#define DISPLAY_TXT(T1, V1) \
    snprintf(buf, bufsiz, "  %-22.22s | %-52.52s ", T1, V1); \
    lines.push_back(buf);
#define DISPLAY_INFO(T1) \
    snprintf(buf, bufsiz, "  %-77.77s", T1); \
    lines.push_back(buf);
#define DISPLAY_REPART(T1, T2, V1) \
    snprintf(buf, bufsiz, "    %10d ms <= n < %10d ms : %10lu", T1, T2, V1); \
    lines.push_back(buf);
#define DISPLAY_LAST_REPART(T1, V1) \
    snprintf(buf, bufsiz, "    %14.14s n >= %10d ms : %10lu", "", T1, V1); \
    lines.push_back(buf);

void ScreenPrinter::draw_stats_screen()
{
    long   localElapsedTime, globalElapsedTime ;
    struct timeval currentTime;
    float  averageCallRate;
    float  realInstantCallRate;
    unsigned long numberOfCall;
    CStat* s = display_scenario->stats;
    unsigned const bufsiz = 256;
    char buf[bufsiz];

    GET_TIME (&currentTime);
    // computing the real call rate
    globalElapsedTime   = s->computeDiffTimeInMs (&currentTime, &s->M_startTime);
    localElapsedTime    = s->computeDiffTimeInMs (&currentTime, &s->M_pdStartTime);
    // the call rate is for all the call : incoming and outgoing
    numberOfCall        = (s->M_counters[s->CPT_C_IncomingCallCreated] +
                           s->M_counters[s->CPT_C_OutgoingCallCreated]);
    averageCallRate     = (globalElapsedTime > 0 ?
                           1000*(float)numberOfCall/(float)globalElapsedTime :
                           0.0);
    numberOfCall        = (s->M_counters[s->CPT_PD_IncomingCallCreated] +
                           s->M_counters[s->CPT_PD_OutgoingCallCreated]);
    realInstantCallRate = (localElapsedTime  > 0 ?
                           1000*(float)numberOfCall / (float)localElapsedTime :
                           0.0);

    // build and display header info
    DISPLAY_TXT ("Start Time  ", s->formatTime(&s->M_startTime));
    DISPLAY_TXT ("Last Reset Time", s->formatTime(&s->M_pdStartTime));
    DISPLAY_TXT ("Current Time", s->formatTime(&currentTime));

    // printing the header in the middle
    DISPLAY_CROSS_LINE();
    DISPLAY_HEADER();
    DISPLAY_CROSS_LINE();

    DISPLAY_TXT_COL ("Elapsed Time",
                     s->msToHHMMSSus(localElapsedTime),
                     s->msToHHMMSSus(globalElapsedTime));

    DISPLAY_VAL_RATEF_COL ("Call Rate",  realInstantCallRate, averageCallRate);
    DISPLAY_CROSS_LINE ();

    DISPLAY_2VAL  ("Incoming calls created",
                   s->M_counters[s->CPT_PD_IncomingCallCreated],
                   s->M_counters[s->CPT_C_IncomingCallCreated]);
    DISPLAY_2VAL  ("Outgoing calls created",
                   s->M_counters[s->CPT_PD_OutgoingCallCreated],
                   s->M_counters[s->CPT_C_OutgoingCallCreated]);
    DISPLAY_CUMUL ("Total Calls created", s->M_counters[s->CPT_C_IncomingCallCreated] +
                   s->M_counters[s->CPT_C_OutgoingCallCreated]);
    DISPLAY_PERIO ("Current Calls",
                   s->M_counters[s->CPT_C_CurrentCall]);

    if (s->M_genericMap.size()) {
        DISPLAY_CROSS_LINE ();
    }
    for (unsigned int i = 1; i < s->M_genericMap.size() + 1; i++) {
        char *disp = (char *)malloc(20 + strlen(s->M_genericDisplay[i]));
        sprintf(disp, "Counter %s", s->M_genericDisplay[i]);

        DISPLAY_2VAL(disp, s->M_genericCounters[(i - 1)* GENERIC_TYPES + GENERIC_PD], s->M_genericCounters[(i - 1) * GENERIC_TYPES + GENERIC_C]);
        free(disp);
    }

    DISPLAY_CROSS_LINE ();
    DISPLAY_2VAL  ("Successful call",
                   s->M_counters[s->CPT_PD_SuccessfulCall],
                   s->M_counters[s->CPT_C_SuccessfulCall]);
    DISPLAY_2VAL  ("Failed call",
                   s->M_counters[s->CPT_PD_FailedCall],
                   s->M_counters[s->CPT_C_FailedCall]);

    DISPLAY_CROSS_LINE ();
    for (int i = 1; i <= s->nRtds(); i++) {
        char buf2[80];

        snprintf(buf2, 80, "Response Time %s", s->M_revRtdMap[i]);
        DISPLAY_TXT_COL (buf2,
                         s->msToHHMMSSus( (unsigned long)s->computeRtdMean(i, GENERIC_PD)),
                         s->msToHHMMSSus( (unsigned long)s->computeRtdMean(i, GENERIC_C)));
    }
    DISPLAY_TXT_COL ("Call Length",
                     s->msToHHMMSSus( (unsigned long)s->computeMean(s->CPT_PD_AverageCallLength_Sum, s->CPT_PD_NbOfCallUsedForAverageCallLength ) ),
                     s->msToHHMMSSus( (unsigned long)s->computeMean(s->CPT_C_AverageCallLength_Sum, s->CPT_C_NbOfCallUsedForAverageCallLength) ));
}

void ScreenPrinter::draw_repartition_screen(int which)
{
    unsigned const bufsiz = 80;
    char buf[bufsiz];
    char buf2[bufsiz];
    CStat* s = display_scenario->stats;
    if (which > s->nRtds()) {
        DISPLAY_INFO ("  <No repartion defined>");
        return;
    }

    snprintf(buf2, bufsiz, "Average Response Time Repartition %s", s->M_revRtdMap[which]);
    DISPLAY_INFO(buf2);
    draw_repartition_detailed(s->M_ResponseTimeRepartition[which - 1],
                              s->M_SizeOfResponseTimeRepartition);

    if (which == 1)
    {
        // Primary repartition screen
        DISPLAY_INFO("Average Call Length Repartition");
        draw_repartition_detailed(s->M_CallLengthRepartition,
                                  s->M_SizeOfCallLengthRepartition);
    }
}

void ScreenPrinter::draw_repartition_detailed(CStat::T_dynamicalRepartition * tabRepartition,
                                            int sizeOfTab)
{
    unsigned const bufsiz = 80;
    char buf[bufsiz];
    if(tabRepartition != NULL) {
        for(int i=0; i<(sizeOfTab-1); i++) {
            if(i==0) {
                DISPLAY_REPART(0, tabRepartition[i].borderMax,
                               tabRepartition[i].nbInThisBorder);
            } else {
                DISPLAY_REPART(tabRepartition[i-1].borderMax,
                               tabRepartition[i].borderMax,
                               tabRepartition[i].nbInThisBorder);
            }
        }
        DISPLAY_LAST_REPART (tabRepartition[sizeOfTab-1].borderMax,
                             tabRepartition[sizeOfTab-1].nbInThisBorder);
    } else {
        DISPLAY_INFO ("  <No repartion defined>");
    }
}

void ScreenPrinter::draw_vars_screen()
{
    CActions* actions;
    CAction* action;
    bool found;
    unsigned const bufsiz = 80;
    char buf[bufsiz];

    lines.push_back("Action defined Per Message :");
    found = false;
    for (unsigned int i = 0; i < display_scenario->messages.size(); i++) {
        message* curmsg = display_scenario->messages[i];
        actions = curmsg->M_actions;
        if (actions != NULL) {
            switch (curmsg->M_type) {
            case MSG_TYPE_RECV:
                snprintf(buf, bufsiz, "=> Message[%u] (Receive Message) - "
                         "[%d] action(s) defined :",
                         i, actions->getActionSize());
                break;
            case MSG_TYPE_RECVCMD:
                snprintf(buf, bufsiz, "=> Message[%u] (Receive Command Message) - "
                         "[%d] action(s) defined :",
                         i, actions->getActionSize());
                break;
            default:
                snprintf(buf, bufsiz, "=> Message[%u] - [%d] action(s) defined :", i,
                       actions->getActionSize());
                break;
            }
            lines.push_back(buf);

            for (int j = 0; j < actions->getActionSize(); j++) {
                action = actions->getAction(j);
                if (action != NULL) {
                    int printed = snprintf(buf, bufsiz, "   --> action[%d] = ", j);
                    action->printInfo(buf + printed, bufsiz - printed);
                    lines.push_back(buf);
                    found = true;
                }
            }
        }
    }
    if (!found) {
        lines.push_back("=> No action found on any messages");
    }

    lines.push_back("");
    for (unsigned int i = 0;
         i < (display_scenario->messages.size() + 6 - lines.size()); i++) {
      lines.push_back("");
    }
}

void ScreenPrinter::draw_tdm_screen()
{
    int i = 0;
    int in_use = 0;
    int height = (tdm_map_a + 1) * (tdm_map_b + 1);
    int width = (tdm_map_c + 1);
    int total_circuits = height * width;
    unsigned const bufsiz = 80;
    char buf[bufsiz] = {0};

    lines.push_back("TDM Circuits in use:");
    while (i < total_circuits) {
        int buf_position = std::min(79, i % width);
        if (tdm_map[i]) {
            buf[buf_position] = '*';
            in_use++;
        } else {
            buf[buf_position] = '.';
        }
        i++;
        if (buf_position == (width - 1)) {
            lines.push_back(buf);
            memset(buf, 0, bufsiz);
        }
    }
    lines.push_back("");
    snprintf(buf, bufsiz, "%d/%d circuits (%d%%) in use", in_use, total_circuits,
           int(100 * in_use / total_circuits));
    lines.push_back(buf);
    for (unsigned int i = 0;
         i < (display_scenario->messages.size() + 8 - height);
         i++) {
        lines.push_back("");
    }
}
