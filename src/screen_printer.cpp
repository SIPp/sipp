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
 */

#include <curses.h>
#include "screen_printer.hpp"
#include "sipp.hpp"

ScreenPrinter* sp;

#ifdef RTP_STREAM
double last_rtpstream_rate_out = 0;
double last_rtpstream_rate_in = 0;
#endif

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
        clear();
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
        display_scenario->stats->displayStat(lines);
        break;
    case DISPLAY_REPARTITION_SCREEN:
        lines.push_back("---------------------------- Repartition Screen "
                        "------- [1-9]: Change Screen --");
        display_scenario->stats->displayRepartition(lines);
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
        display_scenario->stats->displayRtdRepartition(lines,
                                                        currentRepartitionToDisplay);
        break;
    case DISPLAY_SCENARIO_SCREEN:
    default:
        lines.push_back("------------------------------ Scenario Screen "
                        "-------- [1-9]: Change Screen --");
        draw_scenario_screen();
        break;
    }

    char buf[80];
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
      if (strlen(errstart) > 60) {
        snprintf(buf, 80, "Last Error: %.60s...", errstart);
      } else {
        snprintf(buf, 80, "Last Error: %s", errstart);
      }
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
bool show_index = false;

void ScreenPrinter::draw_scenario_screen()
{
    char buf[80];
    char left_buf[40];
    char right_buf[80];
    int divisor;
    extern int pollnfds;

    unsigned long long total_calls =
        display_scenario->stats->GetStat(CStat::CPT_C_IncomingCallCreated) +
        display_scenario->stats->GetStat(CStat::CPT_C_OutgoingCallCreated);
    if (creationMode == MODE_SERVER) {
        lines.push_back("  Port   Total-time  Total-calls  Transport");
        snprintf(buf, 256, "  %-5d %6lu.%02lu s     %8llu  %s", local_port,
                 clock_tick / 1000, (clock_tick % 1000) / 10, total_calls,
                 TRANSPORT_TO_STRING(transport));
        lines.push_back(buf);
    } else {
        assert(creationMode == MODE_CLIENT);
        if (users >= 0) {
            lines.push_back("     Users (length)   Port   Total-time  "
                            "Total-calls  Remote-host");
            snprintf(buf, 256,
                     "%d (%d ms)   %-5d %6lu.%02lu s     %8llu  %s:%d(%s)",
                     users, duration, local_port, clock_tick / 1000,
                     (clock_tick % 1000) / 10, total_calls, remote_ip,
                     remote_port, TRANSPORT_TO_STRING(transport));
            lines.push_back(buf);
        } else {
            lines.push_back("     Call rate (length)   Port   Total-time  "
                            "Total-calls  Remote-host");
            snprintf(
                buf, 256,
                "%3.1f(%d ms)/%5.3fs   %-5d %6lu.%02lu s     %8llu  %s:%d(%s)",
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
        snprintf(left_buf, 40, "%llu new calls during %lu.%03lu s period",
                 display_scenario->stats->GetStat(
                     CStat::CPT_PD_IncomingCallCreated) +
                     display_scenario->stats->GetStat(
                         CStat::CPT_PD_OutgoingCallCreated),
                 ms_since_last_tick / 1000, ms_since_last_tick % 1000);
    } else {
        snprintf(left_buf, 40,
                 "Call limit reached (-m %lu), %lu.%03lu s period ", stop_after,
                 ms_since_last_tick / 1000, ms_since_last_tick % 1000);
    }
    snprintf(right_buf, 40, "%lu ms scheduler resolution",
             ms_since_last_tick / std::max(scheduling_loops, 1ul));
    snprintf(buf, 80, "  %-38s  %-40s", left_buf, right_buf);
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
        buf, 80, "  %-38s  Peak was %llu calls, after %llu s", left_buf,
        display_scenario->stats->GetStat(CStat::CPT_C_CurrentCallPeak),
        display_scenario->stats->GetStat(CStat::CPT_C_CurrentCallPeakTime));
    lines.push_back(buf);

    snprintf(buf, 80, "  %d Running, %d Paused, %d Woken up",
             last_running_calls, last_paused_calls, last_woken_calls);
    last_woken_calls = 0;
    lines.push_back(buf);

    /* 3rd line dead call msgs, and optional out-of-call msg */
    snprintf(left_buf, 40, "%llu dead call msg (discarded)",
             display_scenario->stats->GetStat(CStat::CPT_G_C_DeadCallMsgs));
    if (creationMode == MODE_CLIENT) {
        snprintf(
            buf, 80, "  %-38s  %llu out-of-call msg (discarded)", left_buf,
            display_scenario->stats->GetStat(CStat::CPT_G_C_OutOfCallMsgs));
    } else {
        snprintf(buf, 80, "  %-38s", left_buf);
    }
    lines.push_back(buf);

    if (compression) {
        snprintf(buf, 80, "  Comp resync: %d sent, %d recv", resynch_send,
                 resynch_recv);
        lines.push_back(buf);
    }

    /* 4th line , sockets and optional errors */
    snprintf(left_buf, 40, "%d open sockets", pollnfds);
    snprintf(buf, 80, "  %-38s  %lu/%lu/%lu %s errors (send/recv/cong)",
             left_buf, nb_net_send_errors, nb_net_recv_errors, nb_net_cong,
             TRANSPORT_TO_STRING(transport));
    lines.push_back(buf);

#ifdef PCAPPLAY
    /* if has media abilities */
    if (hasMedia != 5) {
        snprintf(left_buf, 40, "%lu Total RTP pckts sent ",
                rtp_pckts_pcap);
        if (ms_since_last_tick) {
            snprintf(buf, 80, "  %-38s  %lu.%03lu last period RTP rate (kB/s)",
                    left_buf,
                    rtp_bytes_pcap / ms_since_last_tick,
                    rtp_bytes_pcap % ms_since_last_tick);
        }
        rtp_bytes_pcap = 0;
        rtp2_bytes_pcap = 0;
        lines.push_back(buf);
    }
#endif
#ifdef RTP_STREAM
    /* if we have rtp stream thread running */
    if (rtpstream_numthreads) {
        unsigned long tempbytes;
        unsigned long last_tick = clock_tick;
        /* Saved clock_tick to last_tick and use that in calcs since clock tick */
        /* can change during calculations.                                      */
        if (ms_since_last_tick) {
            tempbytes = rtpstream_bytes_out;
            /* Calculate integer and fraction parts of rtp bandwidth; this value
             * will be saved and reused in the case where last_tick==last_report_time
             */
            last_rtpstream_rate_out = ((double)tempbytes) / ms_since_last_tick;
            /* Potential race condition betwen multiple threads updating the
             * rtpstream_bytes value. We subtract the saved tempbytes value
             * rather than setting it to zero to minimise the chances of missing
             * an update to rtpstream_bytes [update between printing stats and
             * zeroing the counter]. Ideally we would atomically subtract
             * tempbytes from rtpstream_bytes.
             */
            rtpstream_bytes_out -= tempbytes;
            tempbytes = rtpstream_bytes_in;
            last_rtpstream_rate_in = ((double)tempbytes) / ms_since_last_tick;
            rtpstream_bytes_in -= tempbytes;
        }
        snprintf(left_buf, 40, "%lu Total RTP pckts sent", rtpstream_pckts);
        snprintf(buf, 80,"  %-38s  %.3f kB/s RTP OUT",
                left_buf, last_rtpstream_rate_out);
        lines.push_back(buf);

        snprintf(left_buf, 40, "%lu RTP sending threads active", rtpstream_numthreads);
        snprintf(buf, 80, "  %-38s  %.3f kB/s RTP IN",
                 left_buf, last_rtpstream_rate_in);
        lines.push_back(buf);
    }
#endif

    /* 5th line, RTP echo statistics */
    if (rtp_echo_enabled && media_socket_audio > 0) {
        snprintf(left_buf, 40, "%lu Total echo RTP pckts 1st stream",
                rtp_pckts);

        if (ms_since_last_tick) {
            snprintf(buf, 80, "  %-38s  %lu.%03lu last period RTP rate (kB/s)",
                    left_buf,
                    rtp_bytes / ms_since_last_tick,
                    rtp_bytes % ms_since_last_tick);
            lines.push_back(buf);
        }

        snprintf(left_buf, 40, "%lu Total echo RTP pckts 2nd stream",
                rtp2_pckts);
        if (ms_since_last_tick) {
            snprintf(buf, 80, "  %-38s  %lu.%03lu last period RTP rate (kB/s)",
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
        snprintf(buf, 80,
                 "                                 "
                 "Messages  Retrans   Timeout   Unexpected-Msg");
    } else {
        snprintf(buf, 80,
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
        if (show_index) {
            buf_len += snprintf(buf + buf_len, 80 - buf_len, "%-2lu:", index);
        }

        if (SendingMessage* src = curmsg->send_scheme) {
            if (creationMode == MODE_SERVER) {
                if (src->isResponse()) {
                    buf_len += snprintf(buf + buf_len, 80 - buf_len,
                                        "  <---------- %-10d ", src->getCode());
                } else {
                    buf_len +=
                        snprintf(buf + buf_len, 80 - buf_len,
                                 "  <---------- %-10s ", src->getMethod());
                }
            } else {
                if (src->isResponse()) {
                    buf_len += snprintf(buf + buf_len, 80 - buf_len,
                                        "  %10d ----------> ", src->getCode());
                } else {
                    buf_len +=
                        snprintf(buf + buf_len, 80 - buf_len,
                                 "  %10s ----------> ", src->getMethod());
                }
            }

            if (curmsg->start_rtd) {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, " B-RTD%d ",
                                    curmsg->start_rtd);
            } else if (curmsg->stop_rtd) {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, " E-RTD%d ",
                                    curmsg->stop_rtd);
            } else {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, "        ");
            }

            if (curmsg->retrans_delay) {
                buf_len += snprintf(
                    buf + buf_len, 80 - buf_len, "%-9lu %-9lu %-9lu %-9s %-9s",
                    curmsg->nb_sent, curmsg->nb_sent_retrans,
                    curmsg->nb_timeout, "" /* Unexpected */,
                    (lose_packets && curmsg->nb_lost)
                        ? std::to_string(curmsg->nb_lost).c_str()
                        : "");
            } else {
                buf_len += snprintf(
                    buf + buf_len, 80 - buf_len, "%-9lu %-9lu %-9s %-9s %-9s",
                    curmsg->nb_sent, curmsg->nb_sent_retrans, "", /* Timeout. */
                    "" /* Unexpected. */,
                    (lose_packets && curmsg->nb_lost)
                        ? std::to_string(curmsg->nb_lost).c_str()
                        : "");
            }
        } else if (curmsg->recv_response) {
            if (creationMode == MODE_SERVER) {
                buf_len += snprintf(buf + buf_len, 80 - buf_len,
                                    "  ----------> %-10d ", curmsg->recv_response);
            } else {
                buf_len += snprintf(buf + buf_len, 80 - buf_len,
                                    "  %10d <---------- ", curmsg->recv_response);
            }

            if (curmsg->start_rtd) {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, " B-RTD%d ",
                                    curmsg->start_rtd);
            } else if (curmsg->stop_rtd) {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, " E-RTD%d ",
                                    curmsg->stop_rtd);
            } else {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, "        ");
            }

            buf_len += snprintf(buf + buf_len, 80 - buf_len,
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

            snprintf(buf, 80, "%s%-9d                     %-9lu",
                     left_buf,
                     curmsg->sessions,
                     curmsg->nb_unexp);
        } else if (curmsg->recv_request) {
            if (creationMode == MODE_SERVER) {
                buf_len +=
                    snprintf(buf + buf_len, 80 - buf_len,
                             "  ----------> %-10s ", curmsg->recv_request);
            } else {
                buf_len +=
                    snprintf(buf + buf_len, 80 - buf_len, "  %10s <---------- ",
                             curmsg->recv_request);
            }

            if (curmsg->start_rtd) {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, " B-RTD%d ",
                                    curmsg->start_rtd);
            } else if (curmsg->stop_rtd) {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, " E-RTD%d ",
                                    curmsg->stop_rtd);
            } else {
                buf_len += snprintf(buf + buf_len, 80 - buf_len, "        ");
            }

            buf_len += snprintf(buf + buf_len, 80 - buf_len,
                                "%-9ld %-9ld %-9ld %-9ld %-9s", curmsg->nb_recv,
                                curmsg->nb_recv_retrans, curmsg->nb_timeout,
                                curmsg->nb_unexp,
                                (lose_packets && curmsg->nb_lost)
                                    ? std::to_string(curmsg->nb_lost).c_str()
                                    : "");
        } else if (curmsg->M_type == MSG_TYPE_NOP) {
            if (curmsg->display_str) {
                snprintf(buf, 80, " %s", curmsg->display_str);
            } else {
                snprintf(buf, 80, "              [ NOP ]              ");
            }
        } else if (curmsg->M_type == MSG_TYPE_RECVCMD) {
            snprintf(left_buf, 40, "    [ Received Command ]         ");
            snprintf(buf, 80, "%s%-9ld %-9s %-9s %-9s",
                     left_buf,
                     curmsg->M_nbCmdRecv,
                     "",
                     curmsg->retrans_delay ? std::to_string(curmsg->nb_timeout).c_str() : "",
                     "");
        } else if (curmsg->M_type == MSG_TYPE_SENDCMD) {
            snprintf(left_buf, 40, "        [ Sent Command ]         ");
            snprintf(buf, 80, "%s%-9lu %-9s           %-9s",
                     left_buf,
                     curmsg->M_nbCmdSent,
                     "",
                     "");
        } else {
            ERROR("Scenario command not implemented in display");
        }

        lines.push_back(buf);
        if (curmsg->crlf) {
            lines.push_back("");
        }
    }
}

void ScreenPrinter::draw_vars_screen()
{
    CActions* actions;
    CAction* action;
    bool found;
    char buf[80];

    lines.push_back("Action defined Per Message :");
    found = false;
    for (unsigned int i = 0; i < display_scenario->messages.size(); i++) {
        message* curmsg = display_scenario->messages[i];
        actions = curmsg->M_actions;
        if (actions != NULL) {
            switch (curmsg->M_type) {
            case MSG_TYPE_RECV:
                snprintf(buf, 80, "=> Message[%u] (Receive Message) - "
                         "[%d] action(s) defined :",
                         i, actions->getActionSize());
                break;
            case MSG_TYPE_RECVCMD:
                snprintf(buf, 80, "=> Message[%u] (Receive Command Message) - "
                         "[%d] action(s) defined :",
                         i, actions->getActionSize());
                break;
            default:
                snprintf(buf, 80, "=> Message[%u] - [%d] action(s) defined :", i,
                       actions->getActionSize());
                break;
            }
            lines.push_back(buf);

            for (int j = 0; j < actions->getActionSize(); j++) {
                action = actions->getAction(j);
                if (action != NULL) {
                    int printed = snprintf(buf, 80, "   --> action[%d] = ", j);
                    action->printInfo(buf + printed, 80 - printed);
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
    char buf[80] = {0};

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
            memset(buf, 0, 80);
        }
    }
    lines.push_back("");
    snprintf(buf, 80, "%d/%d circuits (%d%%) in use", in_use, total_circuits,
           int(100 * in_use / total_circuits));
    lines.push_back(buf);
    for (unsigned int i = 0;
         i < (display_scenario->messages.size() + 8 - height);
         i++) {
        lines.push_back("");
    }
}


