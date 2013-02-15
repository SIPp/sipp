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
 *           Marc LAMBERTON
 *           Olivier JACQUES
 *           Herve PELLAN
 *           David MANSUTTI
 *           Francois-Xavier Kowalski
 *           Gerard Lyonnaz
 *           From Hewlett Packard Company.
 *           F. Tarek Rogers
 *           Peter Higginson
 *           Vincent Luba
 *           Shriram Natarajan
 *           Guillaume Teissier from FTR&D
 *           Clement Chen
 *           Wolfgang Beck
 *           Charles P Wright from IBM Research
 */
#include "sipp.hpp"

class opentask *opentask::instance = NULL;
unsigned long opentask::calls_since_last_rate_change = 0;
unsigned long opentask::last_rate_change_time = 0;

void opentask::initialize()
{
    assert(instance == NULL);
    instance = new opentask();
}

opentask::opentask()
{
    setRunning();
}

opentask::~opentask()
{
    instance = NULL;
}

void opentask::dump()
{
    WARNING("Uniform rate call generation task: %d", rate);
}

unsigned int opentask::wake()
{
    float ms_per_call;
    if (paused) {
        return 0;
    } else if (users >= 0) {
        /* We need to wait until another call is terminated. */
        return 0;
    } else {
        ms_per_call = rate_period_ms/MAX(rate, 1);
        /* We need to compute when the next call is going to be opened.
         * The current time is the time when the rate last changed, plus
         * the number of calls since then multiplied by the number of milliseconds
         * between each call.
         *
         * We then add the number of milliseconds between each call to that
         * figure.*/

        return (unsigned long) last_rate_change_time +
               (calls_since_last_rate_change * ms_per_call) + ms_per_call;
    }
}

bool opentask::run()
{
    int calls_to_open = 0;

    if (quitting) {
        delete this;
        return false;
    }

    if (paused) {
        setPaused();
        return true;
    }

    long l=0;
    unsigned long long current_calls = main_scenario->stats->GetStat(CStat::CPT_C_CurrentCall);
    unsigned long long total_calls = main_scenario->stats->GetStat(CStat::CPT_C_IncomingCallCreated) + main_scenario->stats->GetStat(CStat::CPT_C_OutgoingCallCreated);

    if (users >= 0) {
        calls_to_open = ((l = (users - current_calls)) > 0) ? l : 0;
    } else {
        calls_to_open = (unsigned int)
                        ((l=(long)floor(((clock_tick - last_rate_change_time) * rate/rate_period_ms)
                                        - calls_since_last_rate_change))>0?l:0);
    }

    if (total_calls + calls_to_open > stop_after) {
        calls_to_open = stop_after - total_calls;
    }

    /* We base our scheduling on the number of calls made since the last rate
     * change, but if we reduce the number of calls we open in order to keep
     * within the limit, that throws this calculation off and brings CPU% up to
     * 100%. To avoid this, we increment calls_since_last_rate_change here. */

    calls_since_last_rate_change += calls_to_open;

    if (open_calls_allowed && (current_calls + calls_to_open > open_calls_allowed)) {

        calls_to_open = open_calls_allowed - current_calls;

    }

    if (calls_to_open <= 0) {
        calls_to_open = 0;
    }

    unsigned int start_clock = getmilliseconds();


    while(calls_to_open--) {
        /* Associate a user with this call, if we are in users mode. */
        int userid = 0;
        if (users >= 0) {
            userid = freeUsers.back();
            freeUsers.pop_back();
        }

        // adding a new OUTGOING CALL
        main_scenario->stats->computeStat(CStat::E_CREATE_OUTGOING_CALL);
        call * call_ptr = call::add_call(userid, local_ip_is_ipv6, use_remote_sending_addr ? &remote_sending_sockaddr : &remote_sockaddr);
        if(!call_ptr) {
            ERROR("Out of memory allocating call!");
        }

        outbound_congestion = false;

        if (!multisocket) {
            switch(transport) {
            case T_UDP:
                call_ptr->associate_socket(main_socket);
                main_socket->ss_count++;
                break;
            case T_TCP:
            case T_SCTP:
            case T_TLS:
                call_ptr->associate_socket(tcp_multiplex);
                tcp_multiplex->ss_count++;
                break;
            }
        }
        if (getmilliseconds() > start_clock) {
            break;
        }
    }

    /* We can pause. */
    if (calls_to_open <= 0) {
        setPaused();
    } else {
        /* Stay running. */
    }

    // Quit after asked number of calls is reached
    if(total_calls >= stop_after) {
        quitting = 1;
        return false;
    }

    return true;
}

void opentask::set_paused(bool new_paused)
{
    if (!instance) {
        /* Doesn't do anything, we must be in server mode. */
        return;
    }
    if (new_paused) {
        instance->setPaused();
    } else {
        instance->setRunning();
        if (users >= 0) {
            set_users(users);
        } else {
            set_rate(rate);
        }
    }
    paused = new_paused;
}

void opentask::set_rate(double new_rate)
{
    if (!instance) {
        /* Doesn't do anything, we must be in server mode. */
    }

    rate = new_rate;
    if(rate < 0) {
        rate = 0;
    }

    last_rate_change_time = getmilliseconds();
    calls_since_last_rate_change = 0;

    if(!open_calls_user_setting) {

        int call_duration_min =  main_scenario->duration;

        if(duration > call_duration_min) call_duration_min = duration;

        if(call_duration_min < 1000) call_duration_min = 1000;

        open_calls_allowed = (int)((3.0 * rate * call_duration_min) / (double)rate_period_ms);
        if(!open_calls_allowed) {
            open_calls_allowed = 1;
        }
    }
}

void opentask::set_users(int new_users)
{
    if (!instance) {
        /* Doesn't do anything, we must be in server mode. */
        return;
    }

    if (new_users < 0) {
        new_users = 0;
    }
    assert(users >= 0);

    if (users < new_users ) {
        while (users < new_users) {
            int userid;
            if (!retiredUsers.empty()) {
                userid = retiredUsers.back();
                retiredUsers.pop_back();
            } else {
                userid = users + 1;
                userVarMap[userid] = new VariableTable(userVariables);
            }
            freeUsers.push_front(userid);
            users++;
        }
    }

    users = open_calls_allowed = new_users;

    last_rate_change_time = clock_tick;
    calls_since_last_rate_change = 0;

    assert(open_calls_user_setting);

    instance->setRunning();
}

void opentask::freeUser(int userId)
{
    if (main_scenario->stats->GetStat(CStat::CPT_C_CurrentCall) > open_calls_allowed) {
        retiredUsers.push_front(userId);
    } else {
        freeUsers.push_front(userId);
        /* Wake up the call creation thread. */
        if (instance) {
            instance->setRunning();
        }
    }
}
