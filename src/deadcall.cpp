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
 *           Olivier Jacques
 *           From Hewlett Packard Company.
 *           Shriram Natarajan
 *           Peter Higginson
 *           Eric Miller
 *           Venkatesh
 *           Enrico Hartung
 *           Nasir Khan
 *           Lee Ballard
 *           Guillaume Teissier from FTR&D
 *           Wolfgang Beck
 *           Venkatesh
 *           Vlad Troyanker
 *           Charles P Wright from IBM Research
 *           Amit On from Followap
 *           Jan Andres from Freenet
 *           Ben Evans from Open Cloud
 *           Marc Van Diest from Belgacom
 *           Michael Dwyer from Cibation
 */

#include <iterator>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>

#include "sipp.hpp"
#include "deadcall.hpp"
#include "assert.h"

/* Defined in call.cpp. */
extern timewheel paused_calls;

deadcall::deadcall(const char *id, const char *reason, bool sent_bye, bool sent_cancel) : listener(id, false)
{
    /* Listen once we are a deadcall, which startListening() checks. */
    startListening();
    this->expiration = clock_tick + deadcall_wait;
    this->reason = strdup(reason);
    this->sent_bye = sent_bye;
    this->sent_cancel = sent_cancel;
    setPaused();
}

deadcall::~deadcall()
{
    free(reason);
}

bool deadcall::process_incoming(const char* msg, const struct sockaddr_storage* /*src*/)
{
    char buffer[MAX_HEADER_LEN];

    setRunning();

    /* The 200 to our BYE or CANCEL, and the 487 to the INVITE we
     * cancelled, only trail the call. */
    unsigned long code = get_reply_code(msg);
    if ((sent_bye || sent_cancel) && (code == 200 || code == 487)) {
        char method[16];
        call::extract_cseq_method(method, sizeof(method), msg);
        if ((sent_bye && code == 200 && !strcmp(method, "BYE")) ||
            (sent_cancel && code == 200 && !strcmp(method, "CANCEL")) ||
            (sent_cancel && code == 487 && !strcmp(method, "INVITE"))) {
            TRACE_MSG("-----------------------------------------------\n"
                      "Dead call %s received a %s message:\n\n%s\n",
                      id, TRANSPORT_TO_STRING(transport), msg);
            return run();
        }
    }

    CStat::globalStat(CStat::E_DEAD_CALL_MSGS);

    snprintf(buffer, MAX_HEADER_LEN, "Dead call %s (%s)", id, reason);

    WARNING("%s, received '%s'", buffer, msg);

    TRACE_MSG("-----------------------------------------------\n"
              "Dead call %s received a %s message:\n\n%s\n",
              id, TRANSPORT_TO_STRING(transport), msg);

    expiration = clock_tick + deadcall_wait;
    return run();
}

bool deadcall::process_twinSippCom(char * msg)
{
    CStat::globalStat(CStat::E_DEAD_CALL_MSGS);
    TRACE_MSG("Received twin message for dead (%s) call %s:%s\n", reason, id, msg);
    return true;
}

bool deadcall::run()
{
    if (clock_tick > expiration) {
        delete this;
        return false;
    } else {
        setPaused();
        return true;
    }
}

unsigned int deadcall::wake()
{
    return expiration;
}

/* Dump call info to error log. */
void deadcall::dump()
{
    WARNING("%s: Dead Call (%s) expiring at %lu", id, reason, expiration);
}
