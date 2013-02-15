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

void watchdog::dump()
{
    WARNING("Watchdog Task: interval = %d, major_threshold = %d (%d triggers left), minor_threshold = %d (%d triggers left)", interval, major_threshold, major_maxtriggers, minor_threshold, minor_maxtriggers);
}

watchdog::watchdog(int interval, int reset_interval, int major_threshold, int major_maxtriggers, int minor_threshold, int minor_maxtriggers)
{
    this->interval = interval;
    this->reset_interval = reset_interval;
    this->major_threshold = major_threshold;
    this->major_maxtriggers = major_maxtriggers;
    this->minor_threshold = minor_threshold;
    this->minor_maxtriggers = minor_maxtriggers;
    major_triggers = 0;
    minor_triggers = 0;
    last_trigger = last_fire = getmilliseconds();
}

bool watchdog::run()
{
    getmilliseconds();
    if (last_fire + this->major_threshold < clock_tick) {
        CStat::globalStat(CStat::E_WATCHDOG_MAJOR);
        last_trigger = clock_tick;
        WARNING("The major watchdog timer %dms has been tripped (%d), %d trips remaining.", major_threshold, clock_tick - last_fire, major_maxtriggers - major_triggers);
        if ((this->major_maxtriggers != -1) && (++major_triggers > this->major_maxtriggers)) {
            ERROR("The watchdog timer has tripped the major threshold of %dms too many times (%d out of %d allowed) (%d out of %d minor %dms timeouts tripped)\n", major_threshold, major_triggers, major_maxtriggers, minor_threshold, minor_triggers, minor_maxtriggers);
        }
    } else if (last_fire + this->minor_threshold < clock_tick) {
        last_trigger = clock_tick;
        CStat::globalStat(CStat::E_WATCHDOG_MINOR);
        WARNING("The minor watchdog timer %dms has been tripped (%d), %d trips remaining.", minor_threshold, clock_tick - last_fire, minor_maxtriggers - minor_triggers);
        if ((this->minor_maxtriggers != -1) && (++minor_triggers > this->minor_maxtriggers)) {
            ERROR("The watchdog timer has tripped the minor threshold of %dms too many times (%d out of %d allowed) (%d out of %d major %dms timeouts tripped)\n", minor_threshold, minor_triggers, minor_maxtriggers, major_threshold, major_triggers, major_maxtriggers);
        }
    }

    if (reset_interval && (major_triggers || minor_triggers) && (last_trigger + reset_interval < clock_tick)) {
        WARNING("Resetting watchdog timer trigger counts, as it has not been triggered in over %dms.", clock_tick - last_trigger);
        major_triggers = minor_triggers = 0;
    }

    last_fire = clock_tick;
    setPaused();
    return true;
}

unsigned int watchdog::wake()
{
    return last_fire + interval;
}
