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

class ratetask *ratetask::instance = NULL;

void ratetask::initialize()
{
    assert(instance == NULL);
    if (rate_increase) {
        instance = new ratetask();
    }
}

void ratetask::dump()
{
    WARNING("Increasing call rate task.");
}

bool ratetask::run()
{
    if (quitting >= 10) {
        delete this;
        return false;
    }

    /* Statistics Logs. */
    if ((getmilliseconds() - last_rate_increase_time) >= rate_increase_freq)  {
        if (rate_increase) {
            rate += rate_increase;
            if (rate_max && (rate > rate_max)) {
                rate = rate_max;
                if (rate_quit) {
                    quitting += 10;
                }
            }
            CallGenerationTask::set_rate(rate);
            last_rate_increase_time = clock_tick;
        }
    }
    setPaused();
    return true;
}

unsigned int ratetask::wake()
{
    return last_rate_increase_time + rate_increase_freq;
}
