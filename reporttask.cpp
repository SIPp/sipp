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

class stattask *stattask::instance = NULL;
class screentask *screentask::instance = NULL;

void stattask::initialize() {
  assert(instance == NULL);
  if (dumpInFile || useCountf || rate_increase) {
    instance = new stattask();
  }
}

void screentask::initialize() {
  assert(instance == NULL);
  if (report_freq) {
    instance = new screentask();
  }
}

void stattask::dump() {
  WARNING("Statistics reporting task.");
}
void screentask::dump() {
  WARNING("Screen update task.");
}

void screentask::report(bool last) {
    print_statistics(last);
    display_scenario->stats->computeStat(CStat::E_RESET_PD_COUNTERS);
    last_report_time  = getmilliseconds();
    scheduling_loops = 0;
}

bool screentask::run() {
  if (quitting > 11) {
    delete this;
    return false;
  }

  if (getmilliseconds() - last_report_time >= report_freq) {
    report(false);
  }

  setPaused();
  return true;
}

unsigned int screentask::wake() {
  return last_report_time + report_freq;
}

void stattask::report() {
    if(dumpInFile) {
      main_scenario->stats->dumpData();
    }
    if (useCountf) {
      print_count_file(countf, 0);
    }

    main_scenario->stats->computeStat(CStat::E_RESET_PL_COUNTERS);
    last_dump_time = clock_tick;
}

bool stattask::run() {
  /* Statistics Logs. */
  if((getmilliseconds() - last_dump_time) >= report_freq_dumpLog)  {
    if (rate_increase) {
      rate += rate_increase;
      if (rate_max && (rate > rate_max)) {
	rate = rate_max;
	if (rate_quit) {
	  quitting += 10;
	}
      }
      opentask::set_rate(rate);
    }
    report();
  }
  setPaused();
  return true;
}

unsigned int stattask::wake() {
  return last_dump_time + report_freq_dumpLog;
}
