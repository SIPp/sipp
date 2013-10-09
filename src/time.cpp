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
 *	     Stefan Esser
 *           Andy Aicken
 */

#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "time.hpp"
#include "sipp.hpp"
#define MICROSECONDS_PER_SECOND 1000000LL
#define MILLISECONDS_PER_MICROSECOND 1000LL

// Returns the number of microseconds that have passed since SIPp
// started. Also updates the current clock_tick.
unsigned long long getmicroseconds()
{
    struct timeval time;
    unsigned long long microseconds;
    static unsigned long long start_time = 0;

    gettimeofday(&time, NULL);
    microseconds = (MICROSECONDS_PER_SECOND * time.tv_sec) + time.tv_usec;
    if (start_time == 0) {
      start_time = microseconds - 1;
    }
    microseconds = microseconds - start_time;

    // Static global from sipp.hpp
    clock_tick = microseconds / MILLISECONDS_PER_MICROSECOND;

    return microseconds;
}

// Returns the number of milliseconds that have passed since SIPp
// started. Also updates the current clock_tick.
unsigned long getmilliseconds()
{
    return getmicroseconds() / MILLISECONDS_PER_MICROSECOND;
}

// Sleeps for the given number of microseconds. Avoids the potential
// EINVAL when using usleep() to sleep for a second or more.
void sipp_usleep(unsigned long usec)
{
    if (usec >= 1000000) {
        sleep(usec / 1000000);
    }
    usec %= 1000000;
    usleep(usec);
}
