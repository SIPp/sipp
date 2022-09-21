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
 *           Stefan Esser
 *           Andy Aicken
 */

#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#if defined(__MACH__) && defined(__APPLE__)
#include <mach/clock.h>
#include <mach/mach.h>
#endif
#include "time.hpp"
#include "sipp.hpp"
#define MICROSECONDS_PER_SECOND 1000000LL
#define MICROSECONDS_PER_MILLISECOND 1000LL
#define NANOSECONDS_PER_MICROSECOND 1000LL

// Returns the number of microseconds that have passed since SIPp
// started. Also updates the current clock_tick.
unsigned long long getmicroseconds()
{
    struct timespec time;
    unsigned long long microseconds;
    static unsigned long long start_time = 0;

#if defined(__MACH__) && defined(__APPLE__)
    // OS X does not have clock_gettime, use clock_get_time
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    time.tv_sec = mts.tv_sec;
    time.tv_nsec = mts.tv_nsec;
#else
#if defined(CLOCK_MONOTONIC_COARSE)
    clock_gettime(CLOCK_MONOTONIC_COARSE, &time);
#else
    clock_gettime(CLOCK_MONOTONIC, &time);
#endif
#endif
    microseconds = (MICROSECONDS_PER_SECOND * time.tv_sec) + (time.tv_nsec / NANOSECONDS_PER_MICROSECOND);
    if (start_time == 0) {
      start_time = microseconds - 1;
    }
    microseconds = microseconds - start_time;

    // Static global from sipp.hpp
    clock_tick = microseconds / MICROSECONDS_PER_MILLISECOND;

    return microseconds;
}

// Returns the number of milliseconds that have passed since SIPp
// started. Also updates the current clock_tick.
unsigned long getmilliseconds()
{
    return getmicroseconds() / MICROSECONDS_PER_MILLISECOND;
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
