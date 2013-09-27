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

/***************** System Portability Features *****************/

unsigned long long getmicroseconds()
{
    struct timeval LS_system_time;
    unsigned long long VI_micro;
    static unsigned long long VI_micro_base = 0;

    gettimeofday(&LS_system_time, NULL);
    VI_micro = (((unsigned long long) LS_system_time.tv_sec) * 1000000LL) + LS_system_time.tv_usec;
    if (!VI_micro_base) VI_micro_base = VI_micro - 1;
    VI_micro = VI_micro - VI_micro_base;

    clock_tick = VI_micro / 1000LL;

    return VI_micro;
}

unsigned long getmilliseconds()
{
    return getmicroseconds() / 1000LL;
}

void sipp_usleep(unsigned long usec)
{
    if (usec >= 1000000) {
        sleep(usec / 1000000);
    }
    usec %= 1000000;
    usleep(usec);
}

/***************** System Portability Features *****************/
