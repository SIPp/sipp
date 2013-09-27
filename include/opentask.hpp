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

#ifndef OPENTASK_HPP
#define OPENTASK_HPP

#include "task.hpp"

class opentask : public task
{
public:
    static void initialize();
    static void set_rate(double new_rate);
    static void set_users(int new_users);
    static void set_paused(bool paused);
    static void freeUser(int userId);

    bool run();
    void dump();

protected:
    unsigned int wake();

private:
    opentask();
    virtual ~opentask();

    static class opentask *instance;
    static unsigned long calls_since_last_rate_change;
    static unsigned long last_rate_change_time;
};

#endif
