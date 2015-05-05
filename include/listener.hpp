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
 *           From Hewlett Packard Company.
 *             Charles P. Wright from IBM Research
 */
#ifndef __LISTENER__
#define __LISTENER__

#include <map>
#include <iterator>
#include <list>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include "sipp.hpp"

class listener
{
public:
    listener(const char *id, bool listening);
    virtual ~listener();
    char *getId();
    virtual bool process_incoming(char * msg, struct sockaddr_storage *src) = 0;
    virtual bool process_twinSippCom(char * msg) = 0;

protected:
    void startListening();
    void stopListening();

    char *id;
    bool listening;
};

typedef std::map<std::string, listener *> listener_map;
listener * get_listener(const char *);

#endif
