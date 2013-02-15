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
 *	     Charles P. Wright from IBM Research
 */
#include <map>
#include <iterator>
#include <list>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include "sipp.hpp"

listener_map listeners;

listener::listener(const char *id, bool listening)
{
    this->id = strdup(id);
    this->listening = false;
    if (listening) {
        startListening();
    }
}

void listener::startListening()
{
    assert(!listening);
    listeners.insert(pair<listener_map::key_type,listener *>(listener_map::key_type(id),this));
    listening = true;
}

void listener::stopListening()
{
    assert(listening);

    listener_map::iterator listener_it;
    listener_it = listeners.find(listener_map::key_type(id));
    listeners.erase(listener_it);

    listening = false;
}

char *listener::getId()
{
    return id;
}

listener::~listener()
{
    if (listening) {
        stopListening();
    }
    free(id);
    id = NULL;

}

listener *get_listener(const char *id)
{
    listener_map::iterator listener_it = listeners.find(listener_map::key_type(id));
    if (listener_it == listeners.end()) {
        return NULL;
    }
    return listener_it->second;
}
