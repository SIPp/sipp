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
 *           Charles P. Wright from IBM Research
 */
#include <map>
#include <iterator>
#include <list>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include "sipp.hpp"
#include "deadcall.hpp"

listener_map listeners;

listener::listener(const char *id, bool listening)
{
    this->id = strdup(id);
    this->listening = false;
    this->own_id = true;
    if (listening) {
        startListening();
    }
}

listener::listener(const char *id, char *storage, size_t size)
{
    size_t len = strlen(id);
    own_id = len >= size;
    if (own_id) {
        this->id = strdup(id);
    } else {
        this->id = static_cast<char *>(memcpy(storage, id, len + 1));
    }
    this->listening = false;
}

void listener::startListening()
{
    assert(!listening);
    listen(id);
    listening = true;
}

void listener::stopListening()
{
    assert(listening);
    unlisten(id);
    listening = false;
}

void listener::listen(const char *key)
{
    std::pair<listener_map::iterator, bool> ins =
        listeners.insert(std::pair<listener_map::key_type,listener *>(listener_map::key_type(key),this));
    if (!ins.second) {
        /* Another listener has this Call-ID, most likely the dead call
         * of an earlier call: the messages are ours from now on, and it
         * leaves the entry alone when it stops. A dead call leaves a live
         * call's messages to it. */
        if (!dynamic_cast<deadcall *>(ins.first->second)) {
            if (dynamic_cast<deadcall *>(this)) {
                return;
            }
            WARNING("Call-ID '%s' is already in use by another call", key);
        }
        /* The key is in the storage of the listener it maps to */
        listener_map::node_type entry = listeners.extract(ins.first);
        entry.key() = key;
        entry.mapped() = this;
        listeners.insert(std::move(entry));
    }
}

void listener::unlisten(const char *key)
{
    listener_map::iterator listener_it;
    listener_it = listeners.find(listener_map::key_type(key));
    if (listener_it != listeners.end() && listener_it->second == this) {
        listeners.erase(listener_it);
    }
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
    if (own_id) {
        free(id);
    }
    id = nullptr;
}

listener *get_listener(const char *id)
{
    listener_map::iterator listener_it = listeners.find(listener_map::key_type(id));
    if (listener_it == listeners.end()) {
        return nullptr;
    }
    return listener_it->second;
}
