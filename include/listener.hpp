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

#include <iterator>
#include <list>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include "sipp.hpp"

class SIPpSocket;

class listener
{
public:
    listener(const char *id, bool listening);
    virtual ~listener();
    char *getId();
    /* socket: the one msg came on. */
    virtual bool process_incoming(const char* msg, const struct sockaddr_storage* src,
                                  SIPpSocket *socket) = 0;
    virtual bool process_twinSippCom(char* msg) = 0;

protected:
    /* Not listening, the id in storage of the derived class if it fits */
    listener(const char *id, char *storage, size_t size);

    void startListening();
    void stopListening();
    /* Takes the messages of this Call-ID too, until unlisten(): key
     * must stay until then */
    void listen(const char *key);
    void unlisten(const char *key);

    char *id;
    bool listening;
    bool own_id; /* id is ours to free */
};

/* The listener of the id, or of a key it listens to */
listener * get_listener(const char *);

#endif
