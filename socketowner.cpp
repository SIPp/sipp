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
 *           Michael Dwyer from Cibation
 */

#include <iterator>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

#include "sipp.hpp"

socket_owner_map_map socket_to_owners;

struct sipp_socket *socketowner::associate_socket(struct sipp_socket *socket) {
  if (socket) {
    this->call_socket = socket;
    add_owner_to_socket(socket);
  }
  return socket;
}

struct sipp_socket *socketowner::dissociate_socket() {
  struct sipp_socket *ret = this->call_socket;

  remove_owner_from_socket(this->call_socket);
  this->call_socket = NULL;

  return ret;
}

unsigned long socketowner::nextownerid = 1;

socketowner::socketowner() {
  this->call_socket = NULL;
  this->ownerid = socketowner::nextownerid++;
}

socketowner::~socketowner() {
  sipp_close_socket(dissociate_socket());
}

void socketowner::add_owner_to_socket(struct sipp_socket *socket) {
  socket_owner_map_map::iterator map_it = socket_to_owners.find(socket);
  /* No map defined for this socket. */
  if (map_it == socket_to_owners.end()) {
    socket_to_owners.insert(socket_map_pair(socket, new owner_map));
    map_it = socket_to_owners.find(socket);
    assert(map_it != socket_to_owners.end());
  }

 owner_map *socket_owner_map = (owner_map *) map_it->second;
 socket_owner_map->insert(long_owner_pair(this->ownerid, this));
}

void socketowner::remove_owner_from_socket(struct sipp_socket *socket) {
  socket_owner_map_map::iterator map_it = socket_to_owners.find(socket);
  /* We must have  a map for this socket. */
  assert(map_it != socket_to_owners.end());

  owner_map *socket_owner_map = (owner_map *) map_it->second;
  owner_map::iterator owner_it = socket_owner_map->find(this->ownerid);
  /* And our owner must exist in the map. */
  assert(owner_it != socket_owner_map->end());
  socket_owner_map->erase(owner_it);

  /* If we have no more calls, we can delete this entry. */
  if (socket_owner_map->begin() == socket_owner_map->end()) {
    delete socket_owner_map;
    socket_to_owners.erase(map_it);
  }
}

/* The caller must delete this list. */
owner_list *get_owners_for_socket(struct sipp_socket *socket) {
  owner_list *l = new owner_list;

  socket_owner_map_map::iterator map_it = socket_to_owners.find(socket);

  /* No map defined for this socket. */
  if (map_it == socket_to_owners.end()) {
    return l;
  }

  owner_map *socket_owner_map = (owner_map *) map_it->second;
  owner_map::iterator owner_it;

  for (owner_it = socket_owner_map->begin();
       owner_it != socket_owner_map->end();
       owner_it++) {
	l->insert(l->end(), owner_it->second);
  }

  return l;
}
