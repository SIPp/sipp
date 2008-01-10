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

#ifndef __SOCKETOWNER__
#define __SOCKETOWNER__

class socketowner {
public:
  socketowner();
  virtual ~socketowner();

  /* Associate/Dissociate this call with a socket. */
  struct sipp_socket *associate_socket(struct sipp_socket *socket);
  struct sipp_socket *dissociate_socket();

  /* Notification of TCP Close events. */
  virtual void tcpClose() = 0;
protected:
  /* What socket is this call bound to. */
  struct sipp_socket *call_socket;
  unsigned long ownerid;
  static unsigned long nextownerid;

private:
  void add_owner_to_socket(struct sipp_socket *socket);
  void remove_owner_from_socket(struct sipp_socket *socket);
};

typedef std::map<unsigned long, socketowner *> owner_map;
typedef std::pair<struct sipp_socket *,owner_map *> socket_map_pair;
typedef std::map<struct sipp_socket *, void *> socket_owner_map_map;
typedef std::list<socketowner *> owner_list;
typedef std::pair<unsigned long, socketowner *> long_owner_pair;
owner_list *get_owners_for_socket(struct sipp_socket *socket);

#endif
