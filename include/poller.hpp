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
 */

#ifndef __POLLER__
#define __POLLER__

#include <cstdint>
#include <unordered_map>
#include <vector>
#include <poll.h>

#include "config.h"
#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif

/* The descriptors a loop waits on, each with a key that its events come
 * back with. Poller is EpollPoller where there is epoll, and PollPoller,
 * over poll(), elsewhere; the two do the same, but epoll forgets a
 * descriptor once it is closed, and poll() keeps reporting it: remove()
 * one before or right after closing it, before the next wait(). */
struct PollerEvent
{
    uint64_t key;
    unsigned events; /* POLLER_IN, POLLER_OUT, POLLER_ERR */
};

enum { POLLER_IN = 1, POLLER_OUT = 2, POLLER_ERR = 4 };

class PollPoller
{
public:
    bool valid() const { return true; }
    /* false with errno set, as epoll_ctl() */
    bool add(int fd, unsigned events, uint64_t key);
    bool modify(int fd, unsigned events, uint64_t key);
    bool remove(int fd);
    size_t size() const { return fds.size(); }
    /* Up to max events in *events: how many, 0 once timeout_ms (-1 for
     * ever) has passed, -1 with errno set on an error, as epoll_wait() */
    int wait(int timeout_ms, PollerEvent* events, int max);

private:
    std::vector<struct pollfd> fds;
    std::vector<uint64_t> keys;
    std::unordered_map<int, size_t> index;
    size_t next = 0; /* where the next events start: each gets its turn */
};

#ifdef HAVE_EPOLL
class EpollPoller
{
public:
    EpollPoller();
    ~EpollPoller();
    EpollPoller(const EpollPoller&) = delete;
    EpollPoller& operator=(const EpollPoller&) = delete;

    bool valid() const { return epfd != -1; }
    bool add(int fd, unsigned events, uint64_t key);
    bool modify(int fd, unsigned events, uint64_t key);
    bool remove(int fd);
    size_t size() const { return count; }
    int wait(int timeout_ms, PollerEvent* events, int max);

private:
    int epfd;
    size_t count = 0;
    std::vector<struct epoll_event> ready;
};

typedef EpollPoller Poller;
#else
typedef PollPoller Poller;
#endif

#endif /* __POLLER__ */
