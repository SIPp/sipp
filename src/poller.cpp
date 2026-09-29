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

#include <errno.h>
#include <unistd.h>

#include "poller.hpp"

static short poll_events(unsigned events)
{
    return (events & POLLER_IN ? POLLIN : 0) | (events & POLLER_OUT ? POLLOUT : 0);
}

bool PollPoller::add(int fd, unsigned events, uint64_t key)
{
    if (index.count(fd)) {
        errno = EEXIST;
        return false;
    }
    index[fd] = fds.size();
    fds.push_back({fd, poll_events(events), 0});
    keys.push_back(key);
    return true;
}

bool PollPoller::modify(int fd, unsigned events, uint64_t key)
{
    auto it = index.find(fd);
    if (it == index.end()) {
        errno = ENOENT;
        return false;
    }
    fds[it->second].events = poll_events(events);
    keys[it->second] = key;
    return true;
}

bool PollPoller::remove(int fd)
{
    if (fd < 0) {
        errno = EBADF;
        return false;
    }
    auto it = index.find(fd);
    if (it == index.end()) {
        errno = ENOENT;
        return false;
    }
    /* the last one takes its place */
    size_t i = it->second;
    index.erase(it);
    if (i != fds.size() - 1) {
        fds[i] = fds.back();
        keys[i] = keys.back();
        index[fds[i].fd] = i;
    }
    fds.pop_back();
    keys.pop_back();
    return true;
}

int PollPoller::wait(int timeout_ms, PollerEvent* events, int max)
{
    int rc = poll(fds.data(), fds.size(), timeout_ms);
    if (rc <= 0) {
        return rc;
    }
    int n = 0;
    size_t start = next < fds.size() ? next : 0;
    for (size_t k = 0; k < fds.size() && n < max; k++) {
        size_t i = (start + k) % fds.size();
        short revents = fds[i].revents;
        if (!revents) {
            continue;
        }
        events[n].key = keys[i];
        events[n].events = (revents & POLLIN ? POLLER_IN : 0) | (revents & POLLOUT ? POLLER_OUT : 0) |
                           (revents & (POLLERR | POLLHUP | POLLNVAL) ? POLLER_ERR : 0);
        n++;
        next = i + 1;
    }
    return n;
}

#ifdef HAVE_EPOLL
static uint32_t epoll_events(unsigned events)
{
    return (events & POLLER_IN ? EPOLLIN : 0) | (events & POLLER_OUT ? EPOLLOUT : 0);
}

EpollPoller::EpollPoller() : epfd(epoll_create1(EPOLL_CLOEXEC))
{
}

EpollPoller::~EpollPoller()
{
    if (epfd != -1) {
        close(epfd);
    }
}

bool EpollPoller::add(int fd, unsigned events, uint64_t key)
{
    struct epoll_event ev = {};
    ev.events = epoll_events(events);
    ev.data.u64 = key;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) {
        return false;
    }
    count++;
    return true;
}

bool EpollPoller::modify(int fd, unsigned events, uint64_t key)
{
    struct epoll_event ev = {};
    ev.events = epoll_events(events);
    ev.data.u64 = key;
    return !epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
}

bool EpollPoller::remove(int fd)
{
    if (fd < 0) {
        errno = EBADF;
        return false;
    }
    /* one closed already is out: it counts as removed */
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr) && errno != EBADF && errno != ENOENT) {
        return false;
    }
    count--;
    return true;
}

int EpollPoller::wait(int timeout_ms, PollerEvent* events, int max)
{
    if (ready.size() < (size_t) max) {
        ready.resize(max);
    }
    int rc = epoll_wait(epfd, ready.data(), max, timeout_ms);
    for (int i = 0; i < rc; i++) {
        uint32_t e = ready[i].events;
        events[i].key = ready[i].data.u64;
        events[i].events = (e & EPOLLIN ? POLLER_IN : 0) | (e & EPOLLOUT ? POLLER_OUT : 0) |
                           (e & (EPOLLERR | EPOLLHUP) ? POLLER_ERR : 0);
    }
    return rc;
}
#endif

#ifdef GTEST
#include "gtest/gtest.h"

#include <sys/socket.h>

template <class T>
class PollerTest : public ::testing::Test
{
};

#ifdef HAVE_EPOLL
typedef ::testing::Types<PollPoller, EpollPoller> PollerTypes;
#else
typedef ::testing::Types<PollPoller> PollerTypes;
#endif
TYPED_TEST_SUITE(PollerTest, PollerTypes);

TYPED_TEST(PollerTest, events_come_with_their_keys) {
    TypeParam poller;
    ASSERT_TRUE(poller.valid());
    int a[2], b[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, a));
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, b));
    ASSERT_TRUE(poller.add(a[0], POLLER_IN, 10));
    ASSERT_TRUE(poller.add(b[0], POLLER_IN, 20));
    EXPECT_FALSE(poller.add(a[0], POLLER_IN, 11));
    EXPECT_EQ(EEXIST, errno);
    EXPECT_EQ(2u, poller.size());

    PollerEvent ev[4];
    EXPECT_EQ(0, poller.wait(0, ev, 4));
    ASSERT_EQ(1, write(b[1], "x", 1));
    ASSERT_EQ(1, poller.wait(100, ev, 4));
    EXPECT_EQ(20u, ev[0].key);
    EXPECT_EQ((unsigned) POLLER_IN, ev[0].events);

    /* a new key, and OUT: a datagram socket can take one */
    ASSERT_TRUE(poller.modify(a[0], POLLER_IN | POLLER_OUT, 12));
    ASSERT_EQ(2, poller.wait(0, ev, 4));
    unsigned keys = 0;
    for (int i = 0; i < 2; i++) {
        keys += ev[i].key;
        if (ev[i].key == 12) {
            EXPECT_EQ((unsigned) POLLER_OUT, ev[i].events);
        }
    }
    EXPECT_EQ(32u, keys);

    /* removed, it says nothing more */
    ASSERT_TRUE(poller.remove(b[0]));
    EXPECT_EQ(1u, poller.size());
    ASSERT_TRUE(poller.modify(a[0], POLLER_IN, 12));
    EXPECT_EQ(0, poller.wait(0, ev, 4));
    for (int fd : {a[0], a[1], b[0], b[1]}) {
        close(fd);
    }
}

TYPED_TEST(PollerTest, each_ready_one_gets_its_turn) {
    TypeParam poller;
    int s[3][2];
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, s[i]));
        ASSERT_EQ(1, write(s[i][1], "x", 1));
        ASSERT_TRUE(poller.add(s[i][0], POLLER_IN, i));
    }
    /* two at a time, of three ready: the third comes up next */
    PollerEvent ev[2];
    unsigned seen = 0;
    for (int round = 0; round < 2; round++) {
        int n = poller.wait(0, ev, 2);
        ASSERT_GE(n, 1);
        for (int i = 0; i < n; i++) {
            seen |= 1u << ev[i].key;
        }
    }
    EXPECT_EQ(7u, seen);
    for (auto& p : s) {
        close(p[0]);
        close(p[1]);
    }
}

TYPED_TEST(PollerTest, a_closed_one_removes) {
    TypeParam poller;
    int a[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, a));
    ASSERT_TRUE(poller.add(a[0], POLLER_IN, 1));
    close(a[0]);
    EXPECT_TRUE(poller.remove(a[0]));
    EXPECT_EQ(0u, poller.size());
    /* no descriptor: nothing to remove, and nothing counted */
    EXPECT_FALSE(poller.remove(-1));
    EXPECT_EQ(EBADF, errno);
    EXPECT_EQ(0u, poller.size());
    PollerEvent ev[1];
    EXPECT_EQ(0, poller.wait(0, ev, 1));
    close(a[1]);
}

#endif // GTEST
