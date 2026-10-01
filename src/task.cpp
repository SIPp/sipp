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

task_list all_tasks;
task_list running_tasks;
/* The first task in the run queue that has not run yet, or its end: a
 * task that resumes goes before it, a new task after it. */
static task_list::iterator first_new = running_tasks.end();
timewheel paused_tasks;

/* Get the overall list of running tasks. */
task_list* get_running_tasks()
{
    return &running_tasks;
}

/* Get the list of all tasks, running or paused. */
task_list* get_all_tasks()
{
    return &all_tasks;
}

void abort_all_tasks()
{
    for (task_list::iterator task_it = all_tasks.begin();
         task_it != all_tasks.end();
         task_it = all_tasks.begin()) {
        (*task_it)->abort();
    }
}

void dump_tasks()
{
    WARNING("---- %zu Active Tasks ----", all_tasks.size());
    for (task_list::iterator task_it = all_tasks.begin();
         task_it != all_tasks.end();
         task_it++) {
        (*task_it)->dump();
    }
}

int expire_paused_tasks()
{
    return paused_tasks.expire_paused_tasks();
}
int paused_tasks_count()
{
    return paused_tasks.size();
}

// Methods for the task class

task::task()
{
    this->taskit = all_tasks.insert(all_tasks.end(), this);
    /* A new task goes last: its first turn may be slow (a call binds
     * its RTP sockets there), and no peer waits on it yet. */
    this->runit = running_tasks.insert(running_tasks.end(), this);
    this->running = true;
    if (first_new == running_tasks.end()) {
        first_new = this->runit;
    }
}

task::~task()
{
    if (running) {
        remove_from_runqueue();
    } else {
        paused_tasks.remove_paused_task(this);
    }
    all_tasks.erase(taskit);
}

/* Put this task back in the run queue: a message came in for it, or
 * its pause is over. It goes before the tasks that have not run yet. */
void task::add_to_runqueue()
{
    this->runit = running_tasks.insert(first_new, this);
    this->running = true;
}

void task::add_to_paused_tasks()
{
    paused_tasks.add_paused_task(this);
}

/* Remove this task from the run queue. */
bool task::remove_from_runqueue()
{
    if (!this->running) {
        return false;
    }
    if (this->runit == first_new) {
        ++first_new;
    }
    running_tasks.erase(this->runit);
    this->running = false;
    return true;
}

void task::setRunning()
{
    if (!running) {
        paused_tasks.remove_paused_task(this);
        add_to_runqueue();
    }
}

void task::setPaused()
{
    if (running) {
        if (!remove_from_runqueue()) {
            WARNING("Tried to remove a running call that wasn't running!");
            assert(0);
        }
    } else {
        paused_tasks.remove_paused_task(this);
    }
    assert(running == false);
    add_to_paused_tasks();
}

void task::abort()
{
    delete this;
}

// Methods for the timewheel class

// Based on the time a given task should next be woken up, finds the
// correct time wheel for it and returns a list of other tasks
// occurring at that point.
task_list *timewheel::task2list(unsigned int wake)
{
    if (wake == 0) {
        return &forever_list;
    }

    assert(wake >= wheel_base);
    if (wheel_base > clock_tick) {
        ERROR("wheel_base is %lu, clock_tick is %lu - expected wheel_base to be less than or equal to clock_tick", wheel_base, clock_tick);
        assert(wheel_base <= clock_tick);
    }

    unsigned int slot_in_first_wheel = wake % LEVEL_ONE_SLOTS;
    unsigned int slot_in_second_wheel = (wake / LEVEL_ONE_SLOTS) % LEVEL_TWO_SLOTS;
    unsigned int slot_in_third_wheel = (wake / (LEVEL_ONE_SLOTS * LEVEL_TWO_SLOTS));

    bool fits_in_first_wheel = ((wake / LEVEL_ONE_SLOTS) == (wheel_base / LEVEL_ONE_SLOTS));
    bool fits_in_second_wheel = ((wake / (LEVEL_ONE_SLOTS * LEVEL_TWO_SLOTS)) ==
            (wheel_base / (LEVEL_ONE_SLOTS * LEVEL_TWO_SLOTS)));
    bool fits_in_third_wheel = (slot_in_third_wheel < LEVEL_THREE_SLOTS);

    if (fits_in_first_wheel) {
        return &wheel_one[slot_in_first_wheel];
    } else if (fits_in_second_wheel) {
        return &wheel_two[slot_in_second_wheel];
    } else if (fits_in_third_wheel) {
        return &wheel_three[slot_in_third_wheel];
    } else{
        ERROR("Attempted to schedule a task too far in the future");
        return nullptr;
    }
}

/* Iterate through our sorted set of paused tasks, removing those that
 * should no longer be paused, and adding them to the run queue. */
int timewheel::expire_paused_tasks()
{
    int found = 0;

    // This while loop counts up from the wheel_base (i.e. the time
    // this function last ran) to the current scheduler time (i.e. clock_tick).
    while (wheel_base < clock_tick) {
        int slot1 = wheel_base % LEVEL_ONE_SLOTS;

        /* If slot1 is 0 (i.e. wheel_base is a multiple of 4096ms),
         * we need to repopulate the first timer wheel with the
         * contents of the first available slot of the second wheel. */
        if (slot1 == 0) {

          /* slot2 represents the slot in the second timer wheel
           * containing the tasks for the next ~4s. So when
           * wheel_base is 4096, wheel2[1] will be moved into wheel 1,
           * when wheel_base of 8192 wheel2[2] will be moved into
           * wheel 1, etc. */
            int slot2 = (wheel_base / LEVEL_ONE_SLOTS) % LEVEL_TWO_SLOTS;

            /* If slot2 is also zero, we must migrate tasks from slot3 into slot2. */
            if (slot2 == 0) {
              /* Same logic above, except that each slot of wheel3
                contains the next 69 minutes of tasks, enough to
                completely fill wheel 2. */
                int slot3 = ((wheel_base / LEVEL_ONE_SLOTS) / LEVEL_TWO_SLOTS);
                assert(slot3 < LEVEL_THREE_SLOTS);

                /* Migrate these tasks to wheel two. */
                for (size_t n = wheel_three[slot3].size(); n; n--) {
                    relocate(wheel_three[slot3].front());
                }
            }

            /* Repopulate wheel 1 from wheel 2 (which will now be full
               of the tasks pulled from wheel 3, if that was
               necessary) */
            for (size_t n = wheel_two[slot2].size(); n; n--) {
                relocate(wheel_two[slot2].front());
            }
        }

        /* Move tasks from the current slot of wheel 1 (i.e. the tasks
        scheduled to fire in the 1ms interval represented by
        wheel_base) onto a run queue. */
        found += wheel_one[slot1].size();
        for(task_list::iterator it = wheel_one[slot1].begin();
                it != wheel_one[slot1].end(); it++) {
            (*it)->add_to_runqueue();
            // Decrement the total number of tasks in this wheel.
            count--;
        }
        wheel_one[slot1].clear();

        wheel_base++; // Move wheel_base to the next 1ms interval
    }

    return found;
}

// Adds a task to the correct timewheel, or to the run queue if its
// wake time is past.
void timewheel::add_paused_task(task *task)
{
    unsigned int wake = task->wake();
    if (wake && wake < wheel_base) {
        task->add_to_runqueue();
        return;
    }
    task_list *list = task2list(wake);
    task->pauseit = list->insert(list->end(), task);
    task->pauselist = list;
    count++;
}

/* The list node moves with the task, so its iterator stays valid. */
void timewheel::relocate(task *task)
{
    unsigned int wake = task->wake();
    if (wake && wake < wheel_base) {
        remove_paused_task(task);
        task->add_to_runqueue();
        return;
    }
    task_list *list = task2list(wake);
    list->splice(list->end(), *task->pauselist, task->pauseit);
    task->pauselist = list;
}

void timewheel::remove_paused_task(task *task)
{
    task_list *list = task->pauselist;
    list->erase(task->pauseit);
    count--;
}

timewheel::timewheel()
{
    count = 0;
    wheel_base = clock_tick;
}

int timewheel::size()
{
    return count;
}

#ifdef GTEST
#include "gtest/gtest.h"

#include <climits>
#include <memory>
#include <random>
#include <set>
#include <vector>

/* A task that wakes up when it is told. */
class wheel_test_task : public task
{
public:
    unsigned int at = 0;
    bool run() override
    {
        return true;
    }
    void dump() override {}
    unsigned int wake() override
    {
        return at;
    }
};

class TimewheelTest : public ::testing::Test
{
protected:
    std::unique_ptr<timewheel> wheel;
    std::vector<std::unique_ptr<wheel_test_task>> tasks;
    std::set<task *> paused;
    unsigned long saved_clock = clock_tick;

    void start(unsigned long now)
    {
        clock_tick = now;
        wheel.reset(new timewheel());
    }

    void TearDown() override
    {
        for (auto &t : tasks) {
            resume(t.get());
        }
        tasks.clear();
        clock_tick = saved_clock;
    }

    wheel_test_task *new_task()
    {
        tasks.emplace_back(new wheel_test_task());
        return tasks.back().get();
    }

    /* Pause a running task until at: false if it runs right away. */
    bool pause(wheel_test_task *t, unsigned int at)
    {
        t->at = at;
        t->remove_from_runqueue();
        wheel->add_paused_task(t);
        if (t->running) {
            return false;
        }
        paused.insert(t);
        return true;
    }

    void resume(task *t)
    {
        if (paused.erase(t)) {
            wheel->remove_paused_task(t);
            t->add_to_runqueue();
        }
    }

    /* The tasks that the clock at now wakes, in their run queue order. */
    std::vector<task *> expire(unsigned long now, int *found = nullptr)
    {
        clock_tick = now;
        int n = wheel->expire_paused_tasks();
        if (found) {
            *found = n;
        }
        /* They went last in the run queue, before the new tasks. */
        std::vector<task *> woken;
        for (task_list::iterator it = first_new; it != running_tasks.begin();) {
            if (!paused.erase(*--it)) {
                break;
            }
            woken.push_back(*it);
        }
        std::reverse(woken.begin(), woken.end());
        return woken;
    }

    /* Random pauses, resumes and clock steps from start, against a
     * reference: a task wakes once the clock is past its wake time,
     * in the order of the wake times, then of the pauses. */
    void check_against_reference(unsigned long now, unsigned int seed)
    {
        std::mt19937_64 rng(seed);
        auto below = [&rng](unsigned long n) { return (unsigned long)(rng() % n); };
        std::map<std::pair<unsigned long, unsigned long>, task *> due;
        std::map<task *, std::pair<unsigned long, unsigned long>> slot;
        std::set<task *> forever;
        unsigned long seq = 0;

        start(now);
        for (int i = 0; i < 300; i++) {
            new_task();
        }
        for (int step = 0; step < 100000; step++) {
            int what = below(100);
            if (what < 45) {
                unsigned long r = below(100);
                if (r < 60) {
                    now += 1;
                } else if (r < 85) {
                    now += 2 + below(20);
                } else if (r < 95) {
                    now += 20 + below(1000);
                } else {
                    now += 1000 + below(20000);
                }
                int found;
                std::vector<task *> woken = expire(now, &found);
                std::vector<task *> expected;
                while (!due.empty() && due.begin()->first.first < now) {
                    expected.push_back(due.begin()->second);
                    slot.erase(due.begin()->second);
                    due.erase(due.begin());
                }
                ASSERT_EQ(expected, woken) << "at " << now;
                ASSERT_EQ((int)woken.size(), found);
            } else if (what < 85) {
                wheel_test_task *t = tasks[below(tasks.size())].get();
                if (!t->running) {
                    continue;
                }
                unsigned long r = below(100), at;
                if (r < 5) {
                    at = 0;
                } else if (r < 15) {
                    at = now - below(std::min(now, 5000UL) + 1);
                } else if (r < 20) {
                    at = now;
                } else if (r < 40) {
                    at = now + below(LEVEL_ONE_SLOTS);
                } else if (r < 55) {
                    at = now + below(3 * LEVEL_ONE_SLOTS);
                } else if (r < 65) {
                    /* many on the same ms */
                    at = (now / 1000 + 1 + below(12)) * 1000;
                } else if (r < 70) {
                    /* the same ms, paused long apart */
                    unsigned long order = below(2) ? 22 : 12;
                    at = ((now >> order) + 1 + below(2)) << order | below(3);
                } else if (r < 90) {
                    at = now + below(1UL << 23);
                } else {
                    at = now + below(1UL << 31);
                }
                at = std::min(at, (unsigned long)UINT_MAX);
                bool waits = pause(t, at);
                if (!at) {
                    forever.insert(t);
                } else if (at >= now) {
                    std::pair<unsigned long, unsigned long> key(at, seq++);
                    due[key] = t;
                    slot[t] = key;
                }
                ASSERT_EQ(!at || at >= now, waits) << "at " << now;
            } else {
                task *t = tasks[below(tasks.size())].get();
                if (slot.count(t)) {
                    due.erase(slot[t]);
                    slot.erase(t);
                }
                forever.erase(t);
                resume(t);
            }
            ASSERT_EQ((int)(due.size() + forever.size()), wheel->size());
        }
    }
};

TEST_F(TimewheelTest, MatchesReference)
{
    check_against_reference(0, 1);
}

TEST_F(TimewheelTest, MatchesReferenceMidWindow)
{
    check_against_reference(5 * LEVEL_ONE_SLOTS - 300, 2);
}

TEST_F(TimewheelTest, MatchesReferenceBeforeThirdWheel)
{
    check_against_reference(LEVEL_ONE_SLOTS * LEVEL_TWO_SLOTS - LEVEL_ONE_SLOTS - 500, 3);
}

TEST_F(TimewheelTest, MatchesReferenceLater)
{
    check_against_reference(7UL * LEVEL_ONE_SLOTS * LEVEL_TWO_SLOTS - 50, 4);
}

/* A task whose wake time changes as it waits in the second wheel wakes
 * at the new time. */
TEST_F(TimewheelTest, WakeMovedLater)
{
    start(0);
    wheel_test_task *t = new_task();
    ASSERT_TRUE(pause(t, 2 * LEVEL_ONE_SLOTS + 10));
    expire(100);
    t->at = 3 * LEVEL_ONE_SLOTS + 20;
    for (unsigned long now = 101; now <= t->at; now++) {
        ASSERT_TRUE(expire(now).empty()) << "at " << now;
    }
    EXPECT_EQ(std::vector<task *>({t}), expire(t->at + 1));
    EXPECT_EQ(0, wheel->size());
}

/* Moved to a past time, it wakes at the latest when its first time's
 * window starts. */
TEST_F(TimewheelTest, WakeMovedEarlier)
{
    start(0);
    wheel_test_task *t = new_task();
    ASSERT_TRUE(pause(t, 2 * LEVEL_ONE_SLOTS + 10));
    expire(100);
    t->at = 50;
    unsigned long now = 100;
    while (expire(++now).empty()) {
        ASSERT_LE(now, 2 * LEVEL_ONE_SLOTS) << "not woken";
    }
    EXPECT_EQ(0, wheel->size());
}

/* A task that never wakes stays until it is resumed. */
TEST_F(TimewheelTest, Forever)
{
    start(0);
    wheel_test_task *t = new_task();
    ASSERT_TRUE(pause(t, 0));
    EXPECT_TRUE(expire(10UL * LEVEL_ONE_SLOTS * LEVEL_TWO_SLOTS).empty());
    EXPECT_EQ(1, wheel->size());
    resume(t);
    EXPECT_EQ(0, wheel->size());
}

#endif // GTEST
