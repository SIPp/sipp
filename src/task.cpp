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
timewheel paused_tasks;

/* Get the overall list of running tasks. */
task_list* get_running_tasks()
{
    return &running_tasks;
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
    WARNING("---- %d Active Tasks ----\n", all_tasks.size());
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
    add_to_runqueue();
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

/* Put this task in the run queue. */
void task::add_to_runqueue()
{
    this->runit = running_tasks.insert(running_tasks.end(), this);
    this->running = true;
}

void task::add_to_paused_tasks(bool increment)
{
    paused_tasks.add_paused_task(this, increment);
}

void task::recalculate_wheel() {
  add_to_paused_tasks(false);
}

/* Remove this task from the run queue. */
bool task::remove_from_runqueue()
{
    if (!this->running) {
        return false;
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
            WARNING("Tried to remove a running call that wasn't running!\n");
            assert(0);
        }
    } else {
        paused_tasks.remove_paused_task(this);
    }
    assert(running == false);
    add_to_paused_tasks(true);
}

void task::abort()
{
    delete this;
}

// Methods for the timewheel class

// Based on the time a given task should next be woken up, finds the
// correct time wheel for it and returns a list of other tasks
// occuring at that point.
task_list *timewheel::task2list(task *task)
{
  unsigned int wake = task->wake();

  if (wake == 0) {
        return &forever_list;
  }

  assert(wake >= wheel_base);
  assert(wheel_base <= clock_tick);

  unsigned int time_until_wake = wake - wheel_base;

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
      return NULL;
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

                for (task_list::iterator l3it = wheel_three[slot3].begin();
                        l3it != wheel_three[slot3].end();
                        l3it++) {
                    /* Migrate this task to wheel two. */
                  (*l3it)->recalculate_wheel();
                }

                wheel_three[slot3].clear();
            }

            /* Repopulate wheel 1 from wheel 2 (which will now be full
               of the tasks pulled from wheel 3, if that was
               necessary) */
            for (task_list::iterator l2it = wheel_two[slot2].begin();
                    l2it != wheel_two[slot2].end();
                    l2it++) {
                /* Migrate this task to wheel one. */
              (*l2it)->recalculate_wheel();
            }

            wheel_two[slot2].clear();
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

// Adds a task to the correct timewheel. When increment is false, does
// not increment the count of tasks owned by this timewheel, and so
// can be used for recalculating the wheel of an existing task.
void timewheel::add_paused_task(task *task, bool increment)
{
    task_list::iterator task_it;
    if (task->wake() && task->wake() < wheel_base) {
        task->add_to_runqueue();
        return;
    }
    task_list *list = task2list(task);
    task_it = list->insert(list->end(), task);
    task->pauselist = list;
    task->pauseit = task_it;
    if (increment) {
        count++;
    }
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

