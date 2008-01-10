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


task::task() {
  this->taskit = all_tasks.insert(all_tasks.end(), this);
  add_to_runqueue();
}

task::~task() {
  if (running) {
    remove_from_runqueue();
  } else {
    paused_tasks.remove_paused_task(this);
  }
  all_tasks.erase(taskit);
}

/* Put this task in the run queue. */
void task::add_to_runqueue() {
  this->runit = running_tasks.insert(running_tasks.end(), this);
  this->running = true;
}

void task::add_to_paused_tasks(bool increment) {
  paused_tasks.add_paused_task(this, increment);
}

/* Remove this task from the run queue. */
bool task::remove_from_runqueue() {
  if (!this->running) {
    return false;
  }
  running_tasks.erase(this->runit);
  this->running = false;
  return true;
}

/* Get the overall list of running tasks. */
task_list * get_running_tasks()
{
  return & running_tasks;
}

void abort_all_tasks() {
  for (task_list::iterator task_it = all_tasks.begin();
      task_it != all_tasks.end(); task_it = all_tasks.begin()) {
    (*task_it)->abort();
  }
}

void dump_tasks() {
  WARNING("---- %d Active Tasks ----\n", all_tasks.size());
  for (task_list::iterator task_it = all_tasks.begin();
      task_it != all_tasks.end(); task_it++) {
    (*task_it)->dump();
  }
}

task_list *timewheel::task2list(task *task) {
  unsigned int wake = task->wake();
  unsigned int wake_sigbits = wake;
  unsigned int base_sigbits = wheel_base;

  if (wake == 0) {
    return &forever_list;
  }

  wake_sigbits /= LEVEL_ONE_SLOTS;
  base_sigbits /= LEVEL_ONE_SLOTS;
  if (wake_sigbits == base_sigbits) {
    return &wheel_one[wake % LEVEL_ONE_SLOTS];
  }
  wake_sigbits /= LEVEL_TWO_SLOTS;
  base_sigbits /= LEVEL_TWO_SLOTS;
  if (wake_sigbits == base_sigbits) {
    return &wheel_two[(wake / LEVEL_ONE_SLOTS) % LEVEL_TWO_SLOTS];
  }
  assert(wake_sigbits < LEVEL_THREE_SLOTS);
  return &wheel_three[wake_sigbits];
}

int expire_paused_tasks() {
  return paused_tasks.expire_paused_tasks();
}
int paused_tasks_count() {
  return paused_tasks.size();
}

/* Iterate through our sorted set of paused tasks, removing those that
 * should no longer be paused, and adding them to the run queue. */
int timewheel::expire_paused_tasks() {
  int found = 0;

  while (wheel_base < clock_tick) {
    int slot1 = wheel_base % LEVEL_ONE_SLOTS;

    /* Migrate tasks from slot2 when we hit 0. */
    if (slot1 == 0) {
      int slot2 = (wheel_base / LEVEL_ONE_SLOTS) % LEVEL_TWO_SLOTS;

      /* If slot2 is also zero, we must migrate tasks from slot3 into slot2. */
      if (slot2 == 0) {
	int slot3 = ((wheel_base / LEVEL_ONE_SLOTS) / LEVEL_TWO_SLOTS);
	assert(slot3 < LEVEL_THREE_SLOTS);

	for (task_list::iterator l3it = wheel_three[slot3].begin();
	     l3it != wheel_three[slot3].end();
	     l3it++) {
	  /* Migrate this task to wheel two. */
	  (*l3it)->add_to_paused_tasks(false);
        }

	wheel_three[slot3].clear();
      }

      for (task_list::iterator l2it = wheel_two[slot2].begin();
	  l2it != wheel_two[slot2].end();
	  l2it++) {
	/* Migrate this task to wheel one. */
	(*l2it)->add_to_paused_tasks(false);
      }

      wheel_two[slot2].clear();
    }

    found += wheel_one[slot1].size();
    for(task_list::iterator it = wheel_one[slot1].begin();
	it != wheel_one[slot1].end(); it++) {
      (*it)->add_to_runqueue();
      count--;
    }
    wheel_one[slot1].clear();

    wheel_base++;
  }

  return found;
}

void timewheel::add_paused_task(task *task, bool increment) {
  task_list::iterator task_it;
  task_list *list = task2list(task);
  task_it = list->insert(list->end(), task);
  task->pauselist = list;
  task->pauseit = task_it;
  if (increment) {
    count++;
  }
}

void timewheel::remove_paused_task(task *task) {
  task_list *list = task->pauselist;
  list->erase(task->pauseit);
  count--;
}

timewheel::timewheel() {
  count = 0;
  wheel_base = clock_tick;
}

int timewheel::size() {
  return count;
}

void task::setRunning() {
  if (!running) {
    paused_tasks.remove_paused_task(this);
    add_to_runqueue();
  }
}

void task::setPaused() {
    if (!remove_from_runqueue()) {
      ERROR("Tried to remove a running call that wasn't running!\n");
    }
    add_to_paused_tasks(true);
}
