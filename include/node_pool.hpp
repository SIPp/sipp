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

#ifndef __NODE_POOL__
#define __NODE_POOL__

#include <cstddef>
#include <new>

/* Blocks of one size, carved from 64 KB slabs and kept for reuse. The
 * dead calls stay for -deadcall_wait after the calls that the heap
 * hands out small chunks to: made from blocks of their own, with their
 * list and map entries, they don't pin the free chunks between the
 * calls' messages. Not thread-safe: for the main thread's tasks and
 * listeners only. At exit, once none of its blocks is in use, a pool
 * gives its slabs back, for a leak check to find nothing left. */
template <size_t Size>
class node_pool
{
public:
    static void *allocate()
    {
        (void)&at_exit;
        if (!free_blocks) {
            const size_t count = 65536 / sizeof(block);
            block *slab = static_cast<block *>(::operator new(count * sizeof(block)));
            /* its first block links the slabs */
            slab[0].next = slabs;
            slabs = slab;
            for (size_t i = 1; i < count; i++) {
                slab[i].next = free_blocks;
                free_blocks = &slab[i];
            }
        }
        block *b = free_blocks;
        free_blocks = b->next;
        used++;
        return b;
    }

    static void deallocate(void *p)
    {
        block *b = static_cast<block *>(p);
        b->next = free_blocks;
        free_blocks = b;
        /* the last one out, after exit began: a container destroyed
         * after this pool's at_exit */
        if (!--used && exiting) {
            release();
        }
    }

private:
    union block {
        block *next;
        alignas(std::max_align_t) unsigned char data[Size];
    };

    static void release()
    {
        while (slabs) {
            block *next = slabs->next;
            ::operator delete(slabs);
            slabs = next;
        }
        free_blocks = nullptr;
    }

    struct releaser {
        ~releaser()
        {
            exiting = true;
            if (!used) {
                release();
            }
        }
    };

    static inline block *free_blocks = nullptr;
    static inline block *slabs = nullptr;
    static inline size_t used = 0;
    static inline bool exiting = false;
    static inline releaser at_exit;
};

/* An allocator of container nodes from a node_pool */
template <class T>
struct node_allocator {
    typedef T value_type;

    node_allocator() = default;
    template <class U> node_allocator(const node_allocator<U> &) {}

    T *allocate(size_t n)
    {
        if (n != 1) {
            return static_cast<T *>(::operator new(n * sizeof(T)));
        }
        return static_cast<T *>(node_pool<sizeof(T)>::allocate());
    }

    void deallocate(T *p, size_t n)
    {
        if (n != 1) {
            ::operator delete(p);
            return;
        }
        node_pool<sizeof(T)>::deallocate(p);
    }
};

template <class T, class U>
bool operator==(const node_allocator<T> &, const node_allocator<U> &)
{
    return true;
}

template <class T, class U>
bool operator!=(const node_allocator<T> &, const node_allocator<U> &)
{
    return false;
}

#endif
