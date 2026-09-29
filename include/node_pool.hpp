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
 * listeners only. */
template <size_t Size>
class node_pool
{
public:
    static void *allocate()
    {
        if (!free_blocks) {
            const size_t count = 65536 / sizeof(block);
            block *slab = static_cast<block *>(::operator new(count * sizeof(block)));
            for (size_t i = 0; i < count; i++) {
                slab[i].next = free_blocks;
                free_blocks = &slab[i];
            }
        }
        block *b = free_blocks;
        free_blocks = b->next;
        return b;
    }

    static void deallocate(void *p)
    {
        block *b = static_cast<block *>(p);
        b->next = free_blocks;
        free_blocks = b;
    }

private:
    union block {
        block *next;
        alignas(std::max_align_t) unsigned char data[Size];
    };
    static inline block *free_blocks = nullptr;
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
