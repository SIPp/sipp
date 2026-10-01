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
 *           Charles P. Wright from IBM Research
 */
#include <functional>
#include <string_view>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include "sipp.hpp"
#include "deadcall.hpp"

/* The keys the listeners take messages for: their ids and the keys they
 * listen to. With the dead calls of -deadcall_wait, a high call rate
 * keeps a million. An open addressing table, split by hash into parts
 * that each grow on their own: growing one moves only its part of the
 * entries, where a single table growing would hold up the main loop for
 * milliseconds. */
struct listener_slot {
    const char *key; /* in storage of the listener it maps to */
    listener *owner; /* none: the slot is free */
    uint32_t hash;
    uint32_t len;
};

struct listener_part {
    listener_slot *slots;
    uint32_t mask;
    uint32_t used;
};

static const uint32_t listener_parts = 1024;

static struct listener_table {
    listener_part parts[listener_parts];

    ~listener_table()
    {
        for (listener_part &part : parts) {
            delete[] part.slots;
            part = listener_part();
        }
    }
} listeners;

static uint32_t key_hash(const char *key, uint32_t len)
{
    return std::hash<std::string_view>()(std::string_view(key, len));
}

static listener_part &part_of(uint32_t hash)
{
    return listeners.parts[hash % listener_parts];
}

/* Where the entry of the hash starts probing in its part */
static uint32_t home_slot(const listener_part &part, uint32_t hash)
{
    return (hash / listener_parts) & part.mask;
}

/* The slot of the key in its part, or the free one where it would go */
static listener_slot *probe(const listener_part &part, const char *key, uint32_t len, uint32_t hash)
{
    for (uint32_t i = home_slot(part, hash);; i = (i + 1) & part.mask) {
        listener_slot *slot = &part.slots[i];
        if (!slot->owner || (slot->hash == hash && slot->len == len && !memcmp(slot->key, key, len))) {
            return slot;
        }
    }
}

/* Twice the slots, or the first ones */
static void grow(listener_part &part)
{
    listener_part old = part;
    uint32_t size = old.slots ? (old.mask + 1) * 2 : 8;
    part.slots = new listener_slot[size]();
    part.mask = size - 1;
    for (uint32_t i = 0; old.slots && i <= old.mask; i++) {
        const listener_slot &slot = old.slots[i];
        if (slot.owner) {
            *probe(part, slot.key, slot.len, slot.hash) = slot;
        }
    }
    delete[] old.slots;
}

/* The slot of the key, nullptr if it has none */
static listener_slot *find_slot(std::string_view key)
{
    uint32_t len = key.size();
    uint32_t hash = key_hash(key.data(), len);
    const listener_part &part = part_of(hash);
    if (!part.slots) {
        return nullptr;
    }
    listener_slot *slot = probe(part, key.data(), len, hash);
    return slot->owner ? slot : nullptr;
}

/* The slot of the key, or a free one counted as taken: the caller fills
 * it */
static listener_slot *take_slot(const char *key, uint32_t len, uint32_t hash)
{
    listener_part &part = part_of(hash);
    /* at most 3/4 full, for short probes */
    if (!part.slots || (part.used + 1) * 4 > (part.mask + 1) * 3) {
        grow(part);
    }
    listener_slot *slot = probe(part, key, len, hash);
    if (!slot->owner) {
        part.used++;
    }
    return slot;
}

static void free_slot(listener_slot *slot)
{
    listener_part &part = part_of(slot->hash);
    uint32_t hole = slot - part.slots;
    /* Move back into the hole the entries after it that probing for
     * them would not find past it */
    for (uint32_t i = (hole + 1) & part.mask; part.slots[i].owner; i = (i + 1) & part.mask) {
        uint32_t home = home_slot(part, part.slots[i].hash);
        if (((i - home) & part.mask) >= ((i - hole) & part.mask)) {
            part.slots[hole] = part.slots[i];
            hole = i;
        }
    }
    part.slots[hole].owner = nullptr;
    part.used--;
}

listener::listener(std::string_view id, bool listening)
{
    this->id = strndup(id.data(), id.size());
    this->listening = false;
    this->own_id = true;
    if (listening) {
        startListening();
    }
}

listener::listener(const char *id, char *storage, size_t size)
{
    size_t len = strlen(id);
    own_id = len >= size;
    if (own_id) {
        this->id = strdup(id);
    } else {
        this->id = static_cast<char *>(memcpy(storage, id, len + 1));
    }
    this->listening = false;
}

void listener::startListening()
{
    assert(!listening);
    listen(id);
    listening = true;
}

void listener::stopListening()
{
    assert(listening);
    unlisten(id);
    listening = false;
}

void listener::listen(const char *key)
{
    uint32_t len = strlen(key);
    uint32_t hash = key_hash(key, len);
    listener_slot *slot = take_slot(key, len, hash);
    if (slot->owner) {
        /* Another listener has this Call-ID, most likely the dead call
         * of an earlier call: the messages are ours from now on, and it
         * leaves the entry alone when it stops. A dead call leaves a live
         * call's messages to it. */
        if (!dynamic_cast<deadcall *>(slot->owner)) {
            if (dynamic_cast<deadcall *>(this)) {
                return;
            }
            WARNING("Call-ID '%s' is already in use by another call", key);
        }
    }
    /* The key is in the storage of the listener it maps to */
    *slot = listener_slot{key, this, hash, len};
}

void listener::unlisten(const char *key)
{
    listener_slot *slot = find_slot(key);
    if (slot && slot->owner == this) {
        free_slot(slot);
    }
}

char *listener::getId()
{
    return id;
}

listener::~listener()
{
    if (listening) {
        stopListening();
    }
    if (own_id) {
        free(id);
    }
    id = nullptr;
}

listener *get_listener(std::string_view id)
{
    listener_slot *slot = find_slot(id);
    return slot ? slot->owner : nullptr;
}

#ifdef GTEST
#include "gtest/gtest.h"
#include <map>
#include <string>
#include <vector>

namespace
{
class test_listener : public listener
{
public:
    test_listener() : listener("test", false) {}
    bool process_incoming(const char *, const struct sockaddr_storage *, SIPpSocket *) override
    {
        return true;
    }
    bool process_twinSippCom(char *) override
    {
        return true;
    }
    using listener::listen;
    using listener::unlisten;
};
} // namespace

TEST(listener, keys_found_while_parts_grow_and_entries_go)
{
    /* Enough keys for the parts to grow and their probes to collide */
    std::vector<std::string> keys;
    for (int i = 0; i < 100000; i++) {
        keys.push_back(std::to_string(i) + "-1234@127.0.0.1");
    }
    test_listener owners[2];
    std::map<size_t, test_listener *> expected;
    unsigned seed = 1;
    for (int n = 1; n <= 1000000; n++) {
        seed = seed * 1103515245 + 12345;
        size_t k = (seed >> 8) % keys.size();
        test_listener *owner = &owners[(seed >> 4) & 1];
        std::map<size_t, test_listener *>::iterator it = expected.find(k);
        if (it == expected.end()) {
            owner->listen(keys[k].c_str());
            expected[k] = owner;
        } else {
            /* not ours: it stays */
            owner->unlisten(keys[k].c_str());
            if (it->second == owner) {
                expected.erase(it);
            }
        }
        if (n % 250000 == 0) {
            for (size_t i = 0; i < keys.size(); i++) {
                it = expected.find(i);
                ASSERT_EQ(get_listener(keys[i].c_str()), it == expected.end() ? nullptr : it->second);
            }
        }
    }
    for (std::pair<const size_t, test_listener *> &entry : expected) {
        entry.second->unlisten(keys[entry.first].c_str());
    }
    for (std::string &key : keys) {
        ASSERT_EQ(get_listener(key.c_str()), nullptr);
    }
}

#endif // GTEST
