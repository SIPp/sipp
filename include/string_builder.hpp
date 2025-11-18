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

#ifndef __STRING_BUILDER_HPP__
#define __STRING_BUILDER_HPP__

#include <cstddef>
#include <cstring>
#include <charconv>
#include <type_traits>

class StringBuilder {
    char* buffer;
    char* current;
    size_t remaining;

public:
    StringBuilder(char* buf, size_t size);

    template<size_t N>
    StringBuilder(char (&buf)[N]) : StringBuilder(buf, N) {}

    StringBuilder& operator<<(const char* str);

    template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
    StringBuilder& operator<<(T val) {
        if (remaining > 1) {
            auto result = std::to_chars(current, current + remaining - 1, val);
            if (result.ec == std::errc()) {
                const size_t written = result.ptr - current;
                current = result.ptr;
                remaining -= written;
                *current = '\0';
            }
            // If result.ec != std::errc(), the number is too long, so don't write anything
        }
        return *this;
    }

    const char* get() const { return buffer; }
};

#endif // __STRING_BUILDER_HPP__
