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

#include "string_builder.hpp"
#include <cstring>

StringBuilder::StringBuilder(char* buf, size_t size) : buffer(buf), current(buf), remaining(size) {
    if (remaining > 0) {
        buffer[0] = '\0';
    }
}

StringBuilder& StringBuilder::operator<<(const char* str) {
    if (str && remaining > 1) {
        const size_t len = strlen(str);
        const size_t to_copy = (len < remaining - 1) ? len : remaining - 1;
        memcpy(current, str, to_copy);
        current += to_copy;
        remaining -= to_copy;
        *current = '\0';
    }
    return *this;
}
