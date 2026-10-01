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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 */

#ifndef __SIPP_STRINGS_H__
#define __SIPP_STRINGS_H__

#include <string>
#include <string.h>

int get_decimal_from_hex(char hex);
void get_host_and_port(const char *addr, char *host, int *port);
std::string wrap(const char *in, int offset, int size);

/* s = the n bytes at p, in a buffer of about their size, as realloc()
 * gave: assign() keeps a larger buffer, and grows one to twice its size */
inline void assign_exact(std::string &s, const char *p, size_t n)
{
    if (n > s.capacity() || n + 32 <= s.capacity()) {
        s = std::string(p, n);
    } else {
        s.assign(p, n);
    }
}

inline void assign_exact(std::string &s, const char *p)
{
    assign_exact(s, p, strlen(p));
}

#endif /* __SIPP_STRINGS_H__ */
