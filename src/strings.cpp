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
 *           Marc LAMBERTON
 *           Olivier JACQUES
 *           Herve PELLAN
 *           David MANSUTTI
 *           Francois-Xavier Kowalski
 *           Gerard Lyonnaz
 *           Francois Draperi (for dynamic_id)
 *           From Hewlett Packard Company.
 *           F. Tarek Rogers
 *           Peter Higginson
 *           Vincent Luba
 *           Shriram Natarajan
 *           Guillaume Teissier from FTR&D
 *           Clement Chen
 *           Wolfgang Beck
 *           Charles P Wright from IBM Research
 *           Martin Van Leeuwen
 *           Andy Aicken
 *           Michael Hirschbichler
 */

#include "strings.hpp"
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

std::string get_host_and_port(const char *addr, int *port)
{
    /* Separate the port number (if any) from the host name.
     * Thing is, the separator is a colon (':').  The colon may also exist
     * in the host portion if the host is specified as an IPv6 address (see
     * RFC 2732).  If that's the case, then we need to skip past the IPv6
     * address, which should be contained within square brackets ('[',']').
     */
    std::string host;
    int port_result = 0;

    const char *initial_bracket = strchr(addr, '[');
    const char *second_bracket = initial_bracket ? strchr(initial_bracket, ']') : nullptr;
    if (second_bracket == nullptr) {
        /* addr is not a []-enclosed IPv6 address, but might still be IPv6 (without
         * a port), or IPv4 or a hostname (with or without a port) */
        const char *first_colon_location = strchr(addr, ':');
        if (first_colon_location != nullptr && strchr(first_colon_location + 1, ':') == nullptr) {
            /* IPv4 address or hostname with a colon in it: the value after
             * it is the port */
            host.assign(addr, first_colon_location - addr);
            port_result = atol(first_colon_location + 1);
        } else {
            /* No colon, or a second one: an IPv6 address without a port */
            host = addr;
        }
    } else {
        /* If '['..']' found, extract the host in them */
        host.assign(initial_bracket + 1, second_bracket - initial_bracket - 1);

        /* Check for a port specified after the ] */
        const char *colon_before_port = strchr(second_bracket + 1, ':');
        if (colon_before_port != nullptr) {
            port_result = atol(colon_before_port + 1);
        }
    }

    // Set the port argument if it wasn't NULL
    if (port != nullptr) {
        *port = port_result;
    }
    return host;
}

int get_decimal_from_hex(char hex)
{
    if (isdigit(hex))
        return hex - '0';
    else
        return tolower(hex) - 'a' + 10;
}

/* Wrap a help text: break a line longer than size characters at its last
 * space, or a word longer than a line where the line ends, and indent the
 * lines after the first by offset spaces, two more in an item starting
 * with '-'. */
std::string wrap(const char *in, int offset, int size)
{
    std::string out;
    size_t line = 0; /* where the text of the current line starts */
    int pos = 0;
    bool indent = false;

    for (const char *p = in; *p; p++) {
        out += *p;
        if (*p == '\n') {
            out.append(offset, ' ');
            line = out.size();
            pos = 0;
            indent = p[1] == '-';
        }
        if (++pos <= size) {
            continue;
        }
        std::string newline = "\n" + std::string(offset + (indent ? 2 : 0), ' ');
        size_t k = out.size() - 1;
        while (k > line && !isspace((unsigned char)out[k])) {
            k--;
        }
        if (k > line) {
            /* Break at the last space: the rest goes to the next line. */
            out.replace(k, 1, newline);
            line = k + newline.size();
            pos = out.size() - line + 1;
        } else {
            /* A word longer than a line: break it before this character. */
            out.insert(out.size() - 1, newline);
            line = out.size() - 1;
            pos = 2;
        }
    }
    return out;
}

#ifdef GTEST
#include "gtest/gtest.h"

TEST(GetHostAndPort, IPv6) {
    int port_result = -1;
    const std::string host_result = get_host_and_port("fe80::92a4:deff:fe74:7af5", &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_EQ("fe80::92a4:deff:fe74:7af5", host_result);
}

TEST(GetHostAndPort, IPv6Brackets) {
    int port_result = -1;
    const std::string host_result = get_host_and_port("[fe80::92a4:deff:fe74:7af5]", &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_EQ("fe80::92a4:deff:fe74:7af5", host_result);
}

TEST(GetHostAndPort, IPv6BracketsAndPort) {
    int port_result = -1;
    const std::string host_result = get_host_and_port("[fe80::92a4:deff:fe74:7af5]:999", &port_result);
    EXPECT_EQ(999, port_result);
    EXPECT_EQ("fe80::92a4:deff:fe74:7af5", host_result);
}

TEST(GetHostAndPort, IPv4) {
    int port_result = -1;
    const std::string host_result = get_host_and_port("127.0.0.1", &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_EQ("127.0.0.1", host_result);
}

TEST(GetHostAndPort, IPv4AndPort) {
    int port_result = -1;
    const std::string host_result = get_host_and_port("127.0.0.1:999", &port_result);
    EXPECT_EQ(999, port_result);
    EXPECT_EQ("127.0.0.1", host_result);
}

TEST(GetHostAndPort, IgnorePort) {
    const std::string host_result = get_host_and_port("127.0.0.1", nullptr);
    EXPECT_EQ("127.0.0.1", host_result);
}

TEST(GetHostAndPort, DNS) {
    int port_result = -1;
    const std::string host_result = get_host_and_port("sipp.sf.net", &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_EQ("sipp.sf.net", host_result);
}

TEST(GetHostAndPort, DNSAndPort) {
    int port_result = -1;
    const std::string host_result = get_host_and_port("sipp.sf.net:999", &port_result);
    EXPECT_EQ(999, port_result);
    EXPECT_EQ("sipp.sf.net", host_result);
}

TEST(Wrap, BreaksAtLastSpace)
{
    EXPECT_EQ("abc def\n  ghi", wrap("abc def ghi", 2, 10));
    EXPECT_EQ("abc\n  - def ghi\n    jkl", wrap("abc\n- def ghi jkl", 2, 10));
}

TEST(Wrap, LongWord)
{
    std::string x(80, 'x');
    EXPECT_EQ(x.substr(0, 77) + "\n" + std::string(22, ' ') + "xxx", wrap(x.c_str(), 22, 77));
    EXPECT_EQ("xxxxxxxxxx\n  xxxxxxxxx\n  xxxxxx", wrap(std::string(25, 'x').c_str(), 2, 10));
}

TEST(Wrap, LongWordAfterFirstLine)
{
    std::string x9(9, 'x');
    EXPECT_EQ("a\n  " + x9 + "\n  " + x9 + "\n  xxxxxxx", wrap(("a " + std::string(25, 'x')).c_str(), 2, 10));
}

#endif //GTEST
