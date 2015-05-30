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

void get_host_and_port(const char * addr, char * host, int * port)
{
    /* Separate the port number (if any) from the host name.
     * Thing is, the separator is a colon (':').  The colon may also exist
     * in the host portion if the host is specified as an IPv6 address (see
     * RFC 2732).  If that's the case, then we need to skip past the IPv6
     * address, which should be contained within square brackets ('[',']').
     */
    const char *has_brackets;
    int len;
    int port_result = 0;

    has_brackets = strchr(addr, '[');
    if (has_brackets != NULL) {
        has_brackets = strchr(has_brackets, ']');
    }
    if (has_brackets == NULL) {
        /* addr is not a []-enclosed IPv6 address, but might still be IPv6 (without
         * a port), or IPv4 or a hostname (with or without a port) */
        char *first_colon_location;
        char *second_colon_location;

        len = strlen(addr) + 1;
        memmove(host, addr, len);

        first_colon_location = strchr(host, ':');
        if (first_colon_location == NULL) {
            /* No colon - just set the port to 0 */
            port_result = 0;
        } else {
            second_colon_location = strchr(first_colon_location + 1, ':');
            if (second_colon_location != NULL) {
                /* Found a second colon in addr - so this is an IPv6 address
                 * without a port. Set the port to 0 */
                port_result = 0;
            } else {
                /* IPv4 address or hostname with a colon in it - convert the colon to
                 * a NUL terminator, and set the value after it as the port */
                *first_colon_location = '\0';
                port_result = atol(first_colon_location + 1);
            }
        }

    } else {                                      /* If '['..']' found,       */
        const char *initial_bracket;                /* extract the remote_host  */
        char *second_bracket;
        char *colon_before_port;

        initial_bracket = strchr( addr, '[' );
        initial_bracket++; /* Step forward one character */
        len = strlen(initial_bracket) + 1;
        memmove(host, initial_bracket, len);

        second_bracket = strchr( host, ']' );
        *second_bracket = '\0';

        /* Check for a port specified after the ] */
        colon_before_port = strchr(second_bracket + 1, ':');
        if (colon_before_port != NULL) {
            port_result = atol(colon_before_port + 1);
        } else {
            port_result = 0;
        }
    }

    // Set the port argument if it wasn't NULL
    if (port != NULL) {
        *port = port_result;
    }
}

static unsigned char tolower_table[256];

void init_tolower_table()
{
    for (int i = 0; i < 256; i++) {
        tolower_table[i] = tolower(i);
    }
}

/* This is simpler than doing a regular tolower, because there are no branches.
 * We also inline it, so that we don't have function call overheads.
 *
 * An alternative to a table would be to do (c | 0x20), but that only works if
 * we are sure that we are searching for characters (or don't care if they are
 * not characters. */
unsigned char inline mytolower(unsigned char c)
{
    return tolower_table[c];
}

char * strcasestr2(char *s, const char *find)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != 0) {
        c = mytolower((unsigned char)c);
        len = strlen(find);
        do {
            do {
                if ((sc = *s++) == 0)
                    return (NULL);
            } while ((char)mytolower((unsigned char)sc) != c);
        } while (strncasecmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

char * strncasestr(char *s, const char *find, size_t n)
{
    char *end = s + n;
    char c, sc;
    size_t len;

    if ((c = *find++) != 0) {
        c = mytolower((unsigned char)c);
        len = strlen(find);
        end -= (len - 1);
        do {
            do {
                if ((sc = *s++) == 0)
                    return (NULL);
                if (s >= end)
                    return (NULL);
            } while ((char)mytolower((unsigned char)sc) != c);
        } while (strncasecmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

int get_decimal_from_hex(char hex)
{
    if (isdigit(hex))
        return hex - '0';
    else
        return tolower(hex) - 'a' + 10;
}

void trim(char *s)
{
    char *p = s;
    while(isspace(*p)) {
        p++;
    }
    int l = strlen(p);
    for (int i = l - 1; i >= 0 && isspace(p[i]); i--) {
        p[i] = '\0';
    }
    memmove(s, p, l + 1);
}


#ifdef GTEST
#include "gtest/gtest.h"

TEST(GetHostAndPort, IPv6) {
    int port_result = -1;
    char host_result[255];
    get_host_and_port("fe80::92a4:deff:fe74:7af5", host_result, &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_STREQ("fe80::92a4:deff:fe74:7af5", host_result);
}

TEST(GetHostAndPort, IPv6Brackets) {
    int port_result = -1;
    char host_result[255];
    get_host_and_port("[fe80::92a4:deff:fe74:7af5]", host_result, &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_STREQ("fe80::92a4:deff:fe74:7af5", host_result);
}

TEST(GetHostAndPort, IPv6BracketsAndPort) {
    int port_result = -1;
    char host_result[255];
    get_host_and_port("[fe80::92a4:deff:fe74:7af5]:999", host_result, &port_result);
    EXPECT_EQ(999, port_result);
    EXPECT_STREQ("fe80::92a4:deff:fe74:7af5", host_result);
}

TEST(GetHostAndPort, IPv4) {
    int port_result = -1;
    char host_result[255];
    get_host_and_port("127.0.0.1", host_result, &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_STREQ("127.0.0.1", host_result);
}

TEST(GetHostAndPort, IPv4AndPort) {
    int port_result = -1;
    char host_result[255];
    get_host_and_port("127.0.0.1:999", host_result, &port_result);
    EXPECT_EQ(999, port_result);
    EXPECT_STREQ("127.0.0.1", host_result);
}

TEST(GetHostAndPort, IgnorePort) {
    char host_result[255];
    get_host_and_port("127.0.0.1", host_result, NULL);
    EXPECT_STREQ("127.0.0.1", host_result);
}

TEST(GetHostAndPort, DNS) {
    int port_result = -1;
    char host_result[255];
    get_host_and_port("sipp.sf.net", host_result, &port_result);
    EXPECT_EQ(0, port_result);
    EXPECT_STREQ("sipp.sf.net", host_result);
}

TEST(GetHostAndPort, DNSAndPort) {
    int port_result = -1;
    char host_result[255];
    get_host_and_port("sipp.sf.net:999", host_result, &port_result);
    EXPECT_EQ(999, port_result);
    EXPECT_STREQ("sipp.sf.net", host_result);
}

#endif //GTEST
