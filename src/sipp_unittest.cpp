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
 *	     Michael Hirschbichler
 */

#define GLOBALS_FULL_DEFINITION
#define NOTLAST 0

#include <dlfcn.h>
#include "sipp.hpp"
#include "assert.h"

int main()
{
    /* Unit testing function */
    char ipv6_addr_brackets[] = "[fe80::92a4:deff:fe74:7af5]";
    char ipv6_addr_port[] = "[fe80::92a4:deff:fe74:7af5]:999";
    char ipv6_addr[] = "fe80::92a4:deff:fe74:7af5";
    char ipv4_addr_port[] = "127.0.0.1:999";
    char ipv4_addr[] = "127.0.0.1";
    char hostname_port[] = "sipp.sf.net:999";
    char hostname[] = "sipp.sf.net";
    int port_result = -1;
    char host_result[255];
    char orig_addr[255];

#define TEST_GET_HOST_AND_PORT(VAR, EXPECTED_HOST, EXPECTED_PORT) {\
    strcpy(host_result,""); \
    strcpy(orig_addr,VAR); \
    get_host_and_port(VAR, host_result, &port_result); \
    if ((strcmp(host_result, EXPECTED_HOST) != 0) || (port_result != EXPECTED_PORT)) \
    {fprintf(stderr, "get_host_and_port fails for address %s - results are %s and %d, expected %s and %d\n", orig_addr, host_result, port_result, EXPECTED_HOST, EXPECTED_PORT);};\
}

    TEST_GET_HOST_AND_PORT(ipv6_addr, "fe80::92a4:deff:fe74:7af5", 0)
    TEST_GET_HOST_AND_PORT(ipv6_addr_brackets, "fe80::92a4:deff:fe74:7af5", 0)
    TEST_GET_HOST_AND_PORT(ipv6_addr_port, "fe80::92a4:deff:fe74:7af5", 999)
    TEST_GET_HOST_AND_PORT(ipv4_addr, "127.0.0.1", 0)
    TEST_GET_HOST_AND_PORT(ipv4_addr_port, "127.0.0.1", 999)
    TEST_GET_HOST_AND_PORT(hostname, "sipp.sf.net", 0)
    TEST_GET_HOST_AND_PORT(hostname_port, "sipp.sf.net", 999)

    return 0;
}
