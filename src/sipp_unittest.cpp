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

#include "sipp.hpp"
#include "auth.hpp"
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

TEST(DigestAuth, nonce) {
    char nonce[40];
    getAuthParameter("nonce", " Authorization: Digest cnonce=\"c7e1249f\",nonce=\"a6ca2bf13de1433183f7c48781bd9304\"", nonce, sizeof(nonce));
    EXPECT_STREQ("a6ca2bf13de1433183f7c48781bd9304", nonce);
    getAuthParameter("nonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\", cnonce=\"c7e1249f\"", nonce, sizeof(nonce));
    EXPECT_STREQ("a6ca2bf13de1433183f7c48781bd9304", nonce);
}

TEST(DigestAuth, cnonce) {
    char cnonce[10];
    getAuthParameter("cnonce", " Authorization: Digest cnonce=\"c7e1249f\",nonce=\"a6ca2bf13de1433183f7c48781bd9304\"", cnonce, sizeof(cnonce));
    EXPECT_STREQ("c7e1249f", cnonce);
    getAuthParameter("cnonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\", cnonce=\"c7e1249f\"", cnonce, sizeof(cnonce));
    EXPECT_STREQ("c7e1249f", cnonce);
}

TEST(DigestAuth, MissingParameter) {
    char cnonce[10];
    getAuthParameter("cnonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\"", cnonce, sizeof(cnonce));
    EXPECT_EQ('\0', cnonce[0]);
}

TEST(DigestAuth, BasicVerification) {
    char* header = strdup(("Digest \r\n"
                           " realm=\"testrealm@host.com\",\r\n"
                           " nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n,"
                           " opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    char result[255];
    createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "hello world", header, NULL, NULL, NULL, result);
    EXPECT_STREQ("Digest username=\"testuser\",realm=\"testrealm@host.com\",uri=\"sip:sip:example.com\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",response=\"db94e01e92f2b09a52a234eeca8b90f7\",algorithm=MD5,opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"", result);
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
    free(header);
}

TEST(DigestAuth, qop) {
    char result[1024];
    char* header = strdup(("Digest \r\n"
                           "\trealm=\"testrealm@host.com\",\r\n"
                           "\tqop=\"auth,auth-int\",\r\n"
                           "\tnonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n,"
                           "\topaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    createAuthHeader("testuser",
                     "secret",
                     "REGISTER",
                     "sip:example.com",
                     "hello world",
                     header,
                     NULL,
                     NULL,
                     NULL,
                     result);
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
    free(header); 
}
