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
 *  Author : Jérôme Poulin - 20 Apr 2021
 */

#include <cctype>
#include <string>
#include <cstring>

std::string url_encode(const std::string &str) {
    std::string new_str;
    unsigned char c;
    int ic;
    const char *chars = str.c_str();
    char bufHex[10];
    size_t len = strlen(chars);

    for (unsigned int i = 0; i < len; i++) {
        c = chars[i];
        ic = c;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            new_str += c;
        } else {
            sprintf(bufHex, "%X", c);
            if (ic < 16) {
                new_str += "%0";
            } else {
                new_str += "%";
            }
            new_str += bufHex;
        }
    }
    return new_str;
}

std::string url_decode(std::string str) {
    std::string ret;
    char ch;
    size_t len = str.length();

    for (unsigned int i = 0; i < len; i++) {
        unsigned int ii;
        if (str[i] != '%') {
            if (str[i] == '+') {
                ret += ' ';
            } else {
                ret += str[i];
            }
        } else {
            sscanf(str.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i = i + 2;
        }
    }
    return ret;
}

#ifdef GTEST
#include "gtest/gtest.h"

TEST(url_encode, encoded_string_contains_entities_if_needed) {
    ASSERT_EQ(url_encode("user1@127.0.0.1:5060"), "user1%40127.0.0.1%3A5060");
    ASSERT_EQ(url_encode("string with spaces"), "string%20with%20spaces");
    ASSERT_EQ(url_encode("alphanum123"), "alphanum123");
    ASSERT_EQ(url_encode("ûtf8"), "%C3%BBtf8");
}

TEST(url_decode, decoded_string_contains_no_entities) {
    ASSERT_EQ(url_decode("user1%40127%2E0%2e0%2e1%3a5060"), "user1@127.0.0.1:5060");
    ASSERT_EQ(url_decode("string%20with%20spaces"), "string with spaces");
    ASSERT_EQ(url_decode("%C3%bbtf8"), "ûtf8");
}

#endif // GTEST
