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
 *  Author : Walter Doekes - 24 Sep 2014
 */

/* This is a separate file because xp_parser.c is a C file, and GTEST
 * only works with C++ files. */

#include "xp_parser.h"

#ifdef GTEST
#include "gtest/gtest.h"

TEST(xp_parser, set_xml_buffer_from_string__good) {
    int res;
    int i;
    const char *buffers[] = {
        ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
         "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\r\n"
         "<!-- quick comment.. -->\r\n"
         "<scenario name=\"Some Scenario\">\r\n"
         "  <send retrans=\"500\"/>\r\n"
         "</scenario>\r\n"), // 1
        ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
         "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">"
         "<!-- quick comment.. -->"
         "<scenario name=\"Some Scenario\">"
         "  <send retrans=\"500\"/>"
         "</scenario>"), // 2
        ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
         "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">"
         "<scenario name=\"Some Scenario\">"
         "  <send retrans=\"500\"/>"
         "</scenario>"), // 3
        ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
         "<scenario name=\"Some Scenario\">"
         "  <send retrans=\"500\"/>"
         "</scenario>"), // 4
        NULL
    };

    for (i = 0; buffers[i]; ++i) {
        const char *elem, *prop;

        res = xp_set_xml_buffer_from_string(buffers[i]);
        EXPECT_EQ(i + 1, res * (i + 1));  // res == 1
        if (!res)
            continue;

        elem = xp_open_element(0);
        EXPECT_STREQ("scenario", elem);

        prop = xp_get_value("name");
        EXPECT_STREQ("Some Scenario", prop);
    }
}

TEST(xp_parser, set_xml_buffer_from_string__bad) {
    int res;
    int i;
    const char *buffers[] = {
        // No <?xml
        ("<!DOCTYPE scenario SYSTEM \"sipp.dtd\">"
         "<!-- quick comment.. -->"
         "<scenario name=\"Some Scenario\">"
         "  <send retrans=\"500\"/>"
         "</scenario>"), // -1
        // Missing ?>
        ("<?xml version=\"1.0\" encoding=\"UTF-8\""
         "<!DOCTYPE scenario SYSTEM \"sipp.dtd\">"
         "<scenario name=\"Some Scenario\">"
         "  <send retrans=\"500\"/>"
         "</scenario>"), // -2
        // Not even a DOCTYPE.
        ("<scenario name=\"Some Scenario\">"
         "  <send retrans=\"500\"/>"
         "</scenario>"), // -3
        NULL
    };

    for (i = 0; buffers[i]; ++i) {
        const char *elem, *prop;

        res = xp_set_xml_buffer_from_string(buffers[i]);
        EXPECT_EQ(-1 - i, (res - 1) * (i + 1)); // res == 0
        if (!res)
            continue;

        elem = xp_open_element(0);
        EXPECT_STREQ("scenario", elem);

        prop = xp_get_value("name");
        EXPECT_STREQ("Some Scenario", prop);
    }
}

TEST(xp_unescape, empty) {
    char buffer[] = "";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("", dst);
}

TEST(xp_unescape, noop) {
    char buffer[] = "<xml>no escape sequences</xml>";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("<xml>no escape sequences</xml>", dst);
}

TEST(xp_unescape, begin_and_end) {
    char buffer[] = "&lt;xml>this &amp;&amp; that</xml&gt;";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("<xml>this && that</xml>", dst);
}

TEST(xp_unescape, single_double_quote) {
    char buffer[] = "&quot;";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("\"", dst);
}

TEST(xp_unescape, escaped_escape) {
    char buffer[] = "&amp;amp;";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("&amp;", dst);
}

TEST(xp_unescape, unclosed_escape) {
    char buffer[] = "&lt; &amp &amp";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("< &amp &amp", dst);
}

TEST(xp_unescape, late_closed_escape) {
    char buffer[] = "&lt; &amp &amp; &gt;";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("< &amp & >", dst);
}

TEST(xp_unescape, unknown_escape) {
    char buffer[] = "&lt;&garbage;&gt;";
    char dst[sizeof(buffer)];
    xp_unescape(buffer, dst);
    EXPECT_STREQ("<&garbage;>", dst);
}

#endif //GTEST
