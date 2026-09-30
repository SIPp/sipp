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
 *  Author : Rob Day - 11 May 2014
 */

#define GLOBALS_FULL_DEFINITION
#include "sipp.hpp"

#include "fileutil.h"
#include "gtest/gtest.h"
#include <pwd.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    globalVariables = new AllocVariableTable(nullptr);
    userVariables = new AllocVariableTable(globalVariables);
    main_scenario = new scenario(0, 0);

    ::testing::InitGoogleTest(&argc, argv);
    int rc = RUN_ALL_TESTS();
    delete main_scenario;
    return rc;
}

/* Quickfix to fix unittests that depend on sipp_exit availability,
 * now that sipp_exit has been moved into sipp.cpp which is not
 * included. */
void sipp_exit(int rc, int rtp_errors, int echo_errors)
{
    exit(rc);
}

TEST(find_file, ExpandsUserHome) {
    const struct passwd* pw = getpwuid(getuid());
    if (!pw || strlen(pw->pw_name) > 32) {
        GTEST_SKIP() << "no user name of 32 characters at most";
    }
    std::string user = pw->pw_name;
    std::string home = pw->pw_dir;

    char* path = find_file(("~" + user + "/file.pcap").c_str(), "");
    EXPECT_EQ(home + "/file.pcap", path);
    free(path);
}
