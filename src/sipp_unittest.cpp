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

#include "multi_instance.hpp"

#include "gtest/gtest.h"
#include <string.h>

int main(int argc, char* argv[])
{
    globalVariables = new AllocVariableTable(nullptr);
    userVariables = new AllocVariableTable(globalVariables);
    main_scenario = new scenario(0, 0);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

/* Quickfix to fix unittests that depend on sipp_exit availability,
 * now that sipp_exit has been moved into sipp.cpp which is not
 * included. */
void sipp_exit(int rc, int rtp_errors, int echo_errors)
{
    exit(rc);
}

TEST(MultiInstanceConfig, ParsesQuotedCsvAndExpandsInstanceArguments)
{
    const std::string csv =
        "role,count,args\n"
        "uas,2,\"-sn uas -p {port}\"\n"
        "uac,2,\"-sn uac 127.0.0.1:{instance_port} -key role {role} -key idx {instance}\"\n";

    std::string error;
    std::vector<MultiInstanceSpec> specs;

    ASSERT_TRUE(parse_multi_instance_csv(csv, "inline.csv", &specs, &error)) << error;
    ASSERT_EQ(2u, specs.size());
    EXPECT_EQ("uas", specs[0].role);
    EXPECT_EQ(2, specs[0].count);
    EXPECT_EQ("-sn uas -p {port}", specs[0].args);
    EXPECT_EQ("uac", specs[1].role);
    EXPECT_EQ(2, specs[1].count);

    std::vector<MultiInstanceCommand> commands =
        build_multi_instance_commands("./sipp", specs, 5060);

    ASSERT_EQ(4u, commands.size());
    EXPECT_EQ(std::vector<std::string>({"./sipp", "-sn", "uas", "-p", "5060"}), commands[0].argv);
    EXPECT_EQ(std::vector<std::string>({"./sipp", "-sn", "uas", "-p", "5061"}), commands[1].argv);
    EXPECT_EQ(std::vector<std::string>({"./sipp", "-sn", "uac", "127.0.0.1:5060", "-key", "role", "uac", "-key", "idx", "0"}), commands[2].argv);
    EXPECT_EQ(std::vector<std::string>({"./sipp", "-sn", "uac", "127.0.0.1:5061", "-key", "role", "uac", "-key", "idx", "1"}), commands[3].argv);
}

TEST(MultiInstanceConfig, ReportsInvalidCsvRows)
{
    const std::string csv =
        "role,count,args\n"
        "uas,0,\"-sn uas\"\n";

    std::string error;
    std::vector<MultiInstanceSpec> specs;

    EXPECT_FALSE(parse_multi_instance_csv(csv, "bad.csv", &specs, &error));
    EXPECT_NE(std::string::npos, error.find("count must be greater than zero"));
}
