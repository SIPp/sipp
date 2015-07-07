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

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string.h>

namespace testing {
    std::string FLAGS_gmock_verbose = "verbose";
}

int main(int argc, char* argv[])
{
    globalVariables = new AllocVariableTable(NULL);
    userVariables = new AllocVariableTable(globalVariables);
    main_scenario = new scenario(0, 0);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

/* Quickfix to fix unittests that depend on sipp_exit availability,
 * now that sipp_exit has been moved into sipp.cpp which is not
 * included. */
void sipp_exit(int rc)
{
    exit(rc);
}
