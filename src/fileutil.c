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
 */

#include <defines.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char* scenario_path;

char* find_file(const char* filename)
{
    char *fullpath;
    if (filename[0] == '/' || !*scenario_path) {
        return strdup(filename);
    }

    fullpath = malloc(MAX_PATH);
    snprintf(fullpath, MAX_PATH, "%s%s", scenario_path, filename);

    if (access(fullpath, R_OK) < 0) {
        free(fullpath);
        WARNING("SIPp now prefers looking for pcap/rtpstream files next to the scenario. "
                "%s couldn't be found next to the scenario, falling back to "
                "using the current working directory", filename);
        return strdup(filename);
    }

    return fullpath;
}
