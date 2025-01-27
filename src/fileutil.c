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
#include <errno.h>
#include <pwd.h>                /* for getpwnam_r() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int expand_user_path(const char* path, char* expanded_home_path /*The buffer*/, size_t buflen)
{
    if (path[0] != '~') {                       /* We have nothing to expand here */
        return 1;
    }

    memset(expanded_home_path, '\0', buflen);
    char* home_dir = NULL;

    if (path[1] == '\0' || path[1] == '/') {                                                    /* '~/path' case */
        home_dir = getenv("HOME");
        if (home_dir == NULL) {
            home_dir = getenv("USERPROFILE");
        } else {
            snprintf(expanded_home_path, buflen - 1, "%s%s", home_dir, path + 1);
        }
    } else {
        const char* first_slash = strchr(path, '/');                                            /* substring starting from '/' */
        const size_t linux_username_limit = 32;                                                 /* As of now */
        char* username = NULL;
        if ((first_slash != NULL) && ((first_slash - (path + 1)) <= linux_username_limit)) {    /* '~someuser/blah' case */
            username = strndup(path + 1, first_slash - (path + 1));
        } else {                                                                                /* '~someuser' case, there is no file, just username */
            return -1;
        }

        struct passwd pwd;
        struct passwd* result;
        const size_t bufsize  = sysconf(_SC_GETPW_R_SIZE_MAX) +1;
        char* buffer = malloc(bufsize * sizeof(char));
        int retcode = getpwnam_r(username, &pwd, buffer, bufsize - 1, &result);
        free(username);
        free(buffer);
        if (result == NULL) {
            if (retcode != 0) {
                errno = retcode;
            }
            WARNING_NO("Unable to resolve home path for [%s]\n", path);
            return -1;
        } else {
            home_dir = result->pw_dir;
        }

        if (home_dir != NULL) {
            if (first_slash != NULL) {                                                      /* '~username/path' case */
                snprintf(expanded_home_path, buflen - 1, "%s%s", home_dir, first_slash);
            } else {                                                                        /* '~username' case should be eliminated above, but just in case it is modified in future*/
                return -1;
            }
        }
    }

    return 1;
}

char* find_file(const char* filename, const char *basepath)
{
    char tmppath[MAX_PATH];
    tmppath[0] = '\0';
    const char* filepathptr = tmppath;
    if ((expand_user_path(filename, tmppath, sizeof(tmppath)) == -1) || (tmppath[0] == '\0')) {     /* we couldn't expand path, or buffer is still empty */
        filepathptr = filename;
    }

    if (filepathptr[0] == '/' || !*basepath) {
        return strdup(filepathptr);
    }

    size_t len = strlen(basepath) + strlen(filepathptr) + 1;
    char* fullpath = malloc(len);
    snprintf(fullpath, len, "%s%s", basepath, filepathptr);

    if (access(fullpath, R_OK) < 0) {
        free(fullpath);
        WARNING("SIPp now prefers looking for pcap/rtpstream files next to the scenario. "
                "%s couldn't be found next to the scenario, falling back to "
                "using the current working directory", filepathptr);
        return strdup(filepathptr);
    }

    return fullpath;
}
