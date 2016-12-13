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
 *           Olivier Jacques
 *           From Hewlett Packard Company.
 *           Charles P Wright from IBM Research
 */
#include "sipp.hpp"

/* This is a fun sample of creating your own extensible keyword. */
int fortune(call *call, MessageComponent *comp, char *buf, int len)
{
    int pipes[2];
    char localbuf[SIPP_MAX_MSG_SIZE];
    char *p = localbuf;
    int ret;
    int written = 0;

    if (pipe(pipes) == -1) {
        ERROR("Could not create pipes!\n");
    }

    switch (fork()) {
    case -1:
        ERROR("Fork failed: %s\n", strerror(errno));
    case 0:
        /* We are the child. */
        close(pipes[0]);
        dup2(pipes[1], fileno(stdout));
        dup2(pipes[1], fileno(stderr));
        close(fileno(stdin));
        system("/usr/bin/fortune");
        exit (127);
    default:
        /* We are the parent*/
        close(pipes[1]);
        while ((ret = read(pipes[0], p, sizeof(localbuf) - (p - localbuf))) > 0) {
            p += ret;
        }
        *p = '\0';
        close(pipes[0]);

        if (len > p - localbuf) {
            len = p -localbuf;
        }

        p = localbuf;
        while(len-- > 0) {
            if (*p == '\n') {
                if (len < 3) {
                    break;
                }
                *buf++ = '\r';
                *buf++ = '\n';
                *buf++ = ' ';
                written += 3;
                p++;
            } else {
                *buf++ = *p++;
                written++;
            }
        }
        break;
    }

    return written;
}

/* On initialization we register our keywords. */
extern "C" int init(void)
{
    registerKeyword("fortune", fortune);
    return 0;
}
