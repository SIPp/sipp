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
 *  Copyright (C) 2003 - The Authors
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 */

/****
 * Screen.hpp : Simple curses & logfile encapsulation 
 */

#ifndef __SCREEN_H__
#define __SCREEN_H__

#include <stdio.h>

#ifdef __cplusplus
extern "C"
#endif
void _screen_error(char *s, int fatal);

extern char _screen_err[32768];

#define OUTPUT_P3(s, p1, p2, p3, fatal) {     \
  sprintf(_screen_err, s, p1, p2, p3);        \
  _screen_error((char *)_screen_err , fatal); \
}
#define OUTPUT_P2(s, p1, p2, fatal) {     \
  sprintf(_screen_err, s, p1, p2);        \
  _screen_error((char *)_screen_err , fatal); \
}
#define OUTPUT_P1(s, p1, fatal) {     \
  sprintf(_screen_err, s, p1);        \
  _screen_error((char *)_screen_err , fatal); \
}

#define ERROR_P3(s, p1, p2, p3) OUTPUT_P3(s, p1, p2, p3, 1)
#define ERROR_P2(s, p1, p2)     OUTPUT_P2(s, p1, p2, 1)
#define ERROR_P1(s, p)          OUTPUT_P1(s, p, 1)
#define ERROR(s)                ERROR_P1("%s", s)
#define ERROR_NO(s) \
        ERROR_P3("%s, errno = %d (%s)", s, errno, strerror(errno))

#define WARNING_P3(s, p1, p2, p3) OUTPUT_P3(s, p1, p2, p3, 0)
#define WARNING_P2(s, p1, p2)     OUTPUT_P2(s, p1, p2, 0)
#define WARNING_P1(s, p)          OUTPUT_P1(s, p, 0)
#define WARNING(s)                WARNING_P1("%s", s)
#define WARNING_NO(s) \
        WARNING_P3("%s, errno = %d (%s)", s, errno, strerror(errno))

#define EXIT_TEST_OK               0
#define EXIT_TEST_FAILED           1
#define EXIT_TEST_RES_INTERNAL     97
#define EXIT_TEST_RES_UNKNOWN      98
#define EXIT_OTHER                 99
#define EXIT_FATAL_ERROR           -1

void screen_set_exename(char * exe_name);
void screen_init(char *logfile_name, void (*exit_handler)());
void screen_clear();
int  screen_readkey();
void screen_exit(int rc);
void screen_sigusr1(int /* not used */);

#endif // __SCREEN_H__

