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
extern "C" {
#endif
  int ERROR(const char *fmt, ...);
  int WARNING(const char *fmt, ...);
  int ERROR_NO(const char *fmt, ...);
  int WARNING_NO(const char *fmt, ...);
#ifdef __cplusplus
}
#endif

#define EXIT_TEST_OK               0
#define EXIT_TEST_FAILED           1
#define EXIT_TEST_RES_INTERNAL     97
#define EXIT_TEST_RES_UNKNOWN      98
#define EXIT_OTHER                 99
#define EXIT_FATAL_ERROR           -1

void screen_set_exename(char * exe_name);
void screen_init(void (*exit_handler)());
void screen_clear();
int  screen_readkey();
void screen_exit(int rc);
void screen_sigusr1(int /* not used */);

#endif // __SCREEN_H__

