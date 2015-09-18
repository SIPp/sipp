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
 */
#ifndef __DEFINES_H__
#define __DEFINES_H__

#ifdef __cplusplus
extern "C" {
#endif
    void ERROR(const char *fmt, ...) __attribute__ ((format(printf, 1, 2), noreturn));
    void WARNING(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
    void ERROR_NO(const char *fmt, ...) __attribute__ ((format(printf, 1, 2), noreturn));
    void WARNING_NO(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#ifdef __cplusplus
}
#endif

#define MAX_PATH                   250

#define EXIT_TEST_OK               0
#define EXIT_TEST_FAILED           1
#define EXIT_TEST_RES_INTERNAL     97
#define EXIT_TEST_RES_UNKNOWN      98
#define EXIT_OTHER                 99
#define EXIT_FATAL_ERROR           -1
#define EXIT_BIND_ERROR            -2

#endif /* __DEFINES_H__ */
