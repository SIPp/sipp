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

#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

    char * comp_load();

#ifndef COMP_MAIN
    extern
#endif
    int (*comp_compress) (void         ** state,
                          char          * msg,
                          unsigned int  * msg_len);

#ifndef COMP_MAIN
    extern
#endif
    int (*comp_uncompress) (void            ** state,
                            char             * msg,
                            unsigned int     * msg_len);

#ifndef COMP_MAIN
    extern
#endif

    void (*comp_free) (void ** state);

#ifndef COMP_MAIN
    extern
#endif
    char comp_error[255];

#ifdef __hpux
#define COMP_PLUGGIN "sippcomp.sl"
#else
#define COMP_PLUGGIN "sippcomp.so"
#endif

#define COMP_OK       0
#define COMP_DISCARD  1
#define COMP_REPLY    2

#define COMP_KO      -1

#ifdef __cplusplus
}
#endif

