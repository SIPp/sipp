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
 *
 */

#define COMP_MAIN
#include "comp.h"

#include <dlfcn.h>
#include <string.h>

char * comp_load()
{
    void *handle;
    char *error;

    comp_error[0] = 0;

    handle = dlopen(COMP_PLUGGIN, RTLD_LAZY);
    if (!handle) {
        strcpy(comp_error, dlerror());
        return comp_error;
    }

    *(void **)(&comp_compress) = dlsym(handle, "comp_compress");
    if((error = (char *) dlerror())) {
        strcpy(comp_error, error);
        return comp_error;
    }

    *(void **)(&comp_uncompress) = dlsym(handle, "comp_uncompress");
    if((error = (char *) dlerror())) {
        strcpy(comp_error, error);
        return comp_error;
    }

    *(void **)(&comp_free) = dlsym(handle, "comp_free");
    if((error = (char *) dlerror())) {
        strcpy(comp_error, error);
        return comp_error;
    }

    return 0;
}
