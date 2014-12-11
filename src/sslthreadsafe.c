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
 *  Author : Gundu RAO - 16 Jul 2004
 *           From Hewlett Packard Company.
 */

#define SSL_MAIN
#include "sslcommon.h"

/*
** Call back function for locking function
*/

/* extern mutex_buf; */
MUTEX_TYPE *mutex_buf = NULL;
void
locking_function(int mode, int n, const char *file, int line)
{
    (void)file; /* unused, avoid warnings */
    (void)line; /* unused, avoid warnings */

    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(mutex_buf[n]);
    else
        MUTEX_UNLOCK(mutex_buf[n]);
}

/*
** Call back id_function
*/

unsigned long id_function(void)
{
    return ((unsigned long)THREAD_ID);
}

int
Thread_setup(void)
{
    int i;
    mutex_buf = (MUTEX_TYPE *)malloc(sizeof(MUTEX_TYPE) * CRYPTO_num_locks());

    if(!mutex_buf)
        return 0;
    for ( i = 0 ; i < CRYPTO_num_locks() ; i++)
        MUTEX_SETUP(mutex_buf[i]);
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    /*
    **  Dynamic locking routine registration
    **/
#ifdef _DYNAMIC_LOCKING_MECHANISM_

    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
#endif
    return 1;

}

/*
** Thread clean up function - After closing open ssl - we need to call this once
*/

int
Thread_cleanup(void)
{
    int i;

    if (!mutex_buf)
        return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

#ifdef _DYNAMIC_LOCKING_MECHANISM_

    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
#endif
    for (i=0 ; i < CRYPTO_num_locks(); i++)
        MUTEX_CLEANUP(mutex_buf[i]);

    mutex_buf = NULL ;
    return 1;
}

#ifdef   _DYNAMIC_LOCKING_MECHANISM_

struct CRYPTO_dynlock_value *
CRYPTO_dynlock_value(const char *file,int line) {
    struct CRYPTO_dynlock_value *value;

    value = (CRYPTO_dynlock_value  *)malloc(sizeof(struct CRYPTO_dynlock_value));

    if(!value)
        return NULL;

    MUTEX_SETUP(value -> mutex);
    return value;
}

void
dyn_lock_function( int mode , struct CRYPTO_dynlock_value *val,\
                   const char *file , int line )
{
    if (mode &CRYPTO_LOCK)

        MUTEX_LOCK(val -> mutex);
    else
        MUTEX_UNLOCK(val -> mutex);
}

void
dyn_destroy_function( struct CRYPTO_dynlock_value *val,\
                      const char *file , int line )
{
    MUTEX_CLEANUP(val -> mutex);
}

#endif
