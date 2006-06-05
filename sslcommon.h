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
#ifndef _ccnv_2_common_h_H
#define _ccnv_2_common_h_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>

#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self( )

/*
**      Define a global variable for the SSL context
*/

/* Initialises an SSL context and makes the lib thread safe */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SSL_MAIN
  extern
#endif
  int init_OpenSSL(void);

#ifndef SSL_MAIN
  extern
#endif
  int Thread_setup(void);

#ifndef SSL_MAIN
  extern
#endif
  SSL_CTX *setup_ssl_context(SSL_METHOD *);

#ifndef SSL_MAIN
  extern
#endif
  int SSL_ERROR(void);

#ifndef SSL_MAIN
//  extern
#endif
//    int createAuthHeader(char * user, char * password, char * method, char * uri, char * msgbody, char * auth, char * result);

#ifdef __cplusplus
}
#endif

#endif
