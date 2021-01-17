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
#ifndef __SSLSOCKET__
#define __SSLSOCKET__

#if defined(USE_OPENSSL)
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#elif defined(USE_WOLFSSL)
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/rand.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509v3.h>
#endif

/* Initialises an SSL context and makes the lib thread safe */

int TLS_init();

enum tls_init_status {
    TLS_INIT_NORMAL, /* 0   Normal completion    */
    TLS_INIT_ERROR   /* 1   Unspecified error    */
};

enum tls_init_status TLS_init_context(void);

/* Helpers for OpenSSL */

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
SSL* SSL_new_client();
SSL* SSL_new_server();
const char *SSL_error_string(int ssl_error, int orig_ret);
#endif

#endif
