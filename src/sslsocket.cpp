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

#include <stdlib.h>
#include <string.h>

#include "sipp.hpp"
#include "sslsocket.hpp"

#if (USE_OPENSSL_KL && OPENSSL_VERSION_NUMBER >= 0x10101000L)
#define HAVE_KEYLOG_CB
#define KEYLOG_ENV "SSLKEYLOGFILE"
#endif

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)

#define CALL_BACK_USER_DATA "ksgr"

static SSL_CTX* sip_trp_ssl_ctx = nullptr;  /* For SSL cserver context */
static SSL_CTX* sip_trp_ssl_ctx_client = nullptr;  /* For SSL cserver context */

#if defined(USE_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x10100000
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), nullptr)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self()

static MUTEX_TYPE *mutex_buf = nullptr;

static void locking_function(int mode, int n, const char *file, int line)
{
    (void)file; /* unused, avoid warnings */
    (void)line; /* unused, avoid warnings */

    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(mutex_buf[n]);
    else
        MUTEX_UNLOCK(mutex_buf[n]);
}

#ifndef WIN32
static unsigned long id_function()
{
    return (unsigned long)THREAD_ID;
}
#endif
#endif

static int thread_setup()
{
#if defined(USE_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x10100000
    int i;
    mutex_buf = (MUTEX_TYPE *)malloc(sizeof(MUTEX_TYPE) * CRYPTO_num_locks());

    if (!mutex_buf)
        return 0;
    for (i = 0; i < CRYPTO_num_locks(); ++i)
        MUTEX_SETUP(mutex_buf[i]);

#ifndef WIN32
    /* For openssl>=1.0 it uses the address of errno for thread id.
     * Works for us. */
    CRYPTO_set_id_callback(id_function);
#endif

    /* > All OpenSSL code has now been transferred to use the new
     * > threading API, so the old one is no longer used and can be
     * > removed. [...] There is now no longer a need to set locking
     * > callbacks!!
     * https://github.com/openssl/openssl/commit/
     * 2e52e7df518d80188c865ea3f7bb3526d14b0c08 */
    CRYPTO_set_locking_callback(locking_function);
#endif
    return 1;
}

static int passwd_call_back_routine(char *buf, int size, int /*flag*/, void *passwd)
{
    strncpy(buf, (char *)(passwd), size);
    buf[size - 1] = '\0';
    return(strlen(buf));
}

#ifdef HAVE_KEYLOG_CB
static const char *keylog_file()
{
    char *kl_env = getenv(KEYLOG_ENV);

    if (kl_env && kl_env[0]) {
        return kl_env;
    } else {
        /* No or empty keylog environment variable */
        return nullptr;
    }
}

/* Add a LF to the keylog line and return the number of bytes written or 0 if
 * writing fails.
 * see: https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
    https://github.com/tlswg/sslkeylogfile
*/
static int write_keylog_line(const char* filename, const char *line)
{
    FILE *keylog_fp = nullptr;
    char buf[256]; /* current keylog maximum line length is 195 */
    size_t line_len = strlen(line);

    if(line_len == 0 || line_len > sizeof(buf) - 2) {
        /* Empty line or too big to fit in a LF and NULL. */
        return 0;
    }
    keylog_fp = fopen(filename, "a");
    if (keylog_fp) {
        memcpy(buf, line, line_len);
        if(line[line_len - 1] != '\n') {
            buf[line_len++] = '\n';
        }
        buf[line_len] = '\0';
        fputs(buf, keylog_fp);
        fclose(keylog_fp);
    }
    return line_len-1;
}

static void sip_tls_keylog_callback(const SSL *ssl, const char *line)
{
    const char *keylog_file_name = keylog_file();

    if (line && keylog_file_name) {
        write_keylog_line(keylog_file_name, line);
    }
}
#endif // HAVE_KEYLOG_CB

/****** SSL error handling *************/
const char *SSL_error_string(int ssl_error, int orig_ret)
{
    switch (ssl_error) {
    case SSL_ERROR_NONE:
        return "No error";
    case SSL_ERROR_ZERO_RETURN:
        return "SSL connection has been closed. SSL returned: SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_WRITE:
        return "SSL I/O function returned SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_READ:
        return "SSL I/O function returned SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_CONNECT:
        return "SSL I/O function returned SSL_ERROR_WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
        return "SSL I/O function returned SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_X509_LOOKUP:
        return "SSL I/O function returned SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_SSL:
        return "SSL protocol error. SSL I/O function returned SSL_ERROR_SSL";
    case SSL_ERROR_SYSCALL:
        if (orig_ret < 0) { /* not EOF */
            return strerror(errno);
        } else { /* EOF */
            return "Non-recoverable I/O error occurred. SSL I/O function returned SSL_ERROR_SYSCALL";
        }
    }
    return "Unknown SSL Error.";
}

SSL* SSL_new_client()
{
    SSL* ssl = SSL_new(sip_trp_ssl_ctx_client);

    // Inject the ServerNameIndication (SNI).
    // It requires to be a hostname. However, SSL takes whatever we set.
    // Ref https://datatracker.ietf.org/doc/html/rfc6066#section-3
    if (strcmp(remote_ip, remote_host)) {
        SSL_set_tlsext_host_name(ssl, remote_host);
    }

    return ssl;
}

SSL* SSL_new_server()
{
    return SSL_new(sip_trp_ssl_ctx);
}

/****** Certificate Verification Callback FACILITY *************/
static int sip_tls_verify_callback(int ok , X509_STORE_CTX *store)
{
    char data[512];
    int  err, depth;
    X509 *cert;

    if (!ok) {
        cert = X509_STORE_CTX_get_current_cert(store);
        err = X509_STORE_CTX_get_error(store);
        depth = X509_STORE_CTX_get_error_depth(store);

        X509_NAME_oneline(X509_get_issuer_name(cert),
                          data, 512);
        WARNING("TLS verification error for issuer: '%s'\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert),
                          data, 512);
        WARNING("TLS verification error for subject: '%s'\n", data);
        WARNING("verify error:num=%d:%s:depth=%d\n", err,
                X509_verify_cert_error_string(err), depth);
    }
    return ok;
}

/***********  Load the CRL's into SSL_CTX **********************/
static int sip_tls_load_crls(SSL_CTX* ctx , const char* crlfile)
{
    X509_STORE          *store;
    X509_LOOKUP         *lookup;

    /*  Get the X509_STORE from SSL context */
    if (!(store = SSL_CTX_get_cert_store(ctx))) {
        return (-1);
    }

    /* Add lookup file to X509_STORE */
    if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))) {
        return (-1);
    }

    /* Add the CRLS to the lookpup object */
#if defined(USE_WOLFSSL)
    if (X509_LOOKUP_load_file(lookup, crlfile, X509_FILETYPE_PEM) != 1) {
#else
    if (X509_load_crl_file(lookup, crlfile, X509_FILETYPE_PEM) != 1) {
#endif
        return (-1);
    }

    /* Set the flags of the store so that CRLS's are consulted */
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#else
#warning This version of OpenSSL (<0.9.7) cannot handle CRL files in capath
    ERROR("This version of OpenSSL (<0.9.7) cannot handle CRL files in capath");
#endif

    return (1);
}

static SSL_CTX* instantiate_ssl_context(const char* context_name)
{
    SSL_CTX* ssl_ctx = nullptr;

#if OPENSSL_VERSION_NUMBER >= 0x10100000  /* >= 1.1 */

    int min_tls_version, max_tls_version;

    if (tls_version == 0.0) {
#if !defined(USE_WOLFSSL) || defined(WOLFSSL_ALLOW_TLSV10)
        min_tls_version = TLS1_VERSION;
#else
        min_tls_version = TLS1_1_VERSION;
#endif
        max_tls_version = TLS_MAX_VERSION;
    } else if (tls_version == 1.0) {
#if !defined(USE_WOLFSSL) || defined(WOLFSSL_ALLOW_TLSV10)
        max_tls_version = min_tls_version = TLS1_VERSION;
#else
        ERROR("Old TLS version 1.0 is no longer supported for [%s] context.", context_name);
        return nullptr;
#endif
    } else if (tls_version == 1.1) {
        max_tls_version = min_tls_version = TLS1_1_VERSION;
    } else if (tls_version == 1.2) {
        max_tls_version = min_tls_version = TLS1_2_VERSION;
    } else if (tls_version == 1.3) {
        max_tls_version = min_tls_version = TLS1_3_VERSION;
    } else {
        ERROR("Unrecognized TLS version for [%s] context: %1.1f", context_name, tls_version);
        return nullptr;
    }

    if (!strncmp(context_name, "client", 6)) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
    } else {
        ssl_ctx = SSL_CTX_new(TLS_server_method());
    }

    SSL_CTX_set_min_proto_version(ssl_ctx, min_tls_version);

    if (max_tls_version != TLS_MAX_VERSION) {
        SSL_CTX_set_max_proto_version(ssl_ctx, max_tls_version);
    }

#else  /* OPENSSL_VERSION < 1.1 */

    if (tls_version == 0.0) {
        if (!strncmp(context_name, "client", 6)) {
            ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        } else {
            ssl_ctx = SSL_CTX_new(SSLv23_server_method());
        }
    } else if (tls_version == 1.0) {
#if !defined(USE_WOLFSSL) || defined(WOLFSSL_ALLOW_TLSV10)
        if (!strncmp(context_name, "client", 6)) {
            ssl_ctx = SSL_CTX_new(TLSv1_client_method());
        } else {
            ssl_ctx = SSL_CTX_new(TLSv1_server_method());
        }
#else
        ERROR("Old TLS version 1.0 is no longer supported for [%s] context.", context_name);
        ssl_ctx = nullptr;
#endif
    } else if (tls_version == 1.1) {
#if !defined(USE_WOLFSSL) || !defined(NO_OLD_TLS)
        if (!strncmp(context_name, "client", 6)) {
            ssl_ctx = SSL_CTX_new(TLSv1_1_client_method());
        } else {
            ssl_ctx = SSL_CTX_new(TLSv1_1_server_method());
        }
#else
        ERROR("Old TLS version 1.1 is no longer supported for [%s] context.", context_name);
        ssl_ctx = nullptr;
#endif
    } else if (tls_version == 1.2) {
        if (!strncmp(context_name, "client", 6)) {
            ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
        } else {
            ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());
        }
    } else if (tls_version == 1.3) {
        if (!strncmp(context_name, "client", 6)) {
            ssl_ctx = SSL_CTX_new(TLSv1_3_client_method());
        } else {
            ssl_ctx = SSL_CTX_new(TLSv1_3_server_method());
        }
    } else {
        ERROR("Unrecognized TLS version for [%s] context: %1.1f", context_name, tls_version);
        ssl_ctx = nullptr;
    }

#endif
    return ssl_ctx;
}

#endif // USE_OPENSSL || USE_WOLFSSL

/************* Prepare the SSL context ************************/
enum tls_init_status TLS_init_context(void)
{
    sip_trp_ssl_ctx = instantiate_ssl_context("generic");

    if (sip_trp_ssl_ctx == nullptr) {
        ERROR("TLS_init_context: SSL_CTX_new with TLS_method failed for generic context");
        return TLS_INIT_ERROR;
    }

    sip_trp_ssl_ctx_client = instantiate_ssl_context("client");

    if (sip_trp_ssl_ctx_client == nullptr) {
        ERROR("TLS_init_context: SSL_CTX_new with TLS_method failed for client context");
        return TLS_INIT_ERROR;
    }

    bool got_ca_file = strlen(tls_ca_name) != 0;
    bool got_crl_file = strlen(tls_crl_name) != 0;

    /* Load the trusted CA's */
    if (got_ca_file) {
        SSL_CTX_load_verify_locations(sip_trp_ssl_ctx, tls_ca_name, nullptr);
        SSL_CTX_load_verify_locations(sip_trp_ssl_ctx_client, tls_ca_name, nullptr);
    }

    /* TLS Verification only makes sense if an CA is specified or
     * we require CRL validation. */
    if (got_ca_file || got_crl_file) {
        if (got_crl_file) {
            if (sip_tls_load_crls(sip_trp_ssl_ctx, tls_crl_name) == -1) {
                ERROR("TLS_init_context: Unable to load CRL file (%s)", tls_crl_name);
                return TLS_INIT_ERROR;
            }

            if (sip_tls_load_crls(sip_trp_ssl_ctx_client, tls_crl_name) == -1) {
                ERROR("TLS_init_context: Unable to load CRL (client) file (%s)",
                    tls_crl_name);
                return TLS_INIT_ERROR;
            }
        }
        /* The following call forces to process the certificates with
         * the initialised SSL_CTX */
        SSL_CTX_set_verify(sip_trp_ssl_ctx,
                           SSL_VERIFY_PEER |
                           SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           sip_tls_verify_callback);

        SSL_CTX_set_verify(sip_trp_ssl_ctx_client,
                           SSL_VERIFY_PEER |
                           SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           sip_tls_verify_callback);
    }


    /* Selection Cipher suits - load the application specified ciphers */
    SSL_CTX_set_default_passwd_cb_userdata(sip_trp_ssl_ctx,
                                           (void *)CALL_BACK_USER_DATA);
    SSL_CTX_set_default_passwd_cb_userdata(sip_trp_ssl_ctx_client,
                                           (void *)CALL_BACK_USER_DATA);
    SSL_CTX_set_default_passwd_cb(sip_trp_ssl_ctx,
                                  passwd_call_back_routine);
    SSL_CTX_set_default_passwd_cb(sip_trp_ssl_ctx_client,
                                  passwd_call_back_routine);

    if (SSL_CTX_use_certificate_file(sip_trp_ssl_ctx,
                                     tls_cert_name,
                                     SSL_FILETYPE_PEM) != 1) {
        char errbuf[256] = {'\0'};
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        ERROR("TLS_init_context: SSL_CTX_use_certificate_file failed: %s", errbuf);
        return TLS_INIT_ERROR;
    }

    if (SSL_CTX_use_certificate_file(sip_trp_ssl_ctx_client,
                                     tls_cert_name,
                                     SSL_FILETYPE_PEM) != 1) {
        char errbuf[256] = {'\0'};
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        ERROR("TLS_init_context: SSL_CTX_use_certificate_file (client) failed: %s", errbuf);
        return TLS_INIT_ERROR;
    }
    if (SSL_CTX_use_PrivateKey_file(sip_trp_ssl_ctx,
                                     tls_key_name,
                                     SSL_FILETYPE_PEM) != 1) {
        ERROR("TLS_init_context: SSL_CTX_use_PrivateKey_file failed");
        return TLS_INIT_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(sip_trp_ssl_ctx_client,
                                    tls_key_name,
                                    SSL_FILETYPE_PEM) != 1) {
        ERROR("TLS_init_context: SSL_CTX_use_PrivateKey_file (client) failed");
        return TLS_INIT_ERROR;
    }

#ifdef HAVE_KEYLOG_CB
    if (keylog_file()) {
        SSL_CTX_set_keylog_callback(sip_trp_ssl_ctx_client, sip_tls_keylog_callback);
        SSL_CTX_set_keylog_callback(sip_trp_ssl_ctx, sip_tls_keylog_callback);
    }
#endif // HAVE_KEYLOG_CB


    return TLS_INIT_NORMAL;
}

int TLS_init()
{
    if (!thread_setup() || !SSL_library_init()) {
        return -1;
    }
    SSL_load_error_strings();
    return 1;
}
