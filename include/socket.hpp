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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 */

#ifndef __SIPP_SOCKET_H__
#define __SIPP_SOCKET_H__

#ifdef USE_OPENSSL
#include "sslcommon.h"

enum ssl_init_status {
    SSL_INIT_NORMAL, /* 0   Normal completion    */
    SSL_INIT_ERROR   /* 1   Unspecified error    */
};

extern SSL_CTX *sip_trp_ssl_ctx;
extern SSL_CTX *sip_trp_ssl_ctx_client;
const char *sip_tls_error_string(SSL *ssl, int size);
ssl_init_status FI_init_ssl_context (void);

#endif // USE_OPENSSL

int gai_getsockaddr(struct sockaddr_storage* ss, const char* host,
                    unsigned short port, int flags, int family);
int gai_getsockaddr(struct sockaddr_storage* ss, const char* host,
                    const char *service, int flags, int family);
void sockaddr_update_port(struct sockaddr_storage* ss, short port);


/* This is an abstraction of a socket, which provides buffers for input and
 * output. */
class SIPpSocket {
public:
    SIPpSocket(bool use_ipv6, int transport, int fd, int accepting);
    static SIPpSocket* new_sipp_call_socket(bool use_ipv6, int transport, bool *existing);

    int connect(struct sockaddr_storage* dest = NULL);
    int reconnect();

    // Reset a failed connection
    void reset_connection();

    // Accept new connections from a TCP socket
    SIPpSocket* accept();

    // Write data to the socket.
    int write(const char *buffer, ssize_t len, int flags, struct sockaddr_storage *dest);

    // Empty data from the socket into our buffer
    int empty();

    // Decrement the reference count of this socket, shutting it down when it reaches 0
    void close();

    int read_error(int ret);

    // Have we read a message from this socket?
    bool message_ready() { return ss_msglen > 0; };

    static void pollset_process(int wait);

    int ss_count;           /* How many users are there of this socket? */
    bool ss_ipv6;
    int ss_transport;       /* T_TCP, T_UDP, or T_TLS. */
    bool ss_control;        /* Is this a control socket? */
    int ss_fd;              /* The underlying file descriptor for this socket. */
    void *ss_comp_state;    /* The compression state. */

    bool ss_changed_dest;   /* Has the destination changed from default. */
    struct sockaddr_storage ss_dest; /* Who we are talking to. */

private:
    bool ss_congested; /* Is this socket congested? */
    bool ss_invalid; /* Has this socket been closed remotely? */

    int handleSCTPNotify(char* buffer);
    void sipp_sctp_peer_params();
    void invalidate();
    void buffer_read(struct socketbuf *newbuf);
    void buffer_write(const char *buffer, size_t len, struct sockaddr_storage *dest);
    ssize_t read_message(char *buf, size_t len, struct sockaddr_storage *src);
    struct socketbuf *ss_in;    /* Buffered input. */
    struct socketbuf *ss_out;   /* Buffered output. */
    size_t ss_msglen;           /* Is there a complete SIP message waiting, and if so how big? */

    void close_calls();
    int flush();
    int write_error(int ret);
    void abort();
    int check_for_message();
    int enter_congestion(int again);
    ssize_t write_primitive(const char* buffer, size_t len,
                            struct sockaddr_storage* dest);


    bool ss_call_socket; /* Is this a call socket? */

#ifdef USE_OPENSSL
    SSL *ss_ssl; /* The underlying SSL descriptor for this socket. */
    BIO *ss_bio; /* The underlying BIO descriptor for this socket. */
#endif

    int ss_pollidx; /* The index of this socket in our poll structures. */

#ifdef USE_SCTP
    int sctpstate;
#endif
};



void setup_ctrl_socket();
void setup_stdin_socket();

int handle_ctrl_socket();
void handle_stdin_socket();

void process_message(SIPpSocket* socket, char *msg, ssize_t msg_size, struct sockaddr_storage *src);
bool reconnect_allowed();

/********************** Network Interfaces ********************/

int send_message(int s, void ** comp_state, char * msg);
#ifdef USE_OPENSSL
int send_message_tls(SSL *s, void ** comp_state, char * msg);
#endif

/* Socket Buffer Management. */
#define NO_COPY 0
#define DO_COPY 1
struct socketbuf *alloc_socketbuf(char *buffer, size_t size, int copy);
struct socketbuf *alloc_socketbuf(char *buffer, size_t size, int copy, struct sockaddr_storage *dest);
void free_socketbuf(struct socketbuf *socketbuf);

/* These buffers lets us read past the end of the message, and then split it if
 * required.  This eliminates the need for reading a message octet by octet and
 * performing a second read for the content length. */
struct socketbuf {
    char *buf;
    size_t len;
    size_t offset;
    struct sockaddr_storage addr;
    struct socketbuf *next;
};

#ifdef USE_SCTP
#define SCTP_DOWN 0
#define SCTP_CONNECTING 1
#define SCTP_UP 2
#endif
/* Abort a connection - close the socket quickly. */

#define WS_EAGAIN 1 /* Return EAGAIN if there is no room for writing the message. */
#define WS_BUFFER 2 /* Buffer the message if there is no room for writing the message. */


#if defined (__hpux) || defined (__alpha) && !defined (__FreeBSD__)
#define sipp_socklen_t int
#else
#define sipp_socklen_t socklen_t
#endif

#if defined(__cplusplus) && defined (__hpux)
#define _RCAST(type, val) (reinterpret_cast<type> (val))
#else
#define _RCAST(type, val) ((type)(val))
#endif

#endif /* __SIPP_SOCKET_H__ */
