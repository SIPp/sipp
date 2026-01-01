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

#include "sslsocket.hpp"

#ifdef USE_SCTP
#define SCTP_DOWN 0
#define SCTP_CONNECTING 1
#define SCTP_UP 2
#endif

/**
 * On some systems you must pass the exact sockaddr struct size to
 * connect/bind/sendto calls. Passing a length that is too large
 * causes EINVAL.
 *
 * For instance on OSX. If you don't, you'll get this:
 * Unable to bind audio RTP socket (IP=X.X.X.X, port=6100), errno = 22
 * (Invalid argument).
 *
 * Usage:
 *
 *   struct sockaddr_storage addr;
 *   ...
 *   bind(socket, (struct sockaddr*)&addr, socklen_from_addr(&addr));
 */
inline socklen_t socklen_from_addr(const struct sockaddr_storage* ss) {
    if (ss->ss_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (ss->ss_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    } else {
        assert(false);
        return 0;
    }
}

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
    void set_bind_port(int bind_port);

    int connect(struct sockaddr_storage* dest = nullptr);
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

#ifdef SO_BINDTODEVICE
    // Bind to specific network device.
    int bind_to_device(const char* device_name);
#endif

    static void pollset_process(int wait);

    int ss_count = 1;           /* How many users are there of this socket? */
    bool ss_ipv6 = false;
    int ss_transport = 0;       /* T_TCP, T_UDP, or T_TLS. */
    bool ss_control = false;    /* Is this a control socket? */
    int ss_fd = -1;             /* The underlying file descriptor for this socket. */
    int ss_port = 0;            /* The port used by this socket */
    int ss_bind_port = 0;       /* Optional local port used by this socket */
    void *ss_comp_state = nullptr;    /* The compression state. */

    bool ss_changed_dest = false;   /* Has the destination changed from default. */
    struct sockaddr_storage ss_dest; /* Who we are talking to. */

private:
    bool ss_congested = false; /* Is this socket congested? */
    bool ss_invalid = false; /* Has this socket been closed remotely? */

    int handleSCTPNotify(char* buffer);
    void sipp_sctp_peer_params();
    void invalidate();
    void buffer_read(struct socketbuf *newbuf);
    void buffer_write(const char *buffer, size_t len, struct sockaddr_storage *dest);
    ssize_t read_message(char *buf, size_t len, struct sockaddr_storage *src);
    struct socketbuf *ss_in = nullptr;    /* Buffered input. */
    struct socketbuf *ss_out = nullptr;   /* Buffered output. */
    struct socketbuf *ss_out_tail = nullptr; /* Tail of buffered output */
    size_t ss_msglen = 0;           /* Is there a complete SIP message waiting, and if so how big? */

    void close_calls();
    int flush();
    int write_error(int ret);
    void abort();
    int check_for_message();
    int enter_congestion(int again);
    ssize_t write_primitive(const char* buffer, size_t len,
                            struct sockaddr_storage* dest);


    bool ss_call_socket = false; /* Is this a call socket? */

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
    SSL *ss_ssl = nullptr; /* The underlying SSL descriptor for this socket. */
    BIO *ss_bio = nullptr; /* The underlying BIO descriptor for this socket. */
#endif

    int ss_pollidx = -1; /* The index of this socket in our poll structures. */

#ifdef USE_SCTP
    int sctpstate = SCTP_DOWN;
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
#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
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

/* Abort a connection - close the socket quickly. */

#define WS_EAGAIN 1 /* Return EAGAIN if there is no room for writing the message. */
#define WS_BUFFER 2 /* Buffer the message if there is no room for writing the message. */


#if defined (__hpux) || (defined (__alpha) && !defined (__FreeBSD__) && !defined (__linux__))
#define sipp_socklen_t int
#else
#define sipp_socklen_t socklen_t
#endif

#if defined(__cplusplus) && defined (__hpux)
#define _RCAST(type, val) (reinterpret_cast<type> (val))
#else
#define _RCAST(type, val) ((type)(val))
#endif

/* Time to wait in microseconds before retrying querying an SSL socket */
#define SIPP_SSL_RETRY_TIMEOUT 200000

/* Max retries when querying an SSL socket */
#define SIPP_SSL_MAX_RETRIES 10

#endif /* __SIPP_SOCKET_H__ */
