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

#ifdef _USE_OPENSSL
#include "sslcommon.h"
#endif

enum ssl_init_status {
    SSL_INIT_NORMAL, /* 0   Normal completion    */
    SSL_INIT_ERROR   /* 1   Unspecified error    */
};

extern  SSL_CTX             *sip_trp_ssl_ctx;
extern  SSL_CTX  *sip_trp_ssl_ctx_client;

int flush_socket(struct sipp_socket *socket);
int write_socket(struct sipp_socket *socket, const char *buffer, ssize_t len, int flags, struct sockaddr_storage *dest);
const char *sip_tls_error_string(SSL *ssl, int size);
void sipp_sctp_peer_params(struct sipp_socket *socket);
void buffer_read(struct sipp_socket *socket, struct socketbuf *newbuf);
int read_error(struct sipp_socket *socket, int ret);
struct socketbuf *alloc_socketbuf(char *buffer, size_t size, int copy, struct sockaddr_storage *dest);
ssize_t read_message(struct sipp_socket *socket, char *buf, size_t len, struct sockaddr_storage *src);
int empty_socket(struct sipp_socket *socket);

ssl_init_status FI_init_ssl_context (void);
struct sipp_socket *sipp_allocate_socket(bool use_ipv6, int transport, int fd, int accepting);

void setup_ctrl_socket();
void setup_stdin_socket();

char * get_inet_address(struct sockaddr_storage * addr);

int handle_ctrl_socket();
void handle_stdin_socket();
void process_message(struct sipp_socket *socket, char *msg, ssize_t msg_size, struct sockaddr_storage *src);


#endif /* __SIPP_SOCKET_H__ */
