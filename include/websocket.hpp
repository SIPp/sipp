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
 */

#ifndef __SIPP_WEBSOCKET_H__
#define __SIPP_WEBSOCKET_H__

#include <stddef.h>
#include <string>

/* SIP over WebSocket (RFC 7118): the opening handshake and the framing
 * (RFC 6455) of one connection. It does no I/O: its socket feeds it the
 * bytes it reads from TCP or TLS, and sends the bytes it gets back. */
class WebSocket
{
public:
    enum Opcode {
        OP_CONTINUATION = 0x0,
        OP_TEXT = 0x1,
        OP_BINARY = 0x2,
        OP_CLOSE = 0x8,
        OP_PING = 0x9,
        OP_PONG = 0xa
    };

    /* What next() found in the bytes fed. With each but NEED_MORE and
     * MESSAGE, there may be a reply to send. */
    enum Event {
        NEED_MORE, /* Nothing complete: feed more. */
        OPENED,    /* The handshake is done; a server replies 101. */
        MESSAGE,   /* A whole message, in payload. */
        REPLY,     /* A ping, to reply with a pong. */
        CLOSED,    /* The peer closed; the reply echoes its close. */
        FAILED     /* A protocol error, in error(); close after the reply. */
    };

    /* A server waits for a client's handshake. Messages may be up to
     * max_message bytes long. */
    WebSocket(bool server, size_t max_message);

    /* A client's handshake: a GET of path, for host. */
    std::string request(const char *host, const char *path);

    void feed(const char *data, size_t len);
    Event next(std::string &payload, std::string &reply);

    /* A message in a frame of its own: a text frame if it is UTF-8, a
     * binary one otherwise (RFC 7118 section 5.2); masked from a client. */
    std::string frame(const char *data, size_t len);
    /* A close frame, to end the connection. */
    std::string close_frame(unsigned code);

    bool is_open() const { return open; }
    /* Has the connection closed or failed? Nothing more comes out. */
    bool is_closed() const { return closed; }
    const std::string &error() const { return err; }

    /* The frames of the messages sent before the handshake was done, up
     * to WS_HELD_MAX bytes; has it been full? */
    std::string held;
    bool held_full = false;

    static std::string accept_key(const std::string &key);
    static std::string encode(int opcode, const char *data, size_t len,
                              const unsigned char *mask, bool fin = true);
    static bool is_utf8(const char *data, size_t len);

private:
    Event handshake(std::string &reply);
    Event fail(unsigned code, const std::string &why, std::string &reply);
    Event message(int opcode, const std::string &payload, std::string &reply);
    std::string make_frame(int opcode, const char *data, size_t len);

    bool server;
    size_t max_message;
    bool open = false;
    bool closed = false;
    std::string key;       /* A client's Sec-WebSocket-Key. */
    std::string in;        /* The bytes fed, from pos on not parsed yet. */
    size_t pos = 0;
    int fragmented = -1;   /* The opcode of the message in fragments. */
    std::string fragments;
    std::string err;
};

#endif /* __SIPP_WEBSOCKET_H__ */
