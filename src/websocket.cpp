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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#if defined(USE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/rand.h>
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/rand.h>
#endif

#include "websocket.hpp"

/* RFC 6455 section 1.3 */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static std::string base64(const unsigned char *data, size_t len)
{
    static const char digits[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;

    for (size_t i = 0; i < len; i += 3) {
        unsigned long n = (unsigned long)data[i] << 16;
        if (i + 1 < len) {
            n |= data[i + 1] << 8;
        }
        if (i + 2 < len) {
            n |= data[i + 2];
        }
        out += digits[n >> 18 & 63];
        out += digits[n >> 12 & 63];
        out += i + 1 < len ? digits[n >> 6 & 63] : '=';
        out += i + 2 < len ? digits[n & 63] : '=';
    }
    return out;
}

static void random_bytes(unsigned char *buf, int len)
{
    if (RAND_bytes(buf, len) != 1) {
        for (int i = 0; i < len; i++) {
            buf[i] = rand();
        }
    }
}

static std::string trim(const std::string &s)
{
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) {
        return "";
    }
    return s.substr(b, s.find_last_not_of(" \t") + 1 - b);
}

/* The values of the name header lines of an HTTP head, comma-separated.
 * The head ends with a CRLF, and its first line is the request or status
 * line. */
static std::string header(const std::string &head, const char *name)
{
    size_t name_len = strlen(name);
    std::string values;
    size_t bol = head.find("\r\n");

    while (bol != std::string::npos && bol + 2 < head.size()) {
        bol += 2;
        size_t eol = head.find("\r\n", bol);
        if (eol == std::string::npos) {
            eol = head.size();
        }
        if (eol - bol > name_len && head[bol + name_len] == ':' &&
                !strncasecmp(head.c_str() + bol, name, name_len)) {
            if (!values.empty()) {
                values += ',';
            }
            values += trim(head.substr(bol + name_len + 1, eol - bol - name_len - 1));
        }
        bol = eol;
    }
    return values;
}

/* Is token in the comma-separated list, ignoring case? */
static bool has_token(const std::string &list, const char *token)
{
    size_t b = 0;

    while (b <= list.size()) {
        size_t e = list.find(',', b);
        if (e == std::string::npos) {
            e = list.size();
        }
        if (!strcasecmp(trim(list.substr(b, e - b)).c_str(), token)) {
            return true;
        }
        b = e + 1;
    }
    return false;
}

WebSocket::WebSocket(bool server, size_t max_message) :
    server(server),
    max_message(max_message)
{
}

std::string WebSocket::accept_key(const std::string &key)
{
    std::string s = key + WS_GUID;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) ||
            !EVP_DigestUpdate(ctx, s.data(), s.size()) ||
            !EVP_DigestFinal_ex(ctx, hash, &len)) {
        len = 0;
    }
    EVP_MD_CTX_free(ctx);
    return base64(hash, len);
}

bool WebSocket::is_utf8(const char *data, size_t len)
{
    const unsigned char *s = (const unsigned char *)data;
    size_t i = 0;

    while (i < len) {
        unsigned long c = s[i];
        unsigned long min;
        size_t n;

        if (c < 0x80) {
            i++;
            continue;
        } else if ((c & 0xe0) == 0xc0) {
            n = 2;
            min = 0x80;
            c &= 0x1f;
        } else if ((c & 0xf0) == 0xe0) {
            n = 3;
            min = 0x800;
            c &= 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            n = 4;
            min = 0x10000;
            c &= 0x07;
        } else {
            return false;
        }
        if (len - i < n) {
            return false;
        }
        for (size_t k = 1; k < n; k++) {
            if ((s[i + k] & 0xc0) != 0x80) {
                return false;
            }
            c = c << 6 | (s[i + k] & 0x3f);
        }
        /* No overlong forms, surrogates, or code points past Unicode's. */
        if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) {
            return false;
        }
        i += n;
    }
    return true;
}

std::string WebSocket::encode(int opcode, const char *data, size_t len,
                              const unsigned char *mask, bool fin)
{
    std::string f;
    unsigned char masked = mask ? 0x80 : 0;

    f += (char)((fin ? 0x80 : 0) | opcode);
    if (len < 126) {
        f += (char)(masked | len);
    } else if (len < 65536) {
        f += (char)(masked | 126);
        f += (char)(len >> 8);
        f += (char)len;
    } else {
        f += (char)(masked | 127);
        for (int i = 7; i >= 0; i--) {
            f += (char)((unsigned long long)len >> (8 * i));
        }
    }
    if (mask) {
        f.append((const char *)mask, 4);
        for (size_t i = 0; i < len; i++) {
            f += (char)(data[i] ^ mask[i % 4]);
        }
    } else {
        f.append(data, len);
    }
    return f;
}

std::string WebSocket::make_frame(int opcode, const char *data, size_t len)
{
    unsigned char mask[4];

    /* A client masks all its frames, a server none (section 5.1). */
    if (server) {
        return encode(opcode, data, len, nullptr);
    }
    random_bytes(mask, sizeof(mask));
    return encode(opcode, data, len, mask);
}

std::string WebSocket::frame(const char *data, size_t len)
{
    return make_frame(is_utf8(data, len) ? OP_TEXT : OP_BINARY, data, len);
}

std::string WebSocket::close_frame(unsigned code)
{
    char status[2] = {(char)(code >> 8), (char)code};
    return make_frame(OP_CLOSE, status, sizeof(status));
}

std::string WebSocket::request(const char *host, const char *path)
{
    unsigned char nonce[16];

    random_bytes(nonce, sizeof(nonce));
    key = base64(nonce, sizeof(nonce));
    /* An absolute path, even if -ws_path leaves out its first '/'. */
    return std::string("GET ") + (*path == '/' ? "" : "/") + path + " HTTP/1.1\r\n"
           "Host: " + host + "\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: " + key + "\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "Sec-WebSocket-Protocol: sip\r\n"
           "\r\n";
}

void WebSocket::feed(const char *data, size_t len)
{
    if (closed) {
        return;
    }
    in.erase(0, pos);
    pos = 0;
    in.append(data, len);
}

/* Fail the connection: with a close frame once it is open, with an HTTP
 * error from a server during the handshake (code 400 or 426). */
WebSocket::Event WebSocket::fail(unsigned code, const std::string &why, std::string &reply)
{
    closed = true;
    err = why;
    if (open) {
        reply = close_frame(code);
    } else if (server) {
        reply = code == 426 ?
                "HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\n" :
                "HTTP/1.1 400 Bad Request\r\n";
        reply += "Content-Length: 0\r\n\r\n";
    }
    return FAILED;
}

WebSocket::Event WebSocket::handshake(std::string &reply)
{
    size_t end = in.find("\r\n\r\n", pos);

    if (end == std::string::npos) {
        if (in.size() - pos > max_message) {
            return fail(400, "a handshake longer than " + std::to_string(max_message) + " bytes", reply);
        }
        return NEED_MORE;
    }
    std::string head = in.substr(pos, end + 2 - pos);
    std::string first = head.substr(0, head.find("\r\n"));
    pos = end + 4;

    bool upgrade = has_token(header(head, "Upgrade"), "websocket") &&
                   has_token(header(head, "Connection"), "Upgrade");

    if (server) {
        std::string client_key = header(head, "Sec-WebSocket-Key");
        if (first.compare(0, 4, "GET ") || first.size() < 13 ||
                first.compare(first.size() - 9, 9, " HTTP/1.1")) {
            return fail(400, "not a GET request: '" + first + "'", reply);
        }
        if (!upgrade) {
            return fail(400, "not a WebSocket upgrade", reply);
        }
        if (!has_token(header(head, "Sec-WebSocket-Version"), "13")) {
            return fail(426, "not WebSocket version 13", reply);
        }
        if (client_key.empty()) {
            return fail(400, "no Sec-WebSocket-Key", reply);
        }
        if (!has_token(header(head, "Sec-WebSocket-Protocol"), "sip")) {
            return fail(400, "the client does not offer the sip subprotocol", reply);
        }
        reply = "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: " + accept_key(client_key) + "\r\n"
                "Sec-WebSocket-Protocol: sip\r\n"
                "\r\n";
    } else {
        if (first.compare(0, 12, "HTTP/1.1 101") || (first.size() > 12 && first[12] != ' ')) {
            return fail(0, "the server answered '" + first + "'", reply);
        }
        if (!upgrade) {
            return fail(0, "not a WebSocket upgrade", reply);
        }
        if (header(head, "Sec-WebSocket-Accept") != accept_key(key)) {
            return fail(0, "a wrong Sec-WebSocket-Accept", reply);
        }
        if (strcasecmp(header(head, "Sec-WebSocket-Protocol").c_str(), "sip")) {
            return fail(0, "the server does not take the sip subprotocol", reply);
        }
    }
    open = true;
    return OPENED;
}

/* May a close frame carry this status code? Those of section 7.4.1 and
 * the IANA registry that are not for local use only, and those for
 * libraries, frameworks and applications (section 7.4.2). */
static bool valid_close_code(unsigned code)
{
    return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
           (code >= 3000 && code <= 4999);
}

/* A whole message: the text of a text message is UTF-8 (section 8.1). */
WebSocket::Event WebSocket::message(int opcode, const std::string &payload, std::string &reply)
{
    if (opcode == OP_TEXT && !is_utf8(payload.data(), payload.size())) {
        return fail(1007, "a text message that is not UTF-8", reply);
    }
    return MESSAGE;
}

/* The next event in the bytes fed: first the handshake, then one frame
 * after the other (RFC 6455 section 5.2). A frame is a 2-byte header
 * (FIN, reserved bits, opcode; MASK, length), a 16- or 64-bit extended
 * length if the length is 126 or 127, a 4-byte mask if masked, then the
 * payload. Data frames make up a message, alone or in fragments; control
 * frames (close, ping, pong) come whole, even between fragments. A frame
 * not all in yet is left for the next call; one that breaks the rules
 * fails the connection. Called until it returns NEED_MORE. */
WebSocket::Event WebSocket::next(std::string &payload, std::string &reply)
{
    reply.clear();
    if (closed) {
        return NEED_MORE;
    }
    if (!open) {
        return handshake(reply);
    }

    /* Frames that need nothing sent (fragments, pongs) do not return. */
    for (;;) {
        const unsigned char *p = (const unsigned char *)in.data() + pos;
        size_t avail = in.size() - pos;
        if (avail < 2) {
            return NEED_MORE;
        }

        /* The 2-byte header */

        bool fin = p[0] & 0x80;
        int opcode = p[0] & 0x0f;
        bool masked = p[1] & 0x80;
        unsigned long long len = p[1] & 0x7f;
        size_t hlen = 2;

        /* No extension is negotiated, so no reserved bit may be set. */
        if (p[0] & 0x70) {
            return fail(1002, "a frame with reserved bits set", reply);
        }
        /* A client masks its frames, a server does not (section 5.1). */
        if (masked != server) {
            return fail(1002, server ? "an unmasked frame from the client" :
                        "a masked frame from the server", reply);
        }
        /* The extended length, in network byte order */
        if (len == 126) {
            if (avail < 4) {
                return NEED_MORE;
            }
            len = p[2] << 8 | p[3];
            hlen = 4;
        } else if (len == 127) {
            if (avail < 10) {
                return NEED_MORE;
            }
            len = 0;
            for (int i = 2; i < 10; i++) {
                len = len << 8 | p[i];
            }
            hlen = 10;
        }
        /* Checked before the payload is in, so that no peer makes it
         * buffer more than a message may take (section 5.5). */
        if (opcode >= OP_CLOSE) {
            if (!fin || len > 125) {
                return fail(1002, "a fragmented or long control frame", reply);
            }
        } else if (len > max_message - fragments.size()) {
            return fail(1009, "a message longer than " + std::to_string(max_message) + " bytes", reply);
        }
        if (masked) {
            hlen += 4;
        }
        if (avail < hlen + len) {
            return NEED_MORE;
        }

        /* The payload, unmasked */
        std::string data(in, pos + hlen, len);
        if (masked) {
            const unsigned char *mask = p + hlen - 4;
            for (size_t i = 0; i < len; i++) {
                data[i] ^= mask[i % 4];
            }
        }
        pos += hlen + len;

        switch (opcode) {
        case OP_TEXT:
        case OP_BINARY:
            /* A message, whole or in its first fragment */
            if (fragmented >= 0) {
                return fail(1002, "a new message inside a fragmented one", reply);
            }
            if (fin) {
                payload.swap(data);
                return message(opcode, payload, reply);
            }
            fragmented = opcode;
            fragments.swap(data);
            break;
        case OP_CONTINUATION:
            /* A further fragment; the last one completes the message. */
            if (fragmented < 0) {
                return fail(1002, "a continuation frame without a message", reply);
            }
            fragments += data;
            if (fin) {
                payload.swap(fragments);
                fragments.clear();
                opcode = fragmented;
                fragmented = -1;
                return message(opcode, payload, reply);
            }
            break;
        case OP_PING:
            reply = make_frame(OP_PONG, data.data(), data.size());
            return REPLY;
        case OP_PONG:
            break;
        case OP_CLOSE:
            /* An optional status code and UTF-8 reason (section 5.5.1) */
            if (data.size() == 1) {
                return fail(1002, "a close frame with a one-byte payload", reply);
            }
            if (data.size() >= 2) {
                unsigned code = (unsigned char)data[0] << 8 | (unsigned char)data[1];
                if (!valid_close_code(code)) {
                    return fail(1002, "a close frame with status code " + std::to_string(code), reply);
                }
                if (!is_utf8(data.data() + 2, data.size() - 2)) {
                    return fail(1007, "a close reason that is not UTF-8", reply);
                }
            }
            closed = true;
            /* Echo its status code (section 5.5.1). */
            reply = make_frame(OP_CLOSE, data.data(), data.size() < 2 ? 0 : 2);
            return CLOSED;
        default:
            return fail(1002, "a frame of unknown opcode " + std::to_string(opcode), reply);
        }
    }
}

#ifdef GTEST
#include "gtest/gtest.h"

static std::string bytes(const char *hex)
{
    std::string s;
    for (; hex[0] && hex[1]; hex += 2) {
        char b[3] = {hex[0], hex[1], 0};
        s += (char)strtol(b, nullptr, 16);
    }
    return s;
}

/* A client and a server, done with the handshake. */
static void handshake(WebSocket &client, WebSocket &server)
{
    std::string payload, reply;
    std::string req = client.request("example.com:5060", "/sip");

    EXPECT_EQ(0U, req.find("GET /sip HTTP/1.1\r\nHost: example.com:5060\r\n"));
    server.feed(req.data(), req.size());
    ASSERT_EQ(WebSocket::OPENED, server.next(payload, reply));
    EXPECT_EQ(0U, reply.find("HTTP/1.1 101 Switching Protocols\r\n"));
    EXPECT_NE(std::string::npos, reply.find("\r\nSec-WebSocket-Protocol: sip\r\n"));
    client.feed(reply.data(), reply.size());
    ASSERT_EQ(WebSocket::OPENED, client.next(payload, reply));
    EXPECT_TRUE(reply.empty());
    EXPECT_TRUE(client.is_open());
    EXPECT_TRUE(server.is_open());
}

TEST(WebSocket, AcceptKey) {
    /* RFC 6455 section 1.3 */
    EXPECT_EQ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", WebSocket::accept_key("dGhlIHNhbXBsZSBub25jZQ=="));
}

TEST(WebSocket, Encode) {
    /* RFC 6455 section 5.7 */
    const unsigned char mask[4] = {0x37, 0xfa, 0x21, 0x3d};
    EXPECT_EQ(bytes("810548656c6c6f"), WebSocket::encode(WebSocket::OP_TEXT, "Hello", 5, nullptr));
    EXPECT_EQ(bytes("818537fa213d7f9f4d5158"), WebSocket::encode(WebSocket::OP_TEXT, "Hello", 5, mask));
    EXPECT_EQ(bytes("010348656c"), WebSocket::encode(WebSocket::OP_TEXT, "Hel", 3, nullptr, false));
    EXPECT_EQ(bytes("80026c6f"), WebSocket::encode(WebSocket::OP_CONTINUATION, "lo", 2, nullptr));

    std::string s(256, 'x');
    EXPECT_EQ(bytes("827e0100") + s, WebSocket::encode(WebSocket::OP_BINARY, s.data(), s.size(), nullptr));
    s.assign(65536, 'x');
    EXPECT_EQ(bytes("827f0000000000010000") + s, WebSocket::encode(WebSocket::OP_BINARY, s.data(), s.size(), nullptr));
    s.assign(125, 'x');
    EXPECT_EQ(bytes("827d") + s, WebSocket::encode(WebSocket::OP_BINARY, s.data(), s.size(), nullptr));
    s.assign(126, 'x');
    EXPECT_EQ(bytes("827e007e") + s, WebSocket::encode(WebSocket::OP_BINARY, s.data(), s.size(), nullptr));
}

TEST(WebSocket, Utf8) {
    EXPECT_TRUE(WebSocket::is_utf8("INVITE sip:a@b SIP/2.0\r\n", 24));
    EXPECT_TRUE(WebSocket::is_utf8("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80", 14));
    EXPECT_FALSE(WebSocket::is_utf8("\xff", 1));
    EXPECT_FALSE(WebSocket::is_utf8("\xc0\x80", 2));         /* Overlong */
    EXPECT_FALSE(WebSocket::is_utf8("\xed\xa0\x80", 3));     /* Surrogate */
    EXPECT_FALSE(WebSocket::is_utf8("\xf4\x90\x80\x80", 4)); /* Past U+10FFFF */
    EXPECT_FALSE(WebSocket::is_utf8("\xc3", 1));             /* Cut short */
    EXPECT_FALSE(WebSocket::is_utf8("\xc3(", 2));

    WebSocket server(true, 100);
    EXPECT_EQ(bytes("810141"), server.frame("A", 1));
    EXPECT_EQ(bytes("8201ff"), server.frame("\xff", 1));
}

TEST(WebSocket, Messages) {
    WebSocket client(false, 100000), server(true, 100000);
    std::string payload, reply, f;
    handshake(client, server);

    /* Client frames are masked, each with a mask of its own. */
    f = client.frame("INVITE", 6);
    ASSERT_EQ(12U, f.size());
    EXPECT_EQ('\x81', f[0]);
    EXPECT_EQ('\x86', f[1]);
    server.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::MESSAGE, server.next(payload, reply));
    EXPECT_EQ("INVITE", payload);
    EXPECT_EQ(WebSocket::NEED_MORE, server.next(payload, reply));

    /* Server frames are not; and one read may hold several frames. */
    f = server.frame("SIP/2.0 100", 11) + server.frame("SIP/2.0 200", 11);
    EXPECT_EQ(bytes("810b") + "SIP/2.0 100", f.substr(0, 13));
    client.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::MESSAGE, client.next(payload, reply));
    EXPECT_EQ("SIP/2.0 100", payload);
    EXPECT_EQ(WebSocket::MESSAGE, client.next(payload, reply));
    EXPECT_EQ("SIP/2.0 200", payload);

    /* 16- and 64-bit lengths, a byte at a time. */
    for (size_t len : {300, 70000}) {
        std::string msg(len, 'm');
        f = client.frame(msg.data(), msg.size());
        for (size_t i = 0; i + 1 < f.size(); i++) {
            server.feed(&f[i], 1);
            ASSERT_EQ(WebSocket::NEED_MORE, server.next(payload, reply));
        }
        server.feed(&f[f.size() - 1], 1);
        EXPECT_EQ(WebSocket::MESSAGE, server.next(payload, reply));
        EXPECT_EQ(msg, payload);
    }
}

TEST(WebSocket, Fragments) {
    WebSocket client(false, 100), server(true, 100);
    std::string payload, reply, f;
    handshake(client, server);

    /* A ping may come between the fragments of a message. */
    f = WebSocket::encode(WebSocket::OP_TEXT, "INV", 3, nullptr, false) +
        WebSocket::encode(WebSocket::OP_PING, "hi", 2, nullptr) +
        WebSocket::encode(WebSocket::OP_CONTINUATION, "ITE", 3, nullptr, false) +
        WebSocket::encode(WebSocket::OP_PONG, "", 0, nullptr) +
        WebSocket::encode(WebSocket::OP_CONTINUATION, " sip", 4, nullptr);
    client.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::REPLY, client.next(payload, reply));
    /* The pong, masked. */
    ASSERT_EQ(8U, reply.size());
    EXPECT_EQ('\x8a', reply[0]);
    EXPECT_EQ('\x82', reply[1]);
    server.feed(reply.data(), reply.size());
    EXPECT_EQ(WebSocket::NEED_MORE, server.next(payload, reply));
    EXPECT_EQ(WebSocket::MESSAGE, client.next(payload, reply));
    EXPECT_EQ("INVITE sip", payload);
    EXPECT_EQ(WebSocket::NEED_MORE, client.next(payload, reply));

    /* A character of a text message may span fragments. */
    f = bytes("0101c3") + bytes("8001a9");
    client.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::MESSAGE, client.next(payload, reply));
    EXPECT_EQ("\xc3\xa9", payload);

    /* Fragments no longer, in all, than a message may be. */
    std::string half(60, 'x');
    f = WebSocket::encode(WebSocket::OP_BINARY, half.data(), half.size(), nullptr, false) +
        WebSocket::encode(WebSocket::OP_CONTINUATION, half.data(), half.size(), nullptr);
    client.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::FAILED, client.next(payload, reply));
    EXPECT_EQ("a message longer than 100 bytes", client.error());
    EXPECT_TRUE(client.is_closed());
}

TEST(WebSocket, Ping) {
    WebSocket client(false, 100), server(true, 100);
    std::string payload, reply, f;
    handshake(client, server);

    f = WebSocket::encode(WebSocket::OP_PING, "abc", 3, (const unsigned char *)"\1\2\3\4");
    server.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::REPLY, server.next(payload, reply));
    EXPECT_EQ(bytes("8a03") + "abc", reply);
}

TEST(WebSocket, Close) {
    WebSocket client(false, 100), server(true, 100);
    std::string payload, reply, f;
    handshake(client, server);

    f = client.frame("BYE", 3) + client.close_frame(1000) + client.frame("late", 4);
    server.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::MESSAGE, server.next(payload, reply));
    EXPECT_EQ(WebSocket::CLOSED, server.next(payload, reply));
    EXPECT_EQ(bytes("880203e8"), reply);
    EXPECT_TRUE(server.is_closed());
    /* Nothing comes after a close. */
    EXPECT_EQ(WebSocket::NEED_MORE, server.next(payload, reply));
    server.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::NEED_MORE, server.next(payload, reply));

    f = WebSocket::encode(WebSocket::OP_CLOSE, "", 0, nullptr);
    client.feed(f.data(), f.size());
    EXPECT_EQ(WebSocket::CLOSED, client.next(payload, reply));
    ASSERT_EQ(6U, reply.size());
    EXPECT_EQ('\x88', reply[0]);
    EXPECT_EQ('\x80', reply[1]);

    /* Status codes of the registry and for applications, with a UTF-8
     * reason; the echo leaves out the reason. */
    for (const char *close : {"880203f2", "88070fa0c3a9746521"}) {
        WebSocket client(false, 100), server(true, 100);
        handshake(client, server);
        f = bytes(close);
        client.feed(f.data(), f.size());
        EXPECT_EQ(WebSocket::CLOSED, client.next(payload, reply)) << close;
        ASSERT_EQ(8U, reply.size());
        EXPECT_EQ('\x82', reply[1]);
    }
}

TEST(WebSocket, ProtocolErrors) {
    struct {
        bool to_server;
        std::string frame;
        const char *error;
        unsigned code;
    } tests[] = {
        {true, bytes("810141"), "an unmasked frame from the client", 1002},
        {false, bytes("81810000000041"), "a masked frame from the server", 1002},
        {false, bytes("c10141"), "a frame with reserved bits set", 1002},
        {false, bytes("830141"), "a frame of unknown opcode 3", 1002},
        {false, bytes("800141"), "a continuation frame without a message", 1002},
        {false, bytes("01014181014142"), "a new message inside a fragmented one", 1002},
        {false, bytes("097e0080"), "a fragmented or long control frame", 1002},
        {false, bytes("0900"), "a fragmented or long control frame", 1002},
        {false, bytes("880103"), "a close frame with a one-byte payload", 1002},
        {false, bytes("880203e7"), "a close frame with status code 999", 1002},
        {false, bytes("880203ed"), "a close frame with status code 1005", 1002},
        {false, bytes("88021388"), "a close frame with status code 5000", 1002},
        {false, bytes("880303e8ff"), "a close reason that is not UTF-8", 1007},
        {false, bytes("8102c328"), "a text message that is not UTF-8", 1007},
        {false, bytes("0101c3800128"), "a text message that is not UTF-8", 1007},
        {false, bytes("817e0065"), "a message longer than 100 bytes", 1009},
        {false, bytes("817fffffffffffffffff"), "a message longer than 100 bytes", 1009},
    };

    for (auto &t : tests) {
        WebSocket client(false, 100), server(true, 100);
        std::string payload, reply;
        handshake(client, server);
        WebSocket &ws = t.to_server ? server : client;

        ws.feed(t.frame.data(), t.frame.size());
        EXPECT_EQ(WebSocket::FAILED, ws.next(payload, reply)) << t.error;
        EXPECT_EQ(t.error, ws.error());
        /* A close frame with the status code. */
        ASSERT_GE(reply.size(), 4U);
        EXPECT_EQ('\x88', reply[0]);
        std::string status = reply.substr(reply.size() - 2);
        if (!t.to_server) {
            /* Unmask it. */
            for (int i = 0; i < 2; i++) {
                status[i] ^= reply[2 + i];
            }
        }
        EXPECT_EQ(t.code, (unsigned)((unsigned char)status[0] << 8 | (unsigned char)status[1]));
    }
}

TEST(WebSocket, ServerHandshake) {
    const char *valid =
        "GET / HTTP/1.1\r\n"
        "Host: h\r\n"
        "upgrade: WebSocket\r\n"
        "Connection: keep-alive, Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: chat\r\n"
        "Sec-WebSocket-Protocol: sip\r\n"
        "\r\n";
    std::string payload, reply;

    {
        WebSocket server(true, 1000);
        std::string req = valid;
        /* In two parts, and with a frame right behind. */
        req += bytes("818100000000") + "A";
        server.feed(req.data(), 10);
        EXPECT_EQ(WebSocket::NEED_MORE, server.next(payload, reply));
        server.feed(req.data() + 10, req.size() - 10);
        EXPECT_EQ(WebSocket::OPENED, server.next(payload, reply));
        EXPECT_EQ("HTTP/1.1 101 Switching Protocols\r\n"
                  "Upgrade: websocket\r\n"
                  "Connection: Upgrade\r\n"
                  "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                  "Sec-WebSocket-Protocol: sip\r\n"
                  "\r\n", reply);
        EXPECT_EQ(WebSocket::MESSAGE, server.next(payload, reply));
        EXPECT_EQ("A", payload);
    }

    struct {
        const char *from, *to;
        const char *status;
        const char *error;
    } tests[] = {
        {"GET / ", "POST / ", "400", "not a GET request: 'POST / HTTP/1.1'"},
        {"WebSocket", "h2c", "400", "not a WebSocket upgrade"},
        {"keep-alive, Upgrade", "close", "400", "not a WebSocket upgrade"},
        {"Version: 13", "Version: 8", "426", "not WebSocket version 13"},
        {"Key: dGhlIHNhbXBsZSBub25jZQ==", "Key:", "400", "no Sec-WebSocket-Key"},
        {"Protocol: sip", "Protocol: sips", "400", "the client does not offer the sip subprotocol"},
    };
    for (auto &t : tests) {
        WebSocket server(true, 1000);
        std::string req = valid;
        req.replace(req.find(t.from), strlen(t.from), t.to);
        server.feed(req.data(), req.size());
        EXPECT_EQ(WebSocket::FAILED, server.next(payload, reply)) << t.error;
        EXPECT_EQ(t.error, server.error());
        EXPECT_EQ(std::string("HTTP/1.1 ") + t.status, reply.substr(0, 12));
        EXPECT_FALSE(server.is_open());
    }

    WebSocket server(true, 10);
    server.feed(valid, 11);
    EXPECT_EQ(WebSocket::FAILED, server.next(payload, reply));
    EXPECT_EQ("a handshake longer than 10 bytes", server.error());
}

TEST(WebSocket, ClientHandshake) {
    std::string payload, reply;
    struct {
        const char *from, *to;
        const char *error;
    } tests[] = {
        {"101 Switching Protocols", "404 Not Found", "the server answered 'HTTP/1.1 404 Not Found'"},
        {"101 Switching Protocols", "1010", "the server answered 'HTTP/1.1 1010'"},
        {"Upgrade: websocket", "Upgrade: x", "not a WebSocket upgrade"},
        {"Accept: ", "Accept: x", "a wrong Sec-WebSocket-Accept"},
        {"Protocol: sip", "Protocol: chat", "the server does not take the sip subprotocol"},
    };

    for (auto &t : tests) {
        WebSocket client(false, 1000), server(true, 1000);
        std::string req = client.request("h", "");
        EXPECT_EQ(0U, req.find("GET / HTTP/1.1\r\n"));
        /* A path without its first '/'. */
        EXPECT_EQ(0U, client.request("h", "sip").find("GET /sip HTTP/1.1\r\n"));
        req = client.request("h", "/");
        server.feed(req.data(), req.size());
        ASSERT_EQ(WebSocket::OPENED, server.next(payload, reply));
        reply.replace(reply.find(t.from), strlen(t.from), t.to);
        client.feed(reply.data(), reply.size());
        EXPECT_EQ(WebSocket::FAILED, client.next(payload, reply)) << t.error;
        EXPECT_EQ(t.error, client.error());
        EXPECT_TRUE(reply.empty());
        EXPECT_FALSE(client.is_open());
        EXPECT_TRUE(client.is_closed());
    }
}

#endif /* GTEST */
