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
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           Olivier Jacques
 *           From Hewlett Packard Company.
 *           Shriram Natarajan
 *           Peter Higginson
 *           Eric Miller
 *           Venkatesh
 *           Enrico Hartung
 *           Nasir Khan
 *           Lee Ballard
 *           Guillaume Teissier from FTR&D
 *           Wolfgang Beck
 *           Venkatesh
 *           Vlad Troyanker
 *           Charles P Wright from IBM Research
 *           Amit On from Followap
 *           Jan Andres from Freenet
 *           Ben Evans from Open Cloud
 *           Marc Van Diest from Belgacom
 *           Stefan Esser
 *           Andy Aicken
 *           Walter Doekes
 */

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <charconv>
#include <string_view>

#include "screen.hpp"
#include "sip_parser.hpp"

/*************************** Mini SIP parser (internals) ***************/

/*
 * SIP ABNF can be found here:
 *   http://tools.ietf.org/html/rfc3261#section-25
 * In 2014, there is a very helpful site that lets you browse the ABNF
 * easily:
 *   http://www.in2eps.com/fo-abnf/tk-fo-abnf-sip.html
 */

static const char* internal_find_param(const char* ptr, const char* name);
static const char* internal_find_header(const char* msg, const char* name,
        const char* shortname, bool content);
static const char* internal_skip_lws(const char* ptr);

/* Search for a character, but only inside this header. Returns nullptr if
 * not found. */
static const char* internal_hdrchr(const char* ptr, const char needle);

/* Seek to end of this header. Returns the position the next character,
 * which must be at the header-delimiting-CRLF or, if the message is
 * broken, at the ASCIIZ NUL. */
static const char* internal_hdrend(const char* ptr);

/* A header name looked for, with its colon, and its compact form if it
 * has one, "v:" for "Via:"; their first letters in lower case, compared
 * before the rest */
struct header_name {
    std::string_view name;
    const char *compact;
    int first, second, compact_first;
};

static const char *internal_compact_header_name(std::string_view name);
static header_name internal_header_name(std::string_view name);
static const char *internal_match_header(const char *message, const char *ptr, const header_name &h);
static const char *internal_header_value(const char *line, const char **end);
static std::string internal_join_headers(const char *message, const char *line, const header_name &h, bool content);
static bool internal_append(std::string &dest, const char *src, size_t len, bool *cut);


/*************************** Mini SIP parser (externals) ***************/

std::optional<std::string_view> get_peer_tag(const char *msg)
{
    const char *to_hdr;
    const char *ptr;

    /* Find start of header */
    to_hdr = internal_find_header(msg, "To", "t", true);
    if (!to_hdr) {
        WARNING("No valid To: header in reply");
        return std::nullopt;
    }

    /* Skip past display-name */
    /* FIXME */

    /* Skip past LA/RA-quoted addr-spec if any */
    ptr = internal_hdrchr(to_hdr, '>');
    if (!ptr) {
        /* Maybe an addr-spec without quotes */
        ptr = to_hdr;
    }

    /* Find tag in this header */
    ptr = internal_find_param(ptr, "tag");
    if (!ptr) {
        return std::nullopt;
    }

    /* At most MAX_HEADER_LEN - 1 characters of it */
    const size_t len = strcspn(ptr, " ;\t\r\n");
    return std::string_view(ptr, len < MAX_HEADER_LEN - 1 ? len : MAX_HEADER_LEN - 1);
}

header_value get_header_content(const char *message, std::string_view name)
{
    return get_header(message, name, true);
}

/* If content is true, we only return the header's contents. */
header_value get_header(const char *message, std::string_view name, bool content)
{
    /* returns empty string in case of error */
    if (!message || !*message) {
        return header_value();
    }

    /* for safety's sake */
    if (name.empty() || (name.back() != ':' && name.find(':') == std::string_view::npos)) {
        WARNING("Can not search for header (no colon): %.*s", (int)name.size(), name.data());
        return header_value();
    }

    const header_name h = internal_header_name(name);

    /* The headers are read where they are, up to the blank line that
     * ends them, or to the end of a message that has none */
    const char *line = internal_match_header(message, message, h);
    if (!line) {
        return header_value();
    }

    const char *end;
    const char *value = internal_header_value(line, &end);
    if (internal_match_header(message, *value ? value + 1 : value, h)) {
        return header_value(internal_join_headers(message, line, h, content));
    }

    /* A header alone is returned where it is, without the spaces, tabs
     * and CRs after it, when the message has it as it is returned: the
     * name asked for, its only colon at its end, and one space before
     * the value unless content, and no doubled CR that the join drops (a
     * value has no doubled LF: a space or tab follows each LF in it). */
    const char *text, *min_end;
    if (content) {
        if (end == value) {
            return header_value();
        }
        /* The first character stays, as in the join */
        text = value;
        min_end = value + 1;
    } else {
        text = line + 1;
        min_end = text + name.size();
        /* Not the compact form, whose colon is second, unless it is
         * the name: then the line has the name's characters */
        if (name.back() != ':' || memchr(name.data(), ':', name.size() - 1) || name[0] == ' ' ||
            (text[1] == ':' && name.size() > 2) || std::string_view(text, name.size()) != name) {
            return header_value(internal_join_headers(message, line, h, content));
        }
    }
    const size_t joined_size = (content ? 0 : name.size() + 1) + (end - value);
    while (end > min_end && (end[-1] == ' ' || end[-1] == '\r' || end[-1] == '\t')) {
        end--;
    }
    const std::string_view found(text, end - text);
    if ((!content && end > min_end && (value != min_end + 1 || *min_end != ' ')) ||
        joined_size > MAX_HEADER_LEN * 10 - 1 ||
        (memchr(found.data(), '\r', found.size()) && found.find("\r\r") != std::string_view::npos)) {
        return header_value(internal_join_headers(message, line, h, content));
    }
    return header_value(found);
}

long header_number(std::string_view value)
{
    const char *p = value.data(), *end = p + value.size();
    long number = 0;

    while (p < end && isspace((unsigned char)*p)) {
        p++;
    }
    /* from_chars() takes a '-' but no '+' */
    if (p + 1 < end && *p == '+' && p[1] != '-') {
        p++;
    }
    if (std::from_chars(p, end, number).ec == std::errc::result_out_of_range) {
        number = *p == '-' ? LONG_MIN : LONG_MAX;
    }
    return number;
}

/* The value of the header whose line starts after the newline at line:
 * from after the spaces after its colon to where its last line ends, at
 * *end. The CRLF of the blank line after it is not part of it. */
static const char *internal_header_value(const char *line, const char **end)
{
    const char *src = line;
    const char *eol;

    /* Skip over the header name */
    while (*src != ':') {
        src++;
    }
    src++;

    /* Skip over leading spaces. */
    while (*src == ' ') {
        src++;
    }
    eol = strchr(src, '\n');

    /* Multiline headers always begin with a tab or a space
     * on the subsequent lines. Skip those lines. */
    while (eol && (*(eol + 1) == ' ' || *(eol + 1) == '\t')) {
        eol = strchr(eol + 1, '\n');
    }

    if (!eol) {
        *end = src + strlen(src);
    } else if (eol[-1] == '\r' && eol[1] == '\r' && eol[2] == '\n') {
        *end = eol - 1; /* the blank line's CRLF ends this header */
    } else {
        *end = eol;
    }
    return src;
}

/* The headers of name from the one at line on, joined with ", ", the
 * name before them unless content; the spaces, tabs and CRs around
 * them trimmed and doubled CRs and LFs dropped. They end before the
 * first that doesn't fit in MAX_HEADER_LEN * 10 - 1 characters, or are
 * as much of it as fits when it is the first. */
static std::string internal_join_headers(const char *message, const char *line, const header_name &h, bool content)
{
    const std::string_view name = h.name;
    std::string dest;
    bool cut = false;

    if (!content && !internal_append(dest, name.data(), name.size(), &cut)) {
        line = nullptr;
    }

    while (line) {
        const char *value_end;
        const char *src = internal_header_value(line, &value_end);

        // Add ", " when several headers are present
        if (!dest.empty()) {
            /* Remove trailing whitespaces, tabs, and CRs */
            while (!dest.empty() &&
                   (dest.back() == ' ' || dest.back() == '\r' || dest.back() == '\n' || dest.back() == '\t')) {
                dest.pop_back();
            }

            if (!dest.empty() && dest.back() == ':') {
                if (!internal_append(dest, " ", 1, &cut))
                    break;
            } else {
                if (!internal_append(dest, ", ", 2, &cut))
                    break;
            }
        }

        if (!internal_append(dest, src, value_end - src, &cut)) {
            break;
        }

        line = internal_match_header(message, *src ? src + 1 : src, h);
    }

    /* No header found? */
    if (dest.empty() || cut) {
        return dest;
    }

    /* Remove trailing whitespaces, tabs, and CRs */
    while (dest.size() > 1 && (dest.back() == ' ' || dest.back() == '\r' || dest.back() == '\t')) {
        dest.pop_back();
    }

    /* Remove leading whitespaces */
    dest.erase(0, dest.find_first_not_of(' '));

    /* A header folded on several lines keeps its CRLFs: a [last_*]
     * keyword sends it as it came, with no bare LF in it. */

    /* Remove illegal double CR and double Newline characters */
    for (const char c : {'\r', '\n'}) {
        size_t kept = 0;
        for (size_t i = 0; i < dest.size(); i++) {
            if (dest[i] != c || !kept || dest[kept - 1] != c) {
                dest[kept++] = dest[i];
            }
        }
        dest.resize(kept);
    }

    return dest;
}

/* Append len bytes of src to dest, if they fit in MAX_HEADER_LEN * 10 -
 * 1 characters: false when they don't, with *cut set and as many as fit
 * written to an empty dest. */
static bool internal_append(std::string &dest, const char *src, size_t len, bool *cut)
{
    const size_t room = MAX_HEADER_LEN * 10 - 1 - dest.size();

    if (len > room) {
        if (dest.empty()) {
            dest.assign(src, room);
            *cut = true;
        }
        return false;
    }
    dest.append(src, len);
    return true;
}

/* The newline before the first line from ptr on that starts with name or
 * compact_name, or nullptr when the headers of message end first, at
 * their blank line or at the end of message. One pass over its lines,
 * rather than searching all of what is left of the message for each
 * form, as strcasestr() did */
static inline const char *internal_match_header(const char *message, const char *ptr, const header_name &h)
{
    for (const char *line = strchr(ptr, '\n'); line; line = strchr(line + 1, '\n')) {
        if (line[1] == '\r' && line[2] == '\n' && line != message && line[-1] == '\r') {
            return nullptr;
        }
        const int c = tolower((unsigned char)line[1]);
        if (c == h.first && (h.second < 0 || tolower((unsigned char)line[2]) == h.second) &&
            !strncasecmp(line + 1, h.name.data(), h.name.size())) {
            return line;
        }
        if (c == h.compact_first && line[2] == h.compact[1]) {
            return line;
        }
    }
    return nullptr;
}

static header_name internal_header_name(std::string_view name)
{
    header_name h;

    h.name = name;
    h.compact = internal_compact_header_name(name);
    if (h.compact) {
        h.compact++;
    }
    h.first = tolower((unsigned char)name[0]);
    h.second = name.size() > 1 ? tolower((unsigned char)name[1]) : -1;
    h.compact_first = h.compact ? tolower((unsigned char)h.compact[0]) : -1;
    return h;
}

const char *internal_compact_header_name(std::string_view name)
{
    static const struct {
        std::string_view name;
        const char *compact;
    } compact_names[] = {
        {"call-id:", "\ni:"},
        {"contact:", "\nm:"},
        {"content-encoding:", "\ne:"},
        {"content-length:", "\nl:"},
        {"content-type:", "\nc:"},
        {"from:", "\nf:"},
        {"to:", "\nt:"},
        {"via:", "\nv:"},
    };
    const int first = tolower((unsigned char)name[0]);

    for (const auto &c : compact_names) {
        /* Only the name of the same length and first letter */
        if (c.name.size() == name.size() && c.name[0] == first &&
            !strncasecmp(name.data(), c.name.data(), name.size())) {
            return c.compact;
        }
    }
    return nullptr;
}

std::string_view get_first_line(const char *message)
{
    if (!message) {
        return "";
    }
    return std::string_view(message, strcspn(message, "\r\n"));
}

/* The Call-ID of msg, or "" when it has none or the header is too long:
 * the caller says what that means for it. */
std::string_view get_call_id(const char *msg)
{
    const char *content, *end_of_header;
    size_t length;

    content = internal_find_header(msg, "Call-ID", "i", true);
    if (!content) {
        return "";
    }

    /* Always returns something */
    end_of_header = internal_hdrend(content);
    length = end_of_header - content;
    if (length + 1 > MAX_HEADER_LEN) {
        return "";
    }
    return std::string_view(content, length);
}

unsigned long int get_cseq_value(const char* msg)
{
    const char* ptr1;

    // no short form for CSeq:
    ptr1 = strstr(msg, "\r\nCSeq:");
    if (!ptr1) {
        ptr1 = strstr(msg, "\r\nCSEQ:");
    }
    if (!ptr1) {
        ptr1 = strstr(msg, "\r\ncseq:");
    }
    if (!ptr1) {
        ptr1 = strstr(msg, "\r\nCseq:");
    }
    if (!ptr1) {
        WARNING("No valid Cseq header in request %s", msg);
        return 0;
    }

    ptr1 += 7;

    while (*ptr1 == ' ' || *ptr1 == '\t') {
        ++ptr1;
    }

    if (!*ptr1) {
        WARNING("No valid Cseq data in header");
        return 0;
    }

    return strtoul(ptr1, nullptr, 10);
}

/* The status code, after the first blank of the first line: 0 for a
 * request, or a first line without one */
unsigned long get_reply_code(const char* msg)
{
    if (!msg) {
        return 0;
    }
    const char *end = msg + strcspn(msg, "\r\n");
    while (msg < end && *msg != ' ' && *msg != '\t')
        ++msg;
    while (msg < end && (*msg == ' ' || *msg == '\t'))
        ++msg;

    if (msg < end) {
        return atol(msg);
    }
    return 0;
}

static const char* internal_find_header(const char* msg, const char* name, const char* shortname,
        bool content)
{
    const char *ptr = msg;
    int namelen = strlen(name);
    int shortnamelen = shortname ? strlen(shortname) : 0;
    /* The first letter, compared before strncasecmp() is called */
    const int first = tolower((unsigned char)*name);
    const int short_first = shortname ? tolower((unsigned char)*shortname) : 0;

    while (1) {
        int is_short = 0;
        const int c = tolower((unsigned char)*ptr);
        /* RFC3261, 7.3.1: When comparing header fields, field names
         * are always case-insensitive.  Unless otherwise stated in
         * the definition of a particular header field, field values,
         * parameter names, and parameter values are case-insensitive.
         * Tokens are always case-insensitive.  Unless specified
         * otherwise, values expressed as quoted strings are case-
         * sensitive.
         *
         * Ergo, strcasecmp, because:
         *   To:...;tag=bla == TO:...;TAG=BLA
         * But:
         *   Warning: "something" != Warning: "SoMeThInG"
         */
        if ((c == first && strncasecmp(ptr, name, namelen) == 0) ||
            (shortname && (is_short = 1) && c == short_first && strncasecmp(ptr, shortname, shortnamelen) == 0)) {
            const char *tmp = ptr + (is_short ? strlen(shortname) : strlen(name));
            while (*tmp == ' ' || *tmp == '\t') {
                ++tmp;
            }
            if (*tmp == ':') {
                /* Found */
                if (content) {
                    /* We just want the content */
                    ptr = internal_skip_lws(tmp + 1);
                }
                break;
            }
        }

        /* Seek to next line, but not past EOH. A message that starts
         * with its newline has no CR before it, nor anything to read. */
        ptr = strchr(ptr, '\n');
        const bool no_cr = ptr && (ptr == msg || ptr[-1] != '\r');
        if (!ptr || no_cr || (ptr[1] == '\r' && ptr[2] == '\n')) {
            if (no_cr) {
                WARNING("Missing CR during header scan at pos %d", int(ptr - msg));
                /* continue? */
            }
            return nullptr;
        }
        ++ptr;
    }

    return ptr;
}

static const char* internal_hdrchr(const char* ptr, const char needle)
{
    if (*ptr == '\n') {
        return nullptr; /* stray LF */
    }

    while (1) {
        if (*ptr == '\0') {
            return nullptr;
        } else if (*ptr == needle) {
            return ptr;
        } else if (*ptr == '\n') {
            if (ptr[-1] == '\r' && ptr[1] != ' ' && ptr[1] != '\t') {
                return nullptr; /* end of header */
            }
        }
        ++ptr;
    }

    return nullptr; /* never gets here */
}

static const char* internal_hdrend(const char* ptr)
{
    const char *p = ptr;
    while (*p) {
        if (p[0] == '\r' && p[1] == '\n' && (p[2] != ' ' && p[2] != '\t')) {
            return p;
        }
        ++p;
    }
    return p;
}

static const char* internal_find_param(const char* ptr, const char* name)
{
    int namelen = strlen(name);

    while (1) {
        ptr = internal_hdrchr(ptr, ';');
        if (!ptr) {
            return nullptr;
        }
        ++ptr;

        ptr = internal_skip_lws(ptr);
        if (!ptr || !*ptr) {
            return nullptr;
        }

        /* Case insensitive, see RFC 3261 7.3.1 notes above. */
        if (strncasecmp(ptr, name, namelen) == 0 && *(ptr + namelen) == '=') {
            ptr += namelen + 1;
            return ptr;
        }
    }

    return nullptr; /* never gets here */
}

static const char* internal_skip_lws(const char* ptr)
{
    while (1) {
        while (*ptr == ' ' || *ptr == '\t') {
            ++ptr;
        }
        if (ptr[0] == '\r' && ptr[1] == '\n') {
            if (ptr[2] == ' ' || ptr[2] == '\t') {
                ptr += 3;
                continue;
            }
            return nullptr; /* end of this header */
        }
        return ptr;
    }
    return nullptr; /* never gets here */
}


#ifdef GTEST
#include "gtest/gtest.h"
#include <string>

TEST(Parser, internal_find_header) {
    char data[] = "OPTIONS sip:server SIP/2.0\r\n"
"Took: abc1\r\n"
"To k: abc2\r\n"
"To\t :\r\n abc3\r\n"
"From: def\r\n"
"\r\n";
    const char *eq = strstr(data, "To\t :");
    EXPECT_EQ(eq, internal_find_header(data, "To", "t", false));
    EXPECT_STREQ(eq + 8, internal_find_header(data, "To", "t", true));
}

TEST(Parser, internal_find_header_no_callid_missing_cr_in_to) {
    char data[4096];
    const char *pos;
    const char *p;

    /* If you remove the CR ("\r") from any header before the Call-ID,
     * the Call-ID will not be found. */
    strncpy(data, "INVITE sip:3136455552@85.12.1.1:5065 SIP/2.0\r\n\
Via: SIP/2.0/UDP 85.55.55.12:5060;branch=z9hG4bK831a.2bb3de85.0\r\n\
From: \"3136456666\" <sip:104@sbc.profxxx.xx>;tag=b62e0d72-be14-4d3c-bd6a-b4da593b6b17\r\n\
To: <sip:3136455552@sbc2.profxxx.xx>\n\
Contact: <sip:85.55.55.12;did=a19.a2e590e>\r\n\
Call-ID: DLGCH_K0IEXzVwYzJiQlwKMGRkMX5GSAxiKmJ+exQADWYsZ2QsFQFb\r\n\
CSeq: 6476 INVITE\r\n\
Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE, REFER\r\n\
Supported: 100rel, timer, replaces, norefersub\r\n\
Session-Expires: 1800\r\n\
Min-SE: 90\r\n\
Max-Forwards: 70\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 278\r\n\
\r\n\
v=0\r\n\
o=- 592907310 592907310 IN IP4 85.55.55.30\r\n\
s=Centrex v.1.0\r\n\
c=IN IP4 85.55.55.30\r\n\
t=0 0\r\n\
m=audio 41604 RTP/AVP 8 0 101\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n\
a=ptime:20\r\n\
a=maxptime:150\r\n\
a=sendrecv\r\n\
a=rtcp:41605\r\n\
", sizeof(data) - 1);

    if ((pos = internal_find_header(data, "Call-ID", "i", false)) && (p = strchr(pos, '\r'))) {
        data[p - data] = '\0';
        /* Unexpected.. */
        ASSERT_FALSE(1);
        EXPECT_STREQ(pos, "Call-ID: DLGCH_K0IEXzVwYzJiQlwKMGRkMX5GSAxiKmJ+exQADWYsZ2QsFQFb");
    } else {
        /* Not finding any, because of missing CR. */
        ASSERT_TRUE(1);
    }
}

TEST(Parser, get_header_mixed_form) {
    const char* data = "INVITE sip:3136455552@85.12.1.1:5065 SIP/2.0\r\n\
v: SIP/2.0/UDP 85.55.55.12:6090;branch=z9hG4bK831a.2bb3de85.0\r\n\
Via: SIP/2.0/UDP 85.55.55.12:5090;branch=z9hG4bK831a.2bb3de85.0\r\n\
Via:SIP/2.0/UDP 85.55.55.12:5060;branch=z9hG4bK831a.2bb3de87.0\r\n\
v: SIP/2.0/UDP 85.55.55.12:4060;branch=z9hG4bK831a.2bb3de86.0\r\n\
v:SIP/2.0/UDP 85.55.55.12:4050;branch=z9hG4bK831a.2bb3de86.0\r\n\
Record-Route: <sip:85.55.55.12:5090;r2=on;lr>\r\n\
Record-Route: <sip:10.231.33.44;r2=on;lr>\r\n\
Record-Route: <sip:10.231.33.77;lr=on>\r\n\
From: \"3136456666\" <sip:104@sbc.profxxx.xx>;tag=b62e0d72-be14-4d3c-bd6a-b4da593b6b17\r\n\
To: <sip:3136455552@sbc2.profxxx.xx>\r\n\
Contact: <sip:12999999999@85.55.55.12;did=a19.a2e590e>\r\n\
Call-ID: DLGCH_K0IEXzVwYzJiQlwKMGRkMX5GSAxiKmJ+exQADWYsZ2QsFQFb\r\n\
CSeq: 6476 INVITE\r\n\
Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, MESSAGE, REFER\r\n\
Supported: 100rel, timer, replaces, norefersub\r\n\
Session-Expires: 1800\r\n\
Min-SE: 90\r\n\
Max-Forwards: 70\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 278\r\n\
\r\n\
v=0\r\n\
o=- 592907310 592907310 IN IP4 85.55.55.30\r\n\
s=Centrex v.1.0\r\n\
c=IN IP4 85.55.55.30\r\n\
t=0 0\r\n\
m=audio 41604 RTP/AVP 8 0 101\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=fmtp:101 0-16\r\n\
a=ptime:20\r\n\
a=maxptime:150\r\n\
a=sendrecv\r\n\
a=rtcp:41605\r\n\
";
    EXPECT_EQ("Via: SIP/2.0/UDP 85.55.55.12:6090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5060;branch=z9hG4bK831a.2bb3de87.0, \
SIP/2.0/UDP 85.55.55.12:4060;branch=z9hG4bK831a.2bb3de86.0, \
SIP/2.0/UDP 85.55.55.12:4050;branch=z9hG4bK831a.2bb3de86.0",
              get_header(data, "Via:", false).view());

    EXPECT_EQ("SIP/2.0/UDP 85.55.55.12:6090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5060;branch=z9hG4bK831a.2bb3de87.0, \
SIP/2.0/UDP 85.55.55.12:4060;branch=z9hG4bK831a.2bb3de86.0, \
SIP/2.0/UDP 85.55.55.12:4050;branch=z9hG4bK831a.2bb3de86.0",
              get_header(data, "Via:", true).view());

    EXPECT_EQ("Record-Route: <sip:85.55.55.12:5090;r2=on;lr>, \
<sip:10.231.33.44;r2=on;lr>, \
<sip:10.231.33.77;lr=on>",
              get_header(data, "Record-Route:", false).view());

    EXPECT_EQ("<sip:85.55.55.12:5090;r2=on;lr>, \
<sip:10.231.33.44;r2=on;lr>, \
<sip:10.231.33.77;lr=on>",
              get_header(data, "Record-Route:", true).view());

    EXPECT_EQ("<sip:12999999999@85.55.55.12;did=a19.a2e590e>", get_header(data, "Contact:", true).view());
}

TEST(Parser, get_header_folded)
{
    const char *data = "SIP/2.0 200 OK\r\n"
                       "Subject: first part\r\n"
                       "\tsecond part\r\n"
                       "To: <sip:b@example.com>\r\n"
                       "\r\n";
    EXPECT_EQ("Subject: first part\r\n\tsecond part", get_header(data, "Subject:", false).view());
    EXPECT_EQ("first part\r\n\tsecond part", get_header(data, "Subject:", true).view());
    EXPECT_EQ("<sip:b@example.com>", get_header(data, "To:", true).view());
}

TEST(Parser, get_header_folded_last)
{
    /* A folded header just before the blank line; a doubled CR in it
     * is dropped */
    const char *data = "SIP/2.0 200 OK\r\n"
                       "Subject: first\r\r\n"
                       " second\r\n"
                       "\r\n"
                       "Subject: in the body\r\n";
    EXPECT_EQ("Subject: first\r\n second", get_header(data, "Subject:", false).view());
    EXPECT_EQ("first\r\n second", get_header(data, "Subject:", true).view());
}

TEST(Parser, get_header_compact_name)
{
    /* A compact header is returned under the name asked for */
    const char *data = "SIP/2.0 200 OK\r\n"
                       "v: SIP/2.0/UDP a\r\n"
                       "i: abc\r\n"
                       "\r\n";
    EXPECT_EQ("Via: SIP/2.0/UDP a", get_header(data, "Via:", false).view());
    EXPECT_EQ("abc", get_header(data, "Call-ID:", true).view());
    EXPECT_EQ("abc", get_header(data, "call-id:", true).view());
}

TEST(Parser, get_header_stops_at_body)
{
    const char *data = "SIP/2.0 200 OK\r\n"
                       "To: <sip:b@example.com>\r\n"
                       "Subject:\r\n"
                       "\r\n"
                       "Via: in the body\r\n";
    EXPECT_EQ("", get_header(data, "Via:", true).view());
    EXPECT_EQ("Subject:", get_header(data, "Subject:", false).view());
    EXPECT_EQ("", get_header(data, "Subject:", true).view());
    EXPECT_EQ("<sip:b@example.com>", get_header(data, "To:", true).view());
}

TEST(Parser, get_header_no_blank_line)
{
    const char *data = "SIP/2.0 200 OK\r\n"
                       "To: <sip:b@example.com>  \r\n"
                       "Via: x\r\n"
                       "Via: y";
    EXPECT_EQ("x, y", get_header(data, "Via:", true).view());
    EXPECT_EQ("<sip:b@example.com>", get_header(data, "To:", true).view());
}

TEST(Parser, get_header_spaces)
{
    /* Spaces around a value go, a tab after the colon stays; an empty
     * value is joined without a comma */
    const char *data = "SIP/2.0 200 OK\r\n"
                       "Via:\r\n"
                       "Via:   x  \r\n"
                       "Route: <a>\t\r\n"
                       "Route: \t<b>\r\n"
                       "To:    a\r\n"
                       "\r\n";
    EXPECT_EQ("Via: x", get_header(data, "Via:", false).view());
    EXPECT_EQ("<a>, \t<b>", get_header(data, "Route:", true).view());
    EXPECT_EQ("a", get_header(data, "To:", true).view());
    EXPECT_EQ("To: a", get_header(data, "To:", false).view());
}

TEST(Parser, get_header_oversized_join)
{
    /* Headers are joined while they fit whole; the first that doesn't
     * fit is left out, with the comma before it kept */
    std::string msg = "SIP/2.0 200 OK\r\n";
    std::string joined;
    for (int i = 0; i < 400; ++i) {
        std::string via = "SIP/2.0/UDP h" + std::to_string(1000 + i) + std::string(40, 'x');
        msg += "Via: " + via + "\r\n";
        joined += (i ? ", " : "") + via;
    }
    msg += "\r\n";

    std::string result(get_header(msg.c_str(), "Via:", true).view());
    EXPECT_EQ(20472u, result.size());
    EXPECT_EQ(joined.substr(0, result.size()), result);
    EXPECT_EQ(',', result.back());
}

/* Whether value is a view into msg */
static bool in_place(const header_value &value, const char *msg)
{
    return value.view().data() >= msg && value.view().data() <= msg + strlen(msg);
}

TEST(Parser, get_header_in_place)
{
    /* One header on one line is returned where it is, but for the
     * spaces, tabs and CRs after it */
    const char *data = "SIP/2.0 200 OK\r\n"
                       "Via: SIP/2.0/UDP a  \t\r\n"
                       "To:   <sip:b@example.com>\r\n"
                       "Subject: first\r\n"
                       " second\r\n"
                       "\r\n";
    const header_value via = get_header(data, "Via:", false);
    EXPECT_EQ("Via: SIP/2.0/UDP a", via.view());
    EXPECT_TRUE(in_place(via, data));
    EXPECT_TRUE(in_place(get_header_content(data, "Via:"), data));
    EXPECT_TRUE(in_place(get_header_content(data, "To:"), data));
    EXPECT_TRUE(in_place(get_header_content(data, "Subject:"), data));
    EXPECT_TRUE(in_place(get_header(data, "Subject:", false), data));
    EXPECT_EQ("Subject: first\r\n second", get_header(data, "Subject:", false).view());

    /* With the name asked for and one space before the value: a text
     * of its own otherwise */
    EXPECT_EQ("To: <sip:b@example.com>", get_header(data, "To:", false).view());
    EXPECT_FALSE(in_place(get_header(data, "To:", false), data));
    EXPECT_EQ("via: SIP/2.0/UDP a", get_header(data, "via:", false).view());
    EXPECT_FALSE(in_place(get_header(data, "via:", false), data));
    EXPECT_EQ("SIP/2.0/UDP a", get_header_content(data, "via:").view());
    EXPECT_TRUE(in_place(get_header_content(data, "via:"), data));
}

TEST(Parser, get_header_odd_forms)
{
    EXPECT_EQ("Via: x", get_header("SIP/2.0 200 OK\r\nVia:x\r\n\r\n", "Via:", false).view());
    EXPECT_EQ("Via: x", get_header("SIP/2.0 200 OK\r\nvia: x\r\n\r\n", "Via:", false).view());
    /* An empty value before another is joined with a comma */
    EXPECT_EQ(", x", get_header_content("SIP/2.0 200 OK\r\nVia:\r\nVia: x\r\n\r\n", "Via:").view());
    /* A lone CR stays, a doubled one goes */
    EXPECT_EQ("a\rb", get_header_content("SIP/2.0 200 OK\r\nVia: a\rb\r\n\r\n", "Via:").view());
    EXPECT_EQ("a\rb", get_header_content("SIP/2.0 200 OK\r\nVia: a\r\rb\r\n\r\n", "Via:").view());
    /* The first character of a value stays */
    EXPECT_EQ("\t", get_header_content("SIP/2.0 200 OK\r\nTo: \t\r\n\r\n", "To:").view());
    EXPECT_EQ("To:", get_header("SIP/2.0 200 OK\r\nTo: \t\r\n\r\n", "To:", false).view());
    /* The value starts after the first colon */
    EXPECT_EQ("X:Y: Y: z", get_header("SIP/2.0 200 OK\r\nX:Y: z\r\n\r\n", "X:Y:", false).view());
    EXPECT_EQ("", get_header("SIP/2.0 200 OK\r\nVia: x\r\n\r\n", "Via", false).view());
}

TEST(Parser, get_header_oversized_name_form)
{
    /* A value too long for the name before it is left out */
    std::string msg = "SIP/2.0 200 OK\r\nSubject: " + std::string(MAX_HEADER_LEN * 10, 'A') + "\r\n\r\n";
    EXPECT_EQ("Subject:", get_header(msg.c_str(), "Subject:", false).view());
}

TEST(Parser, header_number)
{
    for (const char *text : {"0", "129", "  42 INVITE", "\t7", "+5", "-3", "+-5", "--5", "+", "-", "", "x1",
                             "99999999999999999999", "-99999999999999999999", "007", "12abc", "0x1A"}) {
        EXPECT_EQ(strtol(text, nullptr, 10), header_number(text)) << text;
    }
    /* Only the characters of the view */
    EXPECT_EQ(12, header_number(std::string_view("1234", 2)));
}

TEST(Parser, get_header_last) {
    const char* data = "INVITE sip:3136455552@85.12.1.1:5065 SIP/2.0\r\n\
From: SIP/2.0/UDP 85.55.55.12:6090;branch=z9hG4bK831a.2bb3de85.0\r\n\
\r\n\
";
    EXPECT_EQ("", get_header(data, "Via:", false).view());
}

TEST(Parser, get_header_oversized_single) {
    /* A single header whose content is larger than the static
     * last_header[MAX_HEADER_LEN * 10] buffer must be truncated, not
     * overflowed. Run under ASan/Valgrind this catches the overflow;
     * everywhere it asserts the result stays within the buffer. */
    std::string msg = "SIP/2.0 200 OK\r\nSubject: ";
    msg += std::string(MAX_HEADER_LEN * 12, 'A');
    msg += "\r\n\r\n";

    const header_value result = get_header(msg.c_str(), "Subject:", true);
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result.view()[0], 'A');
    EXPECT_EQ(result.view(), std::string(MAX_HEADER_LEN * 10 - 1, 'A'));
}

TEST(Parser, get_header_oversized_repeated) {
    /* Many repeated headers whose concatenated content exceeds the
     * buffer must be truncated, not overflowed. */
    std::string msg = "SIP/2.0 200 OK\r\n";
    for (int i = 0; i < 500; ++i) {
        msg += "Via: SIP/2.0/UDP host" + std::to_string(i) +
               ".example.com:5060;branch=z9hG4bK" +
               std::string(50, 'x') + "\r\n";
    }
    msg += "\r\n";

    const header_value result = get_header(msg.c_str(), "Via:", true);
    EXPECT_LT(result.view().size(), (size_t)(MAX_HEADER_LEN * 10));
}

TEST(Parser, get_peer_tag__notag) {
    EXPECT_FALSE(get_peer_tag("...\r\nTo: <abc>\r\n;tag=notag\r\n\r\n"));
}

TEST(Parser, get_peer_tag__normal) {
    EXPECT_EQ("normal", get_peer_tag("...\r\nTo: <abc>;t2=x;tag=normal;t3=y\r\n\r\n").value_or("(none)"));
}

TEST(Parser, get_peer_tag__upper) {
    EXPECT_EQ("upper", get_peer_tag("...\r\nTo: <abc>;t2=x;TAG=upper;t3=y\r\n\r\n").value_or("(none)"));
}

TEST(Parser, get_peer_tag__normal_2) {
    EXPECT_EQ("normal2", get_peer_tag("...\r\nTo: abc;tag=normal2\r\n\r\n").value_or("(none)"));
}

TEST(Parser, get_peer_tag__folded) {
    EXPECT_EQ("folded", get_peer_tag("...\r\nTo: <abc>\r\n ;tag=folded\r\n\r\n").value_or("(none)"));
}

TEST(Parser, get_peer_tag__space) {
    EXPECT_EQ("space", get_peer_tag("...\r\nTo: <abc> ;tag=space\r\n\r\n").value_or("(none)"));
}

TEST(Parser, get_peer_tag__space_2) {
    EXPECT_EQ("space2", get_peer_tag("...\r\nTo \t:\r\n abc\r\n ;tag=space2\r\n\r\n").value_or("(none)"));
}

TEST(Parser, get_call_id_1) {
    EXPECT_EQ("test1", get_call_id("...\r\nCall-ID: test1\r\n\r\n"));
}

TEST(Parser, get_call_id_2) {
    EXPECT_EQ("test2", get_call_id("...\r\nCALL-ID:\r\n test2\r\n\r\n"));
}

TEST(Parser, get_call_id_3) {
    EXPECT_EQ("test3", get_call_id("...\r\ncall-id:\r\n\t    test3\r\n\r\n"));
}

TEST(Parser, get_call_id_leading_newline)
{
    /* The byte before the message is not read */
    const char buf[] = "\r\nCall-ID: test4\r\n\r\n";
    EXPECT_EQ("", get_call_id(buf + 1));
}

TEST(Parser, get_call_id_short_1) {
    EXPECT_EQ("testshort1", get_call_id("...\r\ni: testshort1\r\n\r\n"));
}

TEST(Parser, get_call_id_short_2) {
    /* The WS surrounding the colon belongs with HCOLON, but the
     * trailing WS does not. */
    EXPECT_EQ("testshort2 \t ", get_call_id("...\r\nI:\r\n \r\n \t testshort2 \t \r\n\r\n"));
}

TEST(Parser, get_peer_tag__empty)
{
    /* A tag with no value is there, unlike none */
    EXPECT_EQ("", get_peer_tag("...\r\nTo: <abc>;tag=\r\n\r\n").value_or("(none)"));
    EXPECT_FALSE(get_peer_tag("...\r\nTo: <abc>\r\n\r\n"));
    EXPECT_FALSE(get_peer_tag("...\r\nFrom: <abc>;tag=x\r\n\r\n"));
}

TEST(Parser, get_peer_tag__long)
{
    /* At most MAX_HEADER_LEN - 1 characters */
    std::string msg = "...\r\nTo: <abc>;tag=" + std::string(MAX_HEADER_LEN + 10, 'x') + "\r\n\r\n";
    EXPECT_EQ(std::string(MAX_HEADER_LEN - 1, 'x'), get_peer_tag(msg.c_str()).value_or("(none)"));
}

TEST(Parser, get_call_id_too_long)
{
    std::string id(MAX_HEADER_LEN - 1, 'a');
    EXPECT_EQ(id, get_call_id(("...\r\nCall-ID: " + id + "\r\n\r\n").c_str()));
    EXPECT_EQ("", get_call_id(("...\r\nCall-ID: " + id + "a\r\n\r\n").c_str()));
    EXPECT_EQ("", get_call_id("...\r\nTo: <abc>\r\n\r\n"));
}

TEST(Parser, get_first_line)
{
    EXPECT_EQ("SIP/2.0 200 OK", get_first_line("SIP/2.0 200 OK\r\nTo: <abc>\r\n\r\n"));
    EXPECT_EQ("INVITE sip:a SIP/2.0", get_first_line("INVITE sip:a SIP/2.0\nTo: <abc>\r\n"));
    EXPECT_EQ("OPTIONS", get_first_line("OPTIONS"));
    EXPECT_EQ("", get_first_line("\r\nTo: <abc>\r\n"));
    EXPECT_EQ("", get_first_line(""));
}

TEST(Parser, get_reply_code)
{
    EXPECT_EQ(200u, get_reply_code("SIP/2.0 200 OK\r\n\r\n"));
    EXPECT_EQ(0u, get_reply_code("INVITE sip:a SIP/2.0\r\n\r\n"));
    /* Not past the end of a message without a blank */
    const char data[] = "SIP/2.0\r\n\r\n\0 486";
    EXPECT_EQ(0u, get_reply_code(data));
    /* Nor past its first line */
    EXPECT_EQ(0u, get_reply_code("SIP/2.0\r\nX-Pad: x 486\r\n\r\n"));
    EXPECT_EQ(0u, get_reply_code("SIP/2.0 abc\r\n\r\n"));
    EXPECT_EQ(0u, get_reply_code("SIP/2.0"));
    EXPECT_EQ(180u, get_reply_code("SIP/2.0\t180 Ringing"));
}

TEST(Parser, get_short_header_via) {
    EXPECT_STREQ("\nv:", internal_compact_header_name("Via:"));
    EXPECT_STREQ("\nm:", internal_compact_header_name("Contact:"));
}

/* The 3pcc-A script sends "invalid" SIP that is parsed by this
 * sip_parser.  We must accept headers without any leading request/
 * response line:
 *
 *   <sendCmd>
 *     <![CDATA[
 *       Call-ID: [call_id]
 *       [$1]
 *     ]]>
 *   </sendCmd>
 */
TEST(Parser, get_call_id_github_0101) { // github-#0101
    const char *input =
        "Call-ID: 1-18220@127.0.0.1\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length:   129\r\n\r\n"
        "v=0\r\no=user1 53655765 2353687637 IN IP4 127.0.0.1\r\n"
        "s=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
        "m=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000";
    EXPECT_EQ("1-18220@127.0.0.1", get_call_id(input));
}

#endif //GTEST
