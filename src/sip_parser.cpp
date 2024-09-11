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

#include <stdlib.h>
#include <string.h>

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

static const char* internal_compact_header_name(const char* name);
static char* internal_match_header(char* message, const char* hdr, const char* compact_hdr);


/*************************** Mini SIP parser (externals) ***************/

char* get_peer_tag(const char* msg)
{
    static char   tag[MAX_HEADER_LEN];
    const char  * to_hdr;
    const char  * ptr;
    int           tag_i = 0;

    /* Find start of header */
    to_hdr = internal_find_header(msg, "To", "t", true);
    if (!to_hdr) {
        WARNING("No valid To: header in reply");
        return nullptr;
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
        return nullptr;
    }

    while (*ptr && *ptr != ' ' && *ptr != ';' && *ptr != '\t' &&
           *ptr != '\r' && *ptr != '\n') {
        tag[tag_i++] = *(ptr++);
    }
    tag[tag_i] = '\0';

    return tag;
}

char* get_header_content(const char* message, const char* name)
{
    return get_header(message, name, true);
}

/* If content is true, we only return the header's contents. */
char* get_header(const char* message, const char* name, bool content)
{
    /* non reentrant. consider accepting char buffer as param */
    static char last_header[MAX_HEADER_LEN * 10];
    const char *cptr;
    char *src, *src_copy, *dest, *start, *ptr;
    bool first_time = true;
    char header_with_newline[MAX_HEADER_LEN + 1];

    const char* compact_header_with_newline;

    /* returns empty string in case of error */
    last_header[0] = '\0';

    if (!message || !*message) {
        return last_header;
    }

    /* for safety's sake */
    if (!name || !strrchr(name, ':')) {
        WARNING("Can not search for header (no colon): %s", name ? name : "(null)");
        return last_header;
    }

    snprintf(header_with_newline, MAX_HEADER_LEN, "\n%s", name);
    compact_header_with_newline = internal_compact_header_name(name);

    /* find end of SIP headers - perform search only until that */
    cptr = strstr(message, "\r\n\r\n");
    if (!cptr) {
        src_copy = strdup(message);
    } else if ((src_copy = (char*)malloc(cptr - message + 1))) {
        src_copy[cptr - message] = '\0';
        memcpy(src_copy, message, cptr - message);
    }
    if (!src_copy) {
        ERROR("Out of memory");
        return last_header;
    }

    src = src_copy;
    dest = last_header;

    while ((src = internal_match_header(
            src, header_with_newline, compact_header_with_newline))) {
        if (!content && first_time) {
            // Add the name to the string;
            dest += sprintf(dest, "%s", name);
            first_time = false;
        }

        if (content || !first_time) {
            /* Just want the header's content, so skip over the header
             * and newline */

            /* Skip over header */
            while (*src != ':') {
                src++;
            }
            src++;

            /* Skip over leading spaces. */
            while (*src == ' ') {
                src++;
            }
        } else {
            /* Just skip the newline */
            src++;
        }
        ptr = strchr(src, '\n');

        /* Multiline headers always begin with a tab or a space
         * on the subsequent lines. Skip those lines. */
        while (ptr && (*(ptr+1) == ' ' || *(ptr+1) == '\t')) {
            ptr = strchr(ptr + 1, '\n');
        }

        if (ptr) {
            *ptr = 0;
        }
        // Add ", " when several headers are present
        if (dest != last_header) {
            /* Remove trailing whitespaces, tabs, and CRs */
            while (dest > last_header &&
                   (*(dest-1) == ' ' ||
                    *(dest-1) == '\r' ||
                    *(dest-1) == '\n' ||
                    *(dest-1) == '\t')) {
                *(--dest) = 0;
            }

            if (*(dest-1) == ':') {
                dest += sprintf(dest, " ");
            } else {
                dest += sprintf(dest, ", ");
            }
        }
        dest += sprintf(dest, "%s", src);

        if (ptr) {
            *ptr = '\n';
        }

        src++;
    }

    /* No header found? */
    if (dest == last_header) {
        free(src_copy);
        return last_header;
    }

    *(dest--) = 0;

    /* Remove trailing whitespaces, tabs, and CRs */
    while (dest > last_header &&
           (*dest == ' ' || *dest == '\r' || *dest == '\t')) {
        *(dest--) = 0;
    }

    /* Remove leading whitespaces */
    for (start = last_header; *start == ' '; start++);

    /* remove enclosed CRs in multilines */
    /* don't remove enclosed CRs for multiple headers (e.g. Via) (Rhys) */
    while ((ptr = strstr(last_header, "\r\n")) != nullptr &&
           (*(ptr + 2) == ' ' || *(ptr + 2) == '\r' || *(ptr + 2) == '\t')) {
        /* Use strlen(ptr) to include trailing zero */
        memmove(ptr, ptr+1, strlen(ptr));
    }

    /* Remove illegal double CR characters */
    while ((ptr = strstr(last_header, "\r\r")) != nullptr) {
        memmove(ptr, ptr+1, strlen(ptr));
    }
    /* Remove illegal double Newline characters */
    while ((ptr = strstr(last_header, "\n\n")) != nullptr) {
        memmove(ptr, ptr+1, strlen(ptr));
    }

    free(src_copy);
    return start;
}

char* internal_match_header(char* message, const char* hdr, const char* compact_hdr) {
    // Attempt to find the header
    char* header_match = strcasestr(message, hdr);
    if (!compact_hdr) {
        // Exit when there is no compact header to compare to
        return header_match;
    }

    char* compact_header_match = strcasestr(message, compact_hdr);

    // Return the other if one is null
    if (header_match == nullptr) {
        return compact_header_match;
    }
    if (compact_header_match == nullptr) {
        return header_match;
    }

    // Value exists return the smaller of the two.
    if (header_match < compact_header_match) {
        return header_match;
    }

    return compact_header_match;
}

const char* internal_compact_header_name(const char* name)
{
    if (!strcasecmp(name, "call-id:")) {
        return "\ni:";
    } else if (!strcasecmp(name, "contact:")) {
        return "\nm:";
    } else if (!strcasecmp(name, "content-encoding:")) {
        return "\ne:";
    } else if (!strcasecmp(name, "content-length:")) {
        return "\nl:";
    } else if (!strcasecmp(name, "content-type:")) {
        return "\nc:";
    } else if (!strcasecmp(name, "from:")) {
        return "\nf:";
    } else if (!strcasecmp(name, "to:")) {
        return "\nt:";
    } else if (!strcasecmp(name, "via:")) {
        return "\nv:";
    }
    return nullptr;
}

char* get_first_line(const char* message)
{
    /* non reentrant. consider accepting char buffer as param */
    static char last_header[MAX_HEADER_LEN * 10];
    const char* src;

    /* returns empty string in case of error */
    memset(last_header, 0, sizeof(last_header));

    if (!message || !*message) {
        return last_header;
    }

    src = message;

    int i=0;
    while (*src) {
        if (*src == '\n' || *src == '\r') {
            break;
        }
        last_header[i] = *src;
        i++;
        src++;
    }

    return last_header;
}

char* get_call_id(const char* msg)
{
    static char call_id[MAX_HEADER_LEN];
    const char *content, *end_of_header;
    unsigned length;

    call_id[0] = '\0';

    content = internal_find_header(msg, "Call-ID", "i", true);
    if (!content) {
        WARNING("(1) No valid Call-ID: header in reply '%s'", msg);
        return call_id;
    }

    /* Always returns something */
    end_of_header = internal_hdrend(content);
    length = end_of_header - content;
    if (length + 1 > MAX_HEADER_LEN) {
        WARNING("(1) Call-ID: header too long in reply '%s'", msg);
        return call_id;
    }

    memcpy(call_id, content, length);
    call_id[length] = '\0';
    return call_id;
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

unsigned long get_reply_code(const char* msg)
{
    while (msg && *msg != ' ' && *msg != '\t')
        ++msg;
    while (msg && (*msg == ' ' || *msg == '\t'))
        ++msg;

    if (msg && strlen(msg) > 0) {
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

    while (1) {
        int is_short = 0;
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
        if (strncasecmp(ptr, name, namelen) == 0 ||
                (shortname && (is_short = 1) &&
                    strncasecmp(ptr, shortname, shortnamelen) == 0)) {
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

        /* Seek to next line, but not past EOH */
        ptr = strchr(ptr, '\n');
        if (!ptr || ptr[-1] != '\r' || (ptr[1] == '\r' && ptr[2] == '\n')) {
            if (ptr && ptr[-1] != '\r') {
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

TEST(Parser, internal_find_header) {
    char data[] = "OPTIONS sip:server SIP/2.0\r\n"
"Took: abc1\r\n"
"To k: abc2\r\n"
"To\t :\r\n abc3\r\n"
"From: def\r\n"
"\r\n";
    const char *eq = strstr(data, "To\t :");
    EXPECT_STREQ(eq, internal_find_header(data, "To", "t", false));
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
    EXPECT_STREQ("Via: SIP/2.0/UDP 85.55.55.12:6090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5060;branch=z9hG4bK831a.2bb3de87.0, \
SIP/2.0/UDP 85.55.55.12:4060;branch=z9hG4bK831a.2bb3de86.0, \
SIP/2.0/UDP 85.55.55.12:4050;branch=z9hG4bK831a.2bb3de86.0", get_header(data, "Via:", false));

    EXPECT_STREQ("SIP/2.0/UDP 85.55.55.12:6090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5090;branch=z9hG4bK831a.2bb3de85.0, \
SIP/2.0/UDP 85.55.55.12:5060;branch=z9hG4bK831a.2bb3de87.0, \
SIP/2.0/UDP 85.55.55.12:4060;branch=z9hG4bK831a.2bb3de86.0, \
SIP/2.0/UDP 85.55.55.12:4050;branch=z9hG4bK831a.2bb3de86.0", get_header(data, "Via:", true));

    EXPECT_STREQ("Record-Route: <sip:85.55.55.12:5090;r2=on;lr>, \
<sip:10.231.33.44;r2=on;lr>, \
<sip:10.231.33.77;lr=on>", get_header(data, "Record-Route:", false));

    EXPECT_STREQ("<sip:85.55.55.12:5090;r2=on;lr>, \
<sip:10.231.33.44;r2=on;lr>, \
<sip:10.231.33.77;lr=on>", get_header(data, "Record-Route:", true));

    EXPECT_STREQ("<sip:12999999999@85.55.55.12;did=a19.a2e590e>", get_header(data, "Contact:", true));
}

TEST(Parser, get_header_last) {
    const char* data = "INVITE sip:3136455552@85.12.1.1:5065 SIP/2.0\r\n\
From: SIP/2.0/UDP 85.55.55.12:6090;branch=z9hG4bK831a.2bb3de85.0\r\n\
\r\n\
";
    EXPECT_STREQ("", get_header(data, "Via:", false));
}

TEST(Parser, get_peer_tag__notag) {
    EXPECT_STREQ(nullptr, get_peer_tag("...\r\nTo: <abc>\r\n;tag=notag\r\n\r\n"));
}

TEST(Parser, get_peer_tag__normal) {
    EXPECT_STREQ("normal", get_peer_tag("...\r\nTo: <abc>;t2=x;tag=normal;t3=y\r\n\r\n"));
}

TEST(Parser, get_peer_tag__upper) {
    EXPECT_STREQ("upper", get_peer_tag("...\r\nTo: <abc>;t2=x;TAG=upper;t3=y\r\n\r\n"));
}

TEST(Parser, get_peer_tag__normal_2) {
    EXPECT_STREQ("normal2", get_peer_tag("...\r\nTo: abc;tag=normal2\r\n\r\n"));
}

TEST(Parser, get_peer_tag__folded) {
    EXPECT_STREQ("folded", get_peer_tag("...\r\nTo: <abc>\r\n ;tag=folded\r\n\r\n"));
}

TEST(Parser, get_peer_tag__space) {
    EXPECT_STREQ("space", get_peer_tag("...\r\nTo: <abc> ;tag=space\r\n\r\n"));
}

TEST(Parser, get_peer_tag__space_2) {
    EXPECT_STREQ("space2", get_peer_tag("...\r\nTo \t:\r\n abc\r\n ;tag=space2\r\n\r\n"));
}

TEST(Parser, get_call_id_1) {
    EXPECT_STREQ("test1", get_call_id("...\r\nCall-ID: test1\r\n\r\n"));
}

TEST(Parser, get_call_id_2) {
    EXPECT_STREQ("test2", get_call_id("...\r\nCALL-ID:\r\n test2\r\n\r\n"));
}

TEST(Parser, get_call_id_3) {
    EXPECT_STREQ("test3", get_call_id("...\r\ncall-id:\r\n\t    test3\r\n\r\n"));
}

TEST(Parser, get_call_id_short_1) {
    EXPECT_STREQ("testshort1", get_call_id("...\r\ni: testshort1\r\n\r\n"));
}

TEST(Parser, get_call_id_short_2) {
    /* The WS surrounding the colon belongs with HCOLON, but the
     * trailing WS does not. */
    EXPECT_STREQ("testshort2 \t ", get_call_id("...\r\nI:\r\n \r\n \t testshort2 \t \r\n\r\n"));
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
    EXPECT_STREQ("1-18220@127.0.0.1", get_call_id(input));
}

#endif //GTEST
