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

#include <string.h>
#include <stdlib.h>

#include "screen.hpp"
#include "strings.hpp"
#include "sip_parser.hpp"

/*************************** Mini SIP parser (internals) ***************/

/*
 * SIP ABNF can be found here:
 *   http://tools.ietf.org/html/rfc3261#section-25
 * In 2014, there is a very helpful site that lets you browse the ABNF
 * easily:
 *   http://www.in2eps.com/fo-abnf/tk-fo-abnf-sip.html
 */

static const char *internal_find_param(const char *ptr, const char *name);
static const char *internal_find_header(const char *msg, const char *name,
        const char *shortname, bool content);
static const char *internal_skip_lws(const char *ptr);

/* Search for a character, but only inside this header. Returns NULL if
 * not found. */
static const char *internal_hdrchr(const char *ptr, const char needle);

/* Seek to end of this header. Returns the position the next character,
 * which must be at the header-delimiting-CRLF or, if the message is
 * broken, at the ASCIIZ NUL. */
static const char *internal_hdrend(const char *ptr);

/*************************** Mini SIP parser (externals) ***************/

char * get_peer_tag(const char *msg)
{
    static char   tag[MAX_HEADER_LEN];
    const char  * to_hdr;
    const char  * ptr;
    int           tag_i = 0;

    /* Find start of header */
    to_hdr = internal_find_header(msg, "To", "t", true);
    if (!to_hdr) {
        WARNING("No valid To: header in reply");
        return NULL;
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
        return NULL;
    }

    while (*ptr && *ptr != ' ' && *ptr != ';' && *ptr != '\t' &&
           *ptr != '\r' && *ptr != '\n') {
        tag[tag_i++] = *(ptr++);
    }
    tag[tag_i] = '\0';

    return tag;
}

char * get_header_content(const char* message, const char * name)
{
    return get_header(message, name, true);
}

/* If content is true, we only return the header's contents. */
char * get_header(const char* message, const char * name, bool content)
{
    /* non reentrant. consider accepting char buffer as param */
    static char last_header[MAX_HEADER_LEN * 10];
    char *src, *src_orig, *dest, *start, *ptr;
    /* Are we searching for a short form header? */
    bool short_form = false;
    bool first_time = true;
    char header_with_newline[MAX_HEADER_LEN + 1];

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

    src_orig = strdup(message);

    do {
        /* We want to start from the beginning of the message each time
         * through this loop, because we may be searching for a short form. */
        src = src_orig;

        snprintf(header_with_newline, MAX_HEADER_LEN, "\n%s", name);
        dest = last_header;

        while ((src = strcasestr2(src, header_with_newline))) {
            if (content || !first_time) {
                /* Just want the header's content, so skip over the header
                 * and newline */
                src += strlen(name) + 1;
            } else {
                /* Just skip the newline */
                src++;
            }
            first_time = false;
            ptr = strchr(src, '\n');

            /* Multiline headers always begin with a tab or a space
             * on the subsequent lines. Skip those lines. */
            while (ptr && (*(ptr+1) == ' ' || *(ptr+1) == '\t')) {
                ptr = strchr(ptr + 1, '\n');
            }

            if (ptr) {
                *ptr = 0;
            }
            // Add "," when several headers are present
            if (dest != last_header) {
                /* Remove trailing whitespaces, tabs, and CRs */
                while (dest > last_header &&
                       (*(dest-1) == ' ' ||
                        *(dest-1) == '\r' ||
                        *(dest-1) == '\n' ||
                        *(dest-1) == '\t')) {
                    *(--dest) = 0;
                }

                dest += sprintf(dest, ",");
            }
            dest += sprintf(dest, "%s", src);
            if (ptr) {
                *ptr = '\n';
            }

            src++;
        }
        /* We found the header. */
        if (dest != last_header) {
            break;
        }
        /* We didn't find the header, even in its short form. */
        if (short_form) {
            free(src_orig);
            return last_header;
        }

        /* We should retry with the short form. */
        short_form = true;
        if (!strcasecmp(name, "call-id:")) {
            name = "i:";
        } else if (!strcasecmp(name, "contact:")) {
            name = "m:";
        } else if (!strcasecmp(name, "content-encoding:")) {
            name = "e:";
        } else if (!strcasecmp(name, "content-length:")) {
            name = "l:";
        } else if (!strcasecmp(name, "content-type:")) {
            name = "c:";
        } else if (!strcasecmp(name, "from:")) {
            name = "f:";
        } else if (!strcasecmp(name, "to:")) {
            name = "t:";
        } else if (!strcasecmp(name, "via:")) {
            name = "v:";
        } else {
            /* There is no short form to try. */
            free(src_orig);
            return last_header;
        }
    } while (1);

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
    while ((ptr = strstr(last_header, "\r\n")) != NULL &&
           (*(ptr + 2) == ' ' || *(ptr + 2) == '\r' || *(ptr + 2) == '\t')) {
        /* Use strlen(ptr) to include trailing zero */
        memmove(ptr, ptr+1, strlen(ptr));
    }

    /* Remove illegal double CR characters */
    while ((ptr = strstr(last_header, "\r\r")) != NULL) {
        memmove(ptr, ptr+1, strlen(ptr));
    }
    /* Remove illegal double Newline characters */
    while ((ptr = strstr(last_header, "\n\n")) != NULL) {
        memmove(ptr, ptr+1, strlen(ptr));
    }

    free(src_orig);
    return start;
}

char * get_first_line(const char * message)
{
    /* non reentrant. consider accepting char buffer as param */
    static char last_header[MAX_HEADER_LEN * 10];
    const char * src;

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

char * get_call_id(const char *msg)
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

unsigned long int get_cseq_value(char *msg)
{
    char *ptr1;


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

    return strtoul(ptr1, NULL, 10);
}

unsigned long get_reply_code(char *msg)
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

static const char *internal_find_header(const char *msg, const char *name, const char *shortname,
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
            return NULL;
        }
        ++ptr;
    }

    return ptr;
}

static const char *internal_hdrchr(const char *ptr, const char needle)
{
    if (*ptr == '\n') {
        return NULL; /* stray LF */
    }

    while (1) {
        if (*ptr == '\0') {
            return NULL;
        } else if (*ptr == needle) {
            return ptr;
        } else if (*ptr == '\n') {
            if (ptr[-1] == '\r' && ptr[1] != ' ' && ptr[1] != '\t') {
                return NULL; /* end of header */
            }
        }
        ++ptr;
    }

    return NULL; /* never gets here */
}

static const char *internal_hdrend(const char *ptr)
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

static const char *internal_find_param(const char *ptr, const char *name)
{
    int namelen = strlen(name);

    while (1) {
        ptr = internal_hdrchr(ptr, ';');
        if (!ptr) {
            return NULL;
        }
        ++ptr;

        ptr = internal_skip_lws(ptr);
        if (!ptr || !*ptr) {
            return NULL;
        }

        /* Case insensitive, see RFC 3261 7.3.1 notes above. */
        if (strncasecmp(ptr, name, namelen) == 0 && *(ptr + namelen) == '=') {
            ptr += namelen + 1;
            return ptr;
        }
    }

    return NULL; /* never gets here */
}

static const char *internal_skip_lws(const char *ptr)
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
            return NULL; /* end of this header */
        }
        return ptr;
    }
    return NULL; /* never gets here */
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

TEST(Parser, get_peer_tag__notag) {
    EXPECT_STREQ(NULL, get_peer_tag("...\r\nTo: <abc>\r\n;tag=notag\r\n\r\n"));
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
