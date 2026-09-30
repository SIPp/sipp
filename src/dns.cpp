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

#include <algorithm>
#include <cstdlib>
#include <utility>
#include <strings.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "dns.hpp"

static unsigned get16(const unsigned char *p)
{
    return p[0] << 8 | p[1];
}

/* Calls rdata(p, length) on each answer of that type in the DNS message
 * msg, len bytes long: the others, such as the CNAME that led to them,
 * are skipped. False if the message is malformed or rdata returns
 * false. */
template <typename F>
static bool dns_answers(const unsigned char *msg, int len, int type, F rdata)
{
    if (len < NS_HFIXEDSZ) {
        return false;
    }
    const unsigned char *end = msg + len;
    const unsigned char *p = msg + NS_HFIXEDSZ;
    unsigned questions = get16(msg + 4);
    unsigned answers = get16(msg + 6);

    while (questions--) {
        int n = dn_skipname(p, end);
        if (n < 0 || end - p < n + NS_QFIXEDSZ) {
            return false;
        }
        p += n + NS_QFIXEDSZ;
    }

    while (answers--) {
        int n = dn_skipname(p, end);
        if (n < 0 || end - p < n + NS_RRFIXEDSZ) {
            return false;
        }
        p += n;
        int rrtype = get16(p);
        int rrclass = get16(p + 2);
        int rdlength = get16(p + 8);
        p += NS_RRFIXEDSZ;
        if (end - p < rdlength) {
            return false;
        }
        if (rrtype == type && rrclass == ns_c_in && !rdata(p, rdlength)) {
            return false;
        }
        p += rdlength;
    }

    return true;
}

/* The domain name at p, within length bytes, into name; "." for the
 * root. Its length in the message, or -1. */
static int dns_name(const unsigned char *msg, int len, const unsigned char *p,
                    int length, std::string &name)
{
    char buf[NS_MAXDNAME];
    int n = dn_expand(msg, msg + len, p, buf, sizeof(buf));
    if (n < 0 || n > length) {
        return -1;
    }
    name = *buf ? buf : ".";
    return n;
}

/* The <character-string> at p, within length bytes, into s. Its length
 * in the message, or -1. */
static int dns_string(const unsigned char *p, int length, std::string &s)
{
    if (length < 1 || length - 1 < *p) {
        return -1;
    }
    s.assign((const char *)p + 1, *p);
    return 1 + *p;
}

bool naptr_parse(const unsigned char *msg, int len,
                 std::vector<naptr_record> &records)
{
    return dns_answers(msg, len, ns_t_naptr,
                       [&](const unsigned char *p, int length) {
        naptr_record r;
        std::string regexp;
        int n;

        if (length < 4) {
            return false;
        }
        r.order = get16(p);
        r.preference = get16(p + 2);
        p += 4;
        length -= 4;
        for (std::string *s : {&r.flags, &r.service, &regexp}) {
            if ((n = dns_string(p, length, *s)) < 0) {
                return false;
            }
            p += n;
            length -= n;
        }
        if (dns_name(msg, len, p, length, r.replacement) < 0) {
            return false;
        }
        records.push_back(std::move(r));
        return true;
    });
}

bool srv_parse(const unsigned char *msg, int len,
               std::vector<srv_record> &records)
{
    return dns_answers(msg, len, ns_t_srv,
                       [&](const unsigned char *p, int length) {
        srv_record r;

        if (length < 7 || dns_name(msg, len, p + 6, length - 6, r.target) < 0) {
            return false;
        }
        r.priority = get16(p);
        r.weight = get16(p + 2);
        r.port = get16(p + 4);
        records.push_back(std::move(r));
        return true;
    });
}

void naptr_select(std::vector<naptr_record> &records, const char *service)
{
    records.erase(std::remove_if(records.begin(), records.end(),
                                 [&](const naptr_record &r) {
                                     return strcasecmp(r.flags.c_str(), "s") ||
                                            strcasecmp(r.service.c_str(), service) ||
                                            r.replacement == ".";
                                 }),
                  records.end());
    std::stable_sort(records.begin(), records.end(),
                     [](const naptr_record &a, const naptr_record &b) {
                         return a.order != b.order ? a.order < b.order :
                                a.preference < b.preference;
                     });
}

void srv_order(std::vector<srv_record> &records,
               unsigned (*random)(unsigned n))
{
    std::stable_sort(records.begin(), records.end(),
                     [](const srv_record &a, const srv_record &b) {
                         return a.priority < b.priority;
                     });

    auto first = records.begin();
    while (first != records.end()) {
        auto last = first;
        while (last != records.end() && last->priority == first->priority) {
            ++last;
        }
        /* Those of weight 0 first: they are picked only when the random
         * number is 0. */
        std::stable_partition(first, last, [](const srv_record &r) {
            return r.weight == 0;
        });
        for (; first != last; ++first) {
            unsigned sum = 0;
            for (auto r = first; r != last; ++r) {
                sum += r->weight;
            }
            unsigned pick = random(sum);
            auto r = first;
            unsigned running = r->weight;
            while (running < pick && r + 1 != last) {
                running += (++r)->weight;
            }
            std::rotate(first, r, r + 1);
        }
    }
}

/* The answer to a query of name, empty if there is none. */
static std::vector<unsigned char> dns_query(const char *name, int type)
{
    std::vector<unsigned char> answer(NS_MAXMSG);
    int len = res_query(name, ns_c_in, type, answer.data(), answer.size());

    /* What did not fit is cut off: that fails to parse. */
    answer.resize(std::max(0, std::min(len, (int)answer.size())));
    return answer;
}

static unsigned srv_random(unsigned n)
{
    return rand() % (n + 1);
}

std::vector<srv_record> srv_lookup(const char *name)
{
    std::vector<unsigned char> answer = dns_query(name, ns_t_srv);
    std::vector<srv_record> records;

    if (!srv_parse(answer.data(), answer.size(), records)) {
        records.clear();
    }
    srv_order(records, srv_random);
    return records;
}

std::vector<srv_record> sip_srv_lookup(const char *host, const char *service,
                                       const char *prefix, std::string &name,
                                       bool &naptr)
{
    std::vector<unsigned char> answer = dns_query(host, ns_t_naptr);
    std::vector<naptr_record> naptrs;

    if (!naptr_parse(answer.data(), answer.size(), naptrs)) {
        naptrs.clear();
    }
    naptr_select(naptrs, service);
    for (const naptr_record &r : naptrs) {
        std::vector<srv_record> records = srv_lookup(r.replacement.c_str());
        if (!records.empty()) {
            name = r.replacement;
            naptr = true;
            return records;
        }
    }

    naptr = false;
    if (!naptrs.empty()) {
        /* RFC 3263 4.2: "If no SRV records were found, the client
         * performs an A or AAAA record lookup of the domain name." */
        return {};
    }
    /* RFC 3263 4.1: "If no NAPTR records are found, the client
     * constructs SRV queries for those transport protocols it
     * supports". Those for other transports only count as none. */
    name = std::string(prefix) + host;
    return srv_lookup(name.c_str());
}

#ifdef GTEST
#include "gtest/gtest.h"

/* _sip._udp.example.test: a CNAME, then two SRV records whose targets
 * are compressed. The question name is at 12, example.test at 22 and
 * test at 30. */
static const unsigned char srv_answer[] =
    "\x12\x34\x81\x80" "\x00\x01" "\x00\x03" "\x00\x00" "\x00\x00"
    "\x04" "_sip" "\x04" "_udp" "\x07" "example" "\x04" "test" "\x00"
    "\x00\x21" "\x00\x01"
    /* CNAME foo.example.test */
    "\xc0\x0c" "\x00\x05" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x06"
    "\x03" "foo" "\xc0\x16"
    /* SRV 10 60 5060 sip1.example.test */
    "\xc0\x0c" "\x00\x21" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x0d"
    "\x00\x0a" "\x00\x3c" "\x13\xc4" "\x04" "sip1" "\xc0\x16"
    /* SRV 20 0 5678 sip2.test */
    "\xc0\x0c" "\x00\x21" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x0d"
    "\x00\x14" "\x00\x00" "\x16\x2e" "\x04" "sip2" "\xc0\x1e";

TEST(srv, parse) {
    std::vector<srv_record> records;
    ASSERT_TRUE(srv_parse(srv_answer, sizeof(srv_answer) - 1, records));
    ASSERT_EQ(2u, records.size());
    EXPECT_EQ(10, records[0].priority);
    EXPECT_EQ(60, records[0].weight);
    EXPECT_EQ(5060, records[0].port);
    EXPECT_EQ("sip1.example.test", records[0].target);
    EXPECT_EQ(20, records[1].priority);
    EXPECT_EQ(0, records[1].weight);
    EXPECT_EQ(5678, records[1].port);
    EXPECT_EQ("sip2.test", records[1].target);
}

TEST(srv, parse_truncated) {
    for (int len = 0; len < (int)sizeof(srv_answer) - 1; len++) {
        std::vector<srv_record> records;
        EXPECT_FALSE(srv_parse(srv_answer, len, records)) << len;
    }
}

TEST(srv, parse_bad_rdlength) {
    /* An SRV record whose target runs past its data. */
    static const unsigned char msg[] =
        "\x00\x00\x81\x80" "\x00\x00" "\x00\x01" "\x00\x00" "\x00\x00"
        "\x00" "\x00\x21" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x08"
        "\x00\x0a" "\x00\x00" "\x13\xc4" "\x04" "sip1" "\x00";
    std::vector<srv_record> records;
    EXPECT_FALSE(srv_parse(msg, sizeof(msg) - 1, records));
}

TEST(srv, parse_root_target) {
    static const unsigned char msg[] =
        "\x00\x00\x81\x80" "\x00\x00" "\x00\x01" "\x00\x00" "\x00\x00"
        "\x00" "\x00\x21" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x07"
        "\x00\x00" "\x00\x00" "\x00\x00" "\x00";
    std::vector<srv_record> records;
    ASSERT_TRUE(srv_parse(msg, sizeof(msg) - 1, records));
    ASSERT_EQ(1u, records.size());
    EXPECT_EQ(".", records[0].target);
}

/* example.test: NAPTR records, their replacements compressed. The
 * question name is at 12. */
static const unsigned char naptr_answer[] =
    "\x12\x34\x81\x80" "\x00\x01" "\x00\x04" "\x00\x00" "\x00\x00"
    "\x07" "example" "\x04" "test" "\x00" "\x00\x23" "\x00\x01"
    /* 20 10 "s" "SIP+D2U" "" _sip._udp.example.test */
    "\xc0\x0c" "\x00\x23" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x1b"
    "\x00\x14" "\x00\x0a" "\x01" "s" "\x07" "SIP+D2U" "\x00"
    "\x04" "_sip" "\x04" "_udp" "\xc0\x0c"
    /* 10 50 "S" "sip+d2t" "" _sip._tcp.example.test */
    "\xc0\x0c" "\x00\x23" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x1b"
    "\x00\x0a" "\x00\x32" "\x01" "S" "\x07" "sip+d2t" "\x00"
    "\x04" "_sip" "\x04" "_tcp" "\xc0\x0c"
    /* 5 0 "" "SIP+D2U" "" foo.example.test: not terminal */
    "\xc0\x0c" "\x00\x23" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x14"
    "\x00\x05" "\x00\x00" "\x00" "\x07" "SIP+D2U" "\x00"
    "\x03" "foo" "\xc0\x0c"
    /* 1 0 "s" "SIP+D2U" "!x!y!" .: no replacement */
    "\xc0\x0c" "\x00\x23" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x15"
    "\x00\x01" "\x00\x00" "\x01" "s" "\x07" "SIP+D2U" "\x05" "!x!y!"
    "\x00";

TEST(naptr, parse) {
    std::vector<naptr_record> records;
    ASSERT_TRUE(naptr_parse(naptr_answer, sizeof(naptr_answer) - 1, records));
    ASSERT_EQ(4u, records.size());
    EXPECT_EQ(20, records[0].order);
    EXPECT_EQ(10, records[0].preference);
    EXPECT_EQ("s", records[0].flags);
    EXPECT_EQ("SIP+D2U", records[0].service);
    EXPECT_EQ("_sip._udp.example.test", records[0].replacement);
    EXPECT_EQ("_sip._tcp.example.test", records[1].replacement);
    EXPECT_EQ("", records[2].flags);
    EXPECT_EQ("foo.example.test", records[2].replacement);
    EXPECT_EQ(".", records[3].replacement);
}

TEST(naptr, parse_truncated) {
    for (int len = 0; len < (int)sizeof(naptr_answer) - 1; len++) {
        std::vector<naptr_record> records;
        EXPECT_FALSE(naptr_parse(naptr_answer, len, records)) << len;
    }
}

TEST(naptr, parse_bad_string) {
    /* A flags string longer than the record. */
    static const unsigned char msg[] =
        "\x00\x00\x81\x80" "\x00\x00" "\x00\x01" "\x00\x00" "\x00\x00"
        "\x00" "\x00\x23" "\x00\x01" "\x00\x00\x00\x3c" "\x00\x06"
        "\x00\x0a" "\x00\x0a" "\x05" "s" "\x00\x00\x00\x00\x00\x00";
    std::vector<naptr_record> records;
    EXPECT_FALSE(naptr_parse(msg, sizeof(msg) - 1, records));
}

TEST(naptr, select) {
    std::vector<naptr_record> records;
    ASSERT_TRUE(naptr_parse(naptr_answer, sizeof(naptr_answer) - 1, records));
    std::vector<naptr_record> udp = records, tcp = records, sctp = records;

    naptr_select(udp, "SIP+D2U");
    ASSERT_EQ(1u, udp.size());
    EXPECT_EQ("_sip._udp.example.test", udp[0].replacement);
    naptr_select(tcp, "SIP+D2T");
    ASSERT_EQ(1u, tcp.size());
    EXPECT_EQ("_sip._tcp.example.test", tcp[0].replacement);
    naptr_select(sctp, "SIP+D2S");
    EXPECT_TRUE(sctp.empty());
}

TEST(naptr, select_order) {
    std::vector<naptr_record> records = {
        {20, 1, "s", "SIP+D2U", "d"}, {10, 50, "s", "SIP+D2U", "c"},
        {10, 20, "s", "SIP+D2U", "a"}, {10, 20, "s", "SIP+D2U", "b"},
    };
    naptr_select(records, "SIP+D2U");
    std::string order;
    for (const auto &r : records) {
        order += r.replacement;
    }
    EXPECT_EQ("abcd", order);
}

static unsigned pick_low(unsigned)
{
    return 0;
}

static unsigned pick_high(unsigned n)
{
    return n;
}

static unsigned pick_5(unsigned n)
{
    return std::min(n, 5u);
}

static std::string targets(const std::vector<srv_record> &records)
{
    std::string s;
    for (const auto &r : records) {
        s += r.target;
    }
    return s;
}

TEST(srv, order_priority) {
    std::vector<srv_record> records = {
        {20, 0, 1, "c"}, {10, 0, 1, "a"}, {30, 0, 1, "d"}, {10, 0, 1, "b"},
    };
    srv_order(records, pick_high);
    EXPECT_EQ("abcd", targets(records));
}

TEST(srv, order_zero_weights) {
    std::vector<srv_record> records = {
        {10, 0, 1, "a"}, {10, 0, 1, "b"}, {10, 0, 1, "c"},
    };
    srv_order(records, pick_high);
    EXPECT_EQ("abc", targets(records));
}

TEST(srv, order_weights) {
    std::vector<srv_record> records = {
        {10, 10, 1, "a"}, {10, 0, 1, "z"}, {10, 20, 1, "b"}, {5, 1, 1, "x"},
    };
    std::vector<srv_record> low = records, high = records, mid = records;

    /* The one of weight 0 only when the pick is 0. */
    srv_order(low, pick_low);
    EXPECT_EQ("xzab", targets(low));
    srv_order(high, pick_high);
    EXPECT_EQ("xbaz", targets(high));
    /* 5 is past z (0) and within a (10); then within b (0 + 20). */
    srv_order(mid, pick_5);
    EXPECT_EQ("xabz", targets(mid));
}

#endif //GTEST
