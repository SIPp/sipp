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
 *  Author : F. Tarek Rogers    - 01 Sept 2004
 *           Russell Roy
 *           Wolfgang Beck
 *           Dragos Vingarzan   - 02 February 2006 vingarzan@gmail.com
 *                              - split in the auth architecture
 *                              - introduced AKAv1-MD5
 *           Frederique Aurouet
 */

#if defined( __FreeBSD__) || defined(__DARWIN) || defined(__SUNOS)
#include <sys/types.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <algorithm>
#include <array>
#include <random>
#include <string>
#include <string_view>
#include "milenage.h"
#include "screen.hpp"
#include "logger.hpp"
#include "auth.hpp"
#include "strings.hpp"
#if defined(USE_OPENSSL)
#include <openssl/evp.h>
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/openssl/evp.h>
#endif

#define MAX_HEADER_LEN  2049
#define HASH_HEX_MAX_SIZE (2 * EVP_MAX_MD_SIZE)

/* The most characters used of a parameter's value, as the buffers it was
 * read in held: a longer value is cut. */
static constexpr size_t MAX_VALUE_LEN = MAX_HEADER_LEN - 1;
static constexpr size_t MAX_ALGORITHM_LEN = 31; // in createAuthHeader()'s error
static constexpr size_t MAX_QOP_LEN = 15;
static constexpr size_t MAX_OPAQUE_LEN = 63;

/* AKA */

#define KLEN 16
typedef std::array<u_char, KLEN> K;
#define RANDLEN 16
typedef std::array<u_char, RANDLEN> RAND;
#define AUTNLEN 16

#define AKLEN 6
typedef std::array<u_char, AKLEN> AK;
#define AMFLEN 2
typedef std::array<u_char, AMFLEN> AMF;
#define MACLEN 8
typedef std::array<u_char, MACLEN> MAC;
#define CKLEN 16
typedef std::array<u_char, CKLEN> CK;
#define IKLEN 16
typedef std::array<u_char, IKLEN> IK;
#define SQNLEN 6
typedef std::array<u_char, SQNLEN> SQN;
#define AUTSLEN 14
typedef std::array<u_char, AUTSLEN> AUTS;
#define RESLEN 8
typedef std::array<u_char, RESLEN> RES;
#define OPLEN 16
typedef std::array<u_char, OPLEN> OP;

AMF amfstar = {};
SQN sqn_he= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* end AKA */

/* A hash in hex, of up to EVP_MAX_MD_SIZE bytes */
struct HashHex {
    std::array<char, HASH_HEX_MAX_SIZE> digits;
    size_t size = 0;

    std::string_view view() const
    {
        return {digits.data(), size};
    }
};

static bool createAuthHeaderDigest(const EVP_MD *md, bool sess, std::string_view user, std::string_view password,
                                   std::string_view method, std::string_view uri, std::string_view msgbody,
                                   std::string_view auth, std::string_view algo, unsigned int nonce_count,
                                   std::string &result);

static bool createAuthHeaderAKAv1MD5(std::string_view user, const char *aka_OP, const char *aka_AMF, const char *aka_K,
                                     std::string_view method, std::string_view uri, std::string_view msgbody,
                                     std::string_view auth, std::string_view algo, unsigned int nonce_count,
                                     std::string &result);

/* This function is from RFC 2617 Section 5 */

static void hashToHex(const unsigned char *_b, size_t size, char *_h)
{
    size_t i;
    unsigned char j;

    for (i = 0; i < size; i++) {
        j = (_b[i] >> 4) & 0xf;
        if (j <= 9) {
            _h[i * 2] = (j + '0');
        } else {
            _h[i * 2] = (j + 'a' - 10);
        }
        j = _b[i] & 0xf;
        if (j <= 9) {
            _h[i * 2 + 1] = (j + '0');
        } else {
            _h[i * 2 + 1] = (j + 'a' - 10);
        }
    };
}

/* Whether s2 is in s1, in any case */
static bool stristr(std::string_view s1, std::string_view s2)
{
    for (size_t at = 0; at + s2.size() <= s1.size(); at++) {
        size_t i = 0;
        while (i < s2.size() && toupper(s1[at + i]) == toupper(s2[i])) {
            i++;
        }
        if (i == s2.size()) {
            return true;
        }
    }
    return false;
}

/* Whether s1 and s2 are the same, in any case */
static bool equalNoCase(std::string_view s1, std::string_view s2)
{
    return s1.size() == s2.size() && !strncasecmp(s1.data(), s2.data(), s1.size());
}

/* Where in s, at or past at, the first character not in set is, as
 * strspn(); and the first in it, as strcspn(): s.size() if none */
static size_t span(std::string_view s, size_t at, std::string_view set)
{
    return std::min(s.find_first_not_of(set, at), s.size());
}

static size_t cspan(std::string_view s, size_t at, std::string_view set)
{
    return std::min(s.find_first_of(set, at), s.size());
}

static const EVP_MD* sha512_256()
{
#if defined(USE_WOLFSSL) && (!defined(EVP_sha512_256) || \
                             !defined(WOLFSSL_SHA512) || defined(WOLFSSL_NOSHA512_256))
    return nullptr;  // not in this wolfSSL
#else
    return EVP_sha512_256();
#endif
}

/* The Digest algorithms, but AKAv1-MD5, with their hash, which is
 * nullptr if the SSL library has none. A -sess one's HA1 is of the
 * nonce and cnonce too (RFC 7616 3.4.2). */
static const struct DigestAlgorithm {
    const char* name;
    const EVP_MD* (*md)();
    bool sess;
} digestAlgorithms[] = {
    {"MD5", EVP_md5, false},
    {"MD5-sess", EVP_md5, true},
    {"SHA-256", EVP_sha256, false},
    {"SHA-256-sess", EVP_sha256, true},
    {"SHA-512-256", sha512_256, false},
    {"SHA-512-256-sess", sha512_256, true},
};

static const DigestAlgorithm *digestAlgorithm(std::string_view algo)
{
    for (const DigestAlgorithm& a : digestAlgorithms) {
        if (equalNoCase(algo, a.name)) {
            return &a;
        }
    }
    return nullptr;
}

/* The value of parameter name in header, cut to max_len characters */
static std::string_view getAuthParameter(std::string_view name, std::string_view header, size_t max_len)
{
    return getAuthParameter(name, header).substr(0, max_len);
}

bool createAuthHeader(std::string_view user, std::string_view password, const char *method, std::string_view uri,
                      std::string_view msgbody, std::string_view auth, const char *aka_OP, const char *aka_AMF,
                      const char *aka_K, unsigned int nonce_count, std::string &result)
{
    if (!stristr(auth, "Digest")) {
        result = "createAuthHeader: authentication must be digest";
        return false;
    }

    if (!method) {
        result = "createAuthHeader: authentication requires a method";
        return false;
    }

    std::string_view algo = getAuthParameter("algorithm", auth, MAX_ALGORITHM_LEN);
    if (algo.empty()) {
        algo = "MD5";
    }

    if (equalNoCase(algo, "AKAv1-MD5")) {
        if (!aka_K) {
            result = "createAuthHeader: AKAv1-MD5 authentication requires a key";
            return false;
        }
        return createAuthHeaderAKAv1MD5(
            user, aka_OP, aka_AMF, aka_K, method, uri, msgbody, auth,
            algo, nonce_count, result);
    } else if (const DigestAlgorithm *a = digestAlgorithm(algo)) {
        if (!a->md()) {
            result = std::string("createAuthHeader: ") + a->name + " is not supported by the SSL library SIPp is built with";
            return false;
        }
        return createAuthHeaderDigest(a->md(), a->sess, user, password, method, uri, msgbody, auth, algo, nonce_count,
                                      result);
    } else {
        result = "createAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256, "
                 "SHA-512-256-sess or AKAv1-MD5, not '";
        result += algo;
        result += "'";
        return false;
    }
}


/* Where the value of parameter name starts in header, or npos: the
 * name must begin the header or follow a ',' or a space, outside a
 * quoted string, and have an '=' after it, with spaces around allowed.
 * So "nonce" isn't found in "cnonce", nor in realm="a, nonce=b". */
static size_t findAuthParameter(std::string_view name, std::string_view header)
{
    const size_t n = name.size();
    bool quoted = false;
    size_t p = 0;

    while (p < header.size()) {
        if (quoted && header[p] == '\\' && p + 1 < header.size()) {
            p += 2; // an escaped character
            continue;
        }
        if (header[p] == '"') {
            quoted = !quoted;
        } else if (!quoted && (p == 0 || header[p - 1] == ',' || isspace(header[p - 1])) && header.size() - p >= n &&
                   !strncasecmp(header.data() + p, name.data(), n)) {
            const size_t eq = span(header, p + n, " \t\r\n");
            if (eq < header.size() && header[eq] == '=') {
                return span(header, eq + 1, " \t\r\n");
            }
        }
        p++;
    }
    return std::string_view::npos;
}

std::string_view getAuthParameter(std::string_view name, std::string_view header)
{
    size_t start = findAuthParameter(name, header);
    size_t end;

    if (start == std::string_view::npos) {
        return {};
    }
    if (start < header.size() && header[start] == '"') {
        start++;
        end = cspan(header, start, "\"");
    } else {
        end = cspan(header, start, " ,\"\r\n");
    }

    return header.substr(start, end - start);
}

/* The challenge after the one at p: past a comma, outside quotes, a
 * token followed by spaces, then by neither '=' nor ',', is the next
 * one's scheme. So the auth-int of a bare qop=auth,auth-int is not. */
static size_t nextChallenge(std::string_view auth, size_t p)
{
    bool quoted = false;

    while (p < auth.size()) {
        if (quoted && auth[p] == '\\' && p + 1 < auth.size()) {
            p += 2; // an escaped character
            continue;
        }
        if (auth[p] == '"') {
            quoted = !quoted;
        } else if (auth[p] == ',' && !quoted) {
            const size_t start = span(auth, p + 1, " \t\r\n");
            const size_t end = cspan(auth, start, " \t\r\n=,");
            const size_t after = span(auth, end, " \t\r\n");
            if (end > start && after > end && after < auth.size() && auth[after] != '=' && auth[after] != ',') {
                return start;
            }
        }
        p++;
    }
    return std::string_view::npos;
}

std::string_view selectAuthChallenge(std::string_view auth)
{
    size_t start = span(auth, 0, " \t");

    while (start != std::string_view::npos) {
        const size_t next = nextChallenge(auth, start);
        const std::string_view challenge = auth.substr(start, next - start);

        if (auth.size() - start > 6 && !strncasecmp(challenge.data(), "Digest", 6) && isspace(auth[start + 6])) {
            const std::string_view algo = getAuthParameter("algorithm", challenge);
            const DigestAlgorithm* a;

            // A -sess one has no cnonce to answer with without a qop
            if (algo.empty() || equalNoCase(algo, "AKAv1-MD5") ||
                ((a = digestAlgorithm(algo)) && a->md() && (!a->sess || !getAuthParameter("qop", challenge).empty()))) {
                return challenge.substr(0, challenge.find_last_not_of(" \t\r\n,") + 1);
            }
        }
        start = next;
    }
    return auth;
}

static void digestString(EVP_MD_CTX *mdctx, std::string_view s)
{
    EVP_DigestUpdate(mdctx, s.data(), s.size());
}

/* Ends the hash in mdctx, and writes it in hex: its length, 0 if the
 * SSL library failed it */
static size_t digestFinalHex(EVP_MD_CTX *mdctx, HashHex &hex)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
    unsigned int len = 0;

    if (!EVP_DigestFinal_ex(mdctx, hash.data(), &len)) {
        len = 0;
    }
    hashToHex(hash.data(), len, hex.digits.data());
    hex.size = 2 * len;
    return hex.size;
}

/* The response, in hex, to a Digest challenge by the hash md, of a
 * -sess algorithm if sess: false, and none, if the SSL library can't
 * compute it (MD5 in FIPS mode) */
static bool createAuthResponse(const EVP_MD *md, bool sess, std::string_view user, std::string_view password,
                               std::string_view method, std::string_view uri, std::string_view authtype,
                               std::string_view msgbody, std::string_view realm, std::string_view nonce,
                               std::string_view cnonce, std::string_view nc, HashHex &result)
{
    HashHex body_hex, ha1_hex, ha2_hex;
    size_t hex_len;
    const bool auth_int = stristr(authtype, "auth-int");
    bool ok = false;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    result.size = 0;
    // Load in A1
    if (!mdctx || !EVP_DigestInit_ex(mdctx, md, nullptr)) {
        goto end;
    }
    digestString(mdctx, user);
    digestString(mdctx, ":");
    digestString(mdctx, realm);
    digestString(mdctx, ":");
    digestString(mdctx, password);
    if (!(hex_len = digestFinalHex(mdctx, ha1_hex))) {
        goto end;
    }
    if (sess) {
        if (!EVP_DigestInit_ex(mdctx, md, nullptr)) {
            goto end;
        }
        digestString(mdctx, ha1_hex.view());
        digestString(mdctx, ":");
        digestString(mdctx, nonce);
        digestString(mdctx, ":");
        digestString(mdctx, cnonce);
        if (digestFinalHex(mdctx, ha1_hex) != hex_len) {
            goto end;
        }
    }

    // If using Auth-Int make a hash of the body - which is NULL for REG
    if (auth_int) {
        if (!EVP_DigestInit_ex(mdctx, md, nullptr)) {
            goto end;
        }
        digestString(mdctx, msgbody);
        if (digestFinalHex(mdctx, body_hex) != hex_len) {
            goto end;
        }
    }

    // Load in A2
    if (!EVP_DigestInit_ex(mdctx, md, nullptr)) {
        goto end;
    }
    digestString(mdctx, method);
    digestString(mdctx, ":");
    if (auth_uri) {
        digestString(mdctx, "sip:");
        digestString(mdctx, std::string_view(auth_uri).substr(0, MAX_VALUE_LEN - 4));
    } else {
        digestString(mdctx, uri.substr(0, MAX_VALUE_LEN));
    }
    if (auth_int) {
        digestString(mdctx, ":");
        digestString(mdctx, body_hex.view());
    }
    if (digestFinalHex(mdctx, ha2_hex) != hex_len ||
            !EVP_DigestInit_ex(mdctx, md, nullptr)) {
        goto end;
    }
    digestString(mdctx, ha1_hex.view());
    digestString(mdctx, ":");
    digestString(mdctx, nonce);
    if (!cnonce.empty()) {
        digestString(mdctx, ":");
        digestString(mdctx, nc);
        digestString(mdctx, ":");
        digestString(mdctx, cnonce);
        digestString(mdctx, ":");
        digestString(mdctx, authtype);
    }
    digestString(mdctx, ":");
    digestString(mdctx, ha2_hex.view());
    ok = digestFinalHex(mdctx, result) == hex_len;
end:
    EVP_MD_CTX_free(mdctx);
    return ok;
}

static bool createAuthHeaderDigest(const EVP_MD *md, bool sess, std::string_view user, std::string_view password,
                                   std::string_view method, std::string_view uri, std::string_view msgbody,
                                   std::string_view auth, std::string_view algo, unsigned int nonce_count,
                                   std::string &result)
{
    HashHex resp_hex;
    std::array<char, 17> cnonce_digits;
    std::array<char, 9> nc_digits;
    std::string_view cnonce, nc;

    // Extract the Auth Type - If not present, using 'none'
    std::string_view authtype = getAuthParameter("qop", auth, MAX_QOP_LEN);
    if (!authtype.empty()) {
        // Sloppy auth type recognition (may be "auth,auth-int")
        if (stristr(authtype, "auth-int")) {
            authtype = "auth-int";
        } else if (stristr(authtype, "auth")) {
            authtype = "auth";
        }
        /* Unpredictable, against a server choosing the plaintext */
        std::random_device rd;
        snprintf(cnonce_digits.data(), cnonce_digits.size(), "%08x%08x", rd(), rd());
        cnonce = std::string_view(cnonce_digits.data(), cnonce_digits.size() - 1);
        snprintf(nc_digits.data(), nc_digits.size(), "%08x", nonce_count);
        nc = std::string_view(nc_digits.data(), nc_digits.size() - 1);
    }

    if (sess && cnonce.empty()) {
        result = "createAuthHeader: ";
        result += algo;
        result += " needs a qop in the challenge, for a cnonce";
        return false;
    }

    // Extract the Opaque value - if present
    const std::string_view opaque = getAuthParameter("opaque", auth, MAX_OPAQUE_LEN);

    // Extract the Realm
    const std::string_view realm = getAuthParameter("realm", auth, MAX_VALUE_LEN);
    if (realm.empty()) {
        result = "createAuthHeader: couldn't parse realm in '";
        result += auth;
        result += "'";
        return false;
    }

    // Extract the Nonce
    const std::string_view nonce = getAuthParameter("nonce", auth, MAX_VALUE_LEN);
    if (nonce.empty()) {
        result = "createAuthHeader: couldn't parse nonce";
        return false;
    }

    // Construct the URI
    const std::string_view sipuri_rest = (auth_uri ? std::string_view(auth_uri) : uri).substr(0, MAX_VALUE_LEN - 4);

    result.reserve(256 + user.size() + realm.size() + sipuri_rest.size() + nonce.size() + opaque.size());
    result = "Digest username=\"";
    result += user;
    result += "\",realm=\"";
    result += realm;
    result += "\"";
    if (!cnonce.empty()) {
        // No double quotes around nc and qop (RFC3261):
        //
        // dig-resp = username / realm / nonce / digest-uri / dresponse
        //             / algorithm / cnonce / opaque / message-qop
        // message-qop = "qop" EQUAL ("auth" / "auth-int" / token)
        // nonce-count =  "nc" EQUAL 8LHEX
        //
        // The digest challenge does have double quotes however:
        //
        // digest-cln = realm / domain / nonce / opaque / stale / algorithm
        //                / qop-options / auth-param
        // qop-options = "qop" EQUAL LDQUOT qop-value *("," qop-value) RDQUOT
        result += ",cnonce=\"";
        result += cnonce;
        result += "\",nc=";
        result += nc;
        result += ",qop=";
        result += authtype;
    }
    result += ",uri=\"";
    const size_t sipuri_at = result.size();
    result += "sip:";
    result += sipuri_rest;

    /* The URI as written in result, which nothing changes until the
     * response is computed */
    const std::string_view sipuri = std::string_view(result).substr(sipuri_at);
    if (!createAuthResponse(md, sess, user, password, method, sipuri, authtype, msgbody, realm, nonce, cnonce, nc,
                            resp_hex)) {
        result = "createAuthHeader: the SSL library failed to compute the ";
        result += algo;
        result += " response";
        return false;
    }

    result += "\",nonce=\"";
    result += nonce;
    result += "\",response=\"";
    result += resp_hex.view();
    result += "\",algorithm=";
    result += algo;
    if (!opaque.empty()) {
        result += ",opaque=\"";
        result += opaque;
        result += "\"";
    }

    return true;
}

int verifyAuthHeader(std::string_view user, std::string_view password, std::string_view method, std::string_view auth,
                     std::string_view msgbody)
{
    if (!stristr(auth, "Digest")) {
        WARNING("verifyAuthHeader: authentication must be digest is %.*s", (int)auth.size(), auth.data());
        return 0;
    }

    std::string_view algo = getAuthParameter("algorithm", auth, MAX_VALUE_LEN);
    if (algo.empty()) {
        algo = "MD5";
    }
    const DigestAlgorithm* a = digestAlgorithm(algo);
    if (!a) {
        WARNING("verifyAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256 or "
                "SHA-512-256-sess, value is '%.*s'",
                (int)algo.size(), algo.data());
        return 0;
    }
    if (!a->md()) {
        WARNING("verifyAuthHeader: %s is not supported by the SSL library SIPp is built with", a->name);
        return 0;
    }
    HashHex result;
    const std::string_view realm = getAuthParameter("realm", auth, MAX_VALUE_LEN);
    const std::string_view uri = getAuthParameter("uri", auth, MAX_VALUE_LEN);
    const std::string_view nonce = getAuthParameter("nonce", auth, MAX_VALUE_LEN);
    const std::string_view cnonce = getAuthParameter("cnonce", auth, MAX_VALUE_LEN);
    const std::string_view nc = getAuthParameter("nc", auth, MAX_VALUE_LEN);
    const std::string_view authtype = getAuthParameter("qop", auth, MAX_VALUE_LEN);
    if (a->sess && cnonce.empty()) {
        return 0;  // no HA1 without a cnonce
    }
    if (!createAuthResponse(a->md(), a->sess, user, password, method, uri, authtype, msgbody, realm, nonce, cnonce, nc,
                            result)) {
        WARNING("verifyAuthHeader: the SSL library failed to compute the %.*s response", (int)algo.size(), algo.data());
        return 0;
    }
    const std::string_view response = getAuthParameter("response", auth, HASH_HEX_MAX_SIZE);
    TRACE_CALLDEBUG("Processing verifyauth command - user %.*s, password %.*s, method %.*s, uri %.*s, realm %.*s, "
                    "nonce %.*s, result expected %.*s, response from user %.*s\n",
                    (int)user.size(), user.data(), (int)password.size(), password.data(), (int)method.size(),
                    method.data(), (int)uri.size(), uri.data(), (int)realm.size(), realm.data(), (int)nonce.size(),
                    nonce.data(), (int)result.size, result.digits.data(), (int)response.size(), response.data());
    return !response.empty() && result.view() == response;
}

/* The bytes of the base64 text buf: none if it is not base64 */
static std::string base64_decode_string(std::string_view buf)
{
    const unsigned int len = buf.size();
    std::string out(len * 3 / 4 + 8, '\0');

    int decoded_len = EVP_DecodeBlock((unsigned char *)&out[0], (const unsigned char *)buf.data(), len);

    if (decoded_len < 0) {
        return {};
    }

    // OpenSSL decodes the '=' padding as zero bytes, wolfSSL doesn't
    if (decoded_len == (int)(len / 4 * 3)) {
        if (len > 0 && buf[len - 1] == '=') decoded_len--;
        if (len > 1 && buf[len - 2] == '=') decoded_len--;
    }

    out.resize(decoded_len);
    return out;
}

/* An AKA key's bytes: those of its text, or those its hex digits after
 * "0x" give, with zeros past their end. */
static void getAKAKey(std::string_view text, u_char *key, size_t len)
{
    size_t n = 0;

    memset(key, 0, len);
    if (text.size() >= 2 && text[0] == '0' && text[1] == 'x') {
        for (size_t i = 2; n < len && i < text.size() && isxdigit(text[i]); n++) {
            int val = get_decimal_from_hex(text[i++]);
            if (i < text.size() && isxdigit(text[i])) {
                val = (val << 4) + get_decimal_from_hex(text[i++]);
            }
            key[n] = val;
        }
    } else {
        memcpy(key, text.data(), std::min(text.size(), len));
    }
}

static bool createAuthHeaderAKAv1MD5(std::string_view user, const char *aka_OP, const char *aka_AMF, const char *aka_K,
                                     std::string_view method, std::string_view uri, std::string_view msgbody,
                                     std::string_view auth, std::string_view algo, unsigned int nonce_count,
                                     std::string &result)
{

    int has_auts = 0;
    AMF amf;
    OP op;
    RAND rnd;
    AUTS auts_bin;
    std::array<char, 2 * AUTSLEN> auts_hex;
    MAC mac, xmac;
    SQN sqn, sqnxoraka, sqn_ms;
    K k;
    RES res;
    CK ck;
    IK ik;
    AK ak;
    int i;

    // Extract the Nonce
    const std::string_view nonce64 = getAuthParameter("nonce", auth, MAX_VALUE_LEN);
    if (nonce64.empty()) {
        result = "createAuthHeaderAKAv1MD5: couldn't parse nonce";
        return false;
    }

    /* Compute the AKA RES */
    const std::string nonce = base64_decode_string(nonce64);
    if (nonce.size() < RANDLEN + AUTNLEN) {
        result = "createAuthHeaderAKAv1MD5 : Nonce is too short " + std::to_string(nonce.size()) + " < " +
                 std::to_string(RANDLEN + AUTNLEN) + " expected\n";
        return false;
    }
    memcpy(rnd.data(), nonce.data(), RANDLEN);
    memcpy(sqnxoraka.data(), nonce.data() + RANDLEN, SQNLEN);
    /* The MAC is over the AMF of AUTN, as a USIM checks it (3GPP TS
     * 33.102 6.3.3): aka_AMF is not used. */
    memcpy(amf.data(), nonce.data() + RANDLEN + SQNLEN, AMFLEN);
    memcpy(mac.data(), nonce.data() + RANDLEN + SQNLEN + AMFLEN, MACLEN);
    /* An omitted aka_OP is all zeros, not what the buffer held. */
    getAKAKey(aka_K, k.data(), KLEN);
    getAKAKey(aka_OP, op.data(), OPLEN);

    /* Compute the AK, response and keys CK IK */
    f2345(k.data(), rnd.data(), res.data(), ck.data(), ik.data(), ak.data(), op.data());

    /* Compute sqn encoded in AUTN */
    for (i=0; i < SQNLEN; i++)
        sqn[i] = sqnxoraka[i] ^ ak[i];

    /* compute XMAC */
    f1(k.data(), rnd.data(), sqn.data(), amf.data(), xmac.data(), op.data());
    if (mac != xmac) {
        result = "createAuthHeaderAKAv1MD5 : MAC != expectedMAC -> Server might not know the secret (man-in-the-middle attack?)\n";
        return false;
    }

    /* Check SQN, compute AUTS if needed and authorization parameter */
    /* the condition below is wrong.
     * Should trigger synchronization when sqn_ms>>3!=sqn_he>>3 for example.
     * Also, we need to store the SQN per user or put it as auth parameter. */
    if (1/*sqn[5] > sqn_he[5]*/) {
        sqn_he[5] = sqn[5];
        has_auts = 0;
        /* RES has to be used as password to compute response */
        if (!createAuthHeaderDigest(EVP_md5(), false, user, std::string_view((const char *)res.data(), RESLEN), method,
                                    uri, msgbody, auth, algo, nonce_count, result)) {
            result = "createAuthHeaderAKAv1MD5 : Unexpected return value from createAuthHeaderDigest\n";
            return false;
        }
    } else {
        sqn_ms[5] = sqn_he[5] + 1;
        f5star(k.data(), rnd.data(), ak.data(), op.data());
        for(i=0; i<SQNLEN; i++)
            auts_bin[i]=sqn_ms[i]^ak[i];
        /* AUTS has a MAC-S over a dummy AMF of zeros (3GPP TS 33.102
         * 6.3.3) */
        f1star(k.data(), rnd.data(), sqn_ms.data(), amfstar.data(), auts_bin.data() + SQNLEN, op.data());
        has_auts = 1;
        /* When re-synchronisation occurs an empty password has to be used */
        /* to compute MD5 response (Cf. rfc 3310 section 3.2) */
        if (!createAuthHeaderDigest(EVP_md5(), false, user, "", method, uri, msgbody, auth, algo, nonce_count,
                                    result)) {
            result = "createAuthHeaderAKAv1MD5 : Unexpected return value from createAuthHeaderDigest\n";
            return false;
        }
    }
    if (has_auts) {
        /* Format data for output in the SIP message */
        hashToHex(auts_bin.data(), AUTSLEN, auts_hex.data());

        result += ",auts=\"";
        result.append(auts_hex.data(), auts_hex.size());
        result += "\"";
    }
    return true;
}


#ifdef GTEST
#include "gtest/gtest.h"

TEST(DigestAuth, nonce) {
    EXPECT_EQ("a6ca2bf13de1433183f7c48781bd9304",
              getAuthParameter(
                  "nonce", " Authorization: Digest cnonce=\"c7e1249f\",nonce=\"a6ca2bf13de1433183f7c48781bd9304\""));
    EXPECT_EQ("a6ca2bf13de1433183f7c48781bd9304",
              getAuthParameter(
                  "nonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\", cnonce=\"c7e1249f\""));
}

TEST(DigestAuth, cnonce) {
    EXPECT_EQ("c7e1249f",
              getAuthParameter(
                  "cnonce", " Authorization: Digest cnonce=\"c7e1249f\",nonce=\"a6ca2bf13de1433183f7c48781bd9304\""));
    EXPECT_EQ("c7e1249f",
              getAuthParameter(
                  "cnonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\", cnonce=\"c7e1249f\""));
}

TEST(DigestAuth, MissingParameter) {
    EXPECT_EQ("", getAuthParameter("cnonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\""));
}

TEST(DigestAuth, BasicVerification) {
    const char *header = "Digest \r\n"
                         " realm=\"testrealm@host.com\",\r\n"
                         " nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n,"
                         " opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
    std::string result;
    createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "hello world", header, nullptr, nullptr, nullptr, 1, result);
    EXPECT_EQ("Digest username=\"testuser\",realm=\"testrealm@host.com\",uri=\"sip:sip:example.com\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",response=\"db94e01e92f2b09a52a234eeca8b90f7\",algorithm=MD5,opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"", result);
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
}

TEST(DigestAuth, LongChallenge) {
    /* A realm and nonce of a challenge longer than a header, answered whole */
    const std::string realm(MAX_HEADER_LEN - 100, 'r'), nonce(MAX_HEADER_LEN - 100, 'n');
    const std::string header = "Digest realm=\"" + realm + "\", nonce=\"" + nonce + "\"";
    std::string result;
    ASSERT_TRUE(createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "", header, nullptr, nullptr,
                                 nullptr, 1, result))
        << result;
    EXPECT_NE(std::string::npos, result.find(",realm=\"" + realm + "\","));
    EXPECT_NE(std::string::npos, result.find(",nonce=\"" + nonce + "\","));
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, ""));
}

TEST(DigestAuth, BasicVerificationSHA256) {
    const char *header = "Digest \r\n"
                         " realm=\"testrealm@host.com\",\r\n"
                         " nonce=\"ZaGxV2WhsCtREI2EsiD1LR0RYd\"\r\n,"
                         " algorithm=SHA-256";
    std::string result;
    createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "hello world", header, nullptr, nullptr, nullptr, 1, result);
    EXPECT_EQ("Digest username=\"testuser\",realm=\"testrealm@host.com\",uri=\"sip:sip:example.com\",nonce=\"ZaGxV2WhsCtREI2EsiD1LR0RYd\",response=\"91b58523b983191b52d14455a2599631990110c974ed2e4b4b49bc6053af04ce\",algorithm=SHA-256", result);
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
}

TEST(DigestAuth, MissingResponse) {
    /* Not the response of any password, were none computed */
    const char* header = "Digest username=\"testuser\",realm=\"r\",uri=\"sip:x\",nonce=\"n\",algorithm=MD5";
    EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "REGISTER", header, ""));
    EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "REGISTER", std::string(header) + ",response=\"\"", ""));
}

/* An Authorization of the example of RFC 7616 3.9.1 */
static std::string rfc7616Authorization(const char* algo, const char* uri,
                                        const char* nc, const char* qop,
                                        const char* response)
{
    return std::string("Digest username=\"Mufasa\", realm=\"http-auth@example.org\", uri=\"") +
           uri + "\", algorithm=" + algo +
           ", nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", nc=" + nc +
           ", cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", qop=" + qop +
           ", response=\"" + response + "\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
}

/* Whether the response is to the example of RFC 7616 3.9.1, of its
 * password and not another, and is the one computed for it */
static void expectRFC7616(const char* algo, const char* method,
                          const char* uri, const char* nc, const char* qop,
                          const char* body, const char* response)
{
    const DigestAlgorithm* a = digestAlgorithm(algo);
    if (!a->md()) {
        return;  // not in this SSL library
    }
    std::string auth = rfc7616Authorization(algo, uri, nc, qop, response);
    EXPECT_EQ(1, verifyAuthHeader("Mufasa", "Circle of Life", method, auth, body)) << auth;
    EXPECT_EQ(0, verifyAuthHeader("Mufasa", "Circle of life", method, auth, body)) << auth;

    HashHex result;
    EXPECT_TRUE(createAuthResponse(a->md(), a->sess, "Mufasa", "Circle of Life", method, uri, qop, body,
                                   "http-auth@example.org", "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
                                   "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", nc, result));
    EXPECT_EQ(response, result.view()) << algo;
}

TEST(DigestAuth, RFC7616) {
    expectRFC7616("MD5", "GET", "/dir/index.html", "00000001", "auth", "",
                  "8ca523f5e9506fed4657c9700eebdbec");
    expectRFC7616("SHA-256", "GET", "/dir/index.html", "00000001", "auth", "",
                  "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1");
    /* With auth-int, as Python's hashlib computes it */
    expectRFC7616("MD5", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n",
                  "3dbb0971468cf612bdccd7dff696c5e6");
    expectRFC7616("SHA-256", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n",
                  "21468b02aafd4fe0a3d84bfddaf3618cc087adff4bb3c92d0a5f99c3035fcb9a");
    /* The other algorithms of RFC 7616, likewise */
    expectRFC7616("SHA-512-256", "GET", "/dir/index.html", "00000001", "auth", "",
                  "430d05014cecc49cab6fbe03176d41a1da86cbfe24a16580e22aaad928d960d0");
    expectRFC7616("MD5-sess", "GET", "/dir/index.html", "00000001", "auth", "",
                  "e783283f46242139c486a698fec7211d");
    expectRFC7616("SHA-256-sess", "GET", "/dir/index.html", "00000001", "auth", "",
                  "2fd51b3a77ad75bad6afad6003e818d767133c46d9e2749e7f5232ae1ea3efd7");
    expectRFC7616("SHA-512-256-sess", "GET", "/dir/index.html", "00000001", "auth", "",
                  "3f2a34f923c38b0fb26dce2fdfc2ce326c23cecf86fbb1444f3e51fbbc2cb92e");
    expectRFC7616("SHA-512-256", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n",
                  "959ca26f4f77c10a9a54b19ac24811fbc7f3c7bda8eec5d8521fb4586ed10e90");
    expectRFC7616("MD5-sess", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n",
                  "11713a2ffc80446ab4c404a4a997b69c");
    expectRFC7616("SHA-256-sess", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n",
                  "2c66c095845ec6e7e158c4f689683959329e5296947f1c4930d0ffa7b93c09fd");
    expectRFC7616("SHA-512-256-sess", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n",
                  "39fcf9431af157aced94549f5fff6fea4d427a3e231c8a5557ccc7976e056b09");
}

TEST(DigestAuth, RFC7616SHA512256) {
    if (!sha512_256()) {
        GTEST_SKIP();
    }
    /* RFC 7616 3.9.2, with the username and response of its erratum
     * 4897: the RFC's are not of its inputs. verifyauth doesn't read
     * the (hashed) username. */
    const char* auth = "Digest username=\"793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b\", "
                       "realm=\"api@example.org\", uri=\"/doe.json\", algorithm=SHA-512-256, "
                       "nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", nc=00000001, "
                       "cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", qop=auth, "
                       "response=\"3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5\", "
                       "opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", userhash=true";
    EXPECT_EQ(1, verifyAuthHeader("J\xc3\xa4s\xc3\xb8n Doe", "Secret, or not?", "GET", auth, ""));
    EXPECT_EQ(0, verifyAuthHeader("Jason Doe", "Secret, or not?", "GET", auth, ""));
}

TEST(DigestAuth, qop) {
    std::string result;
    const char *header = "Digest \r\n"
                         "\trealm=\"testrealm@host.com\",\r\n"
                         "\tqop=\"auth,auth-int\",\r\n"
                         "\tnonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n,"
                         "\topaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
    createAuthHeader("testuser",
                     "secret",
                     "REGISTER",
                     "sip:example.com",
                     "hello world",
                     header,
                     nullptr,
                     nullptr,
                     nullptr,
                     1,
                     result);
    EXPECT_NE(std::string::npos, result.find(",qop=auth-int,")); // no double quotes around qop-value
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
}

TEST(DigestAuth, SessAlgorithms) {
    std::string result;
    const char* algos[] = {"MD5-sess", "SHA-256-sess", "SHA-512-256", "sha-512-256-SESS"};
    const char* qops[] = {"auth", "auth-int", "auth,auth-int"};

    for (const char* algo : algos) {
        if (!digestAlgorithm(algo)->md()) {
            continue;
        }
        for (const char* qop : qops) {
            std::string challenge = std::string("Digest realm=\"r\", nonce=\"n\", qop=\"") + qop +
                                    "\", algorithm=" + algo;
            ASSERT_TRUE(createAuthHeader("testuser", "secret", "INVITE", "bob@example.com", "v=0\r\n", challenge,
                                         nullptr, nullptr, nullptr, 1, result))
                << result;
            /* The algorithm as the challenge has it */
            EXPECT_NE(std::string::npos, result.find(std::string(",algorithm=") + algo)) << result;
            EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "INVITE", result, "v=0\r\n")) << result;
            /* auth-int covers the body */
            EXPECT_EQ(!strcmp(qop, "auth"), verifyAuthHeader("testuser", "secret", "INVITE", result, "v=1\r\n"))
                << result;
            EXPECT_EQ(0, verifyAuthHeader("testuser", "Secret", "INVITE", result, "v=0\r\n")) << result;
            /* Not the response of the algorithm without -sess */
            std::string other = result;
            size_t at = other.find("-sess");
            if (at == std::string::npos) {
                at = other.find("-SESS");
            }
            if (at != std::string::npos) {
                other.erase(at, 5);
                EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "INVITE", other, "v=0\r\n")) << other;
            }
        }
    }

    /* A -sess one has no cnonce without a qop */
    EXPECT_FALSE(createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "",
                                  "Digest realm=\"r\", nonce=\"n\", algorithm=MD5-sess",
                                  nullptr, nullptr, nullptr, 1, result));
    EXPECT_EQ("createAuthHeader: MD5-sess needs a qop in the challenge, for a cnonce", result);
    HashHex response;
    EXPECT_TRUE(createAuthResponse(EVP_md5(), true, "testuser", "secret", "REGISTER", "sip:x", "", "", "r", "n", "", "",
                                   response));
    EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "REGISTER",
                                  "Digest username=\"testuser\",realm=\"r\",uri=\"sip:x\",nonce=\"n\",response=\"" +
                                      std::string(response.view()) + "\",algorithm=MD5-sess",
                                  ""));
    /* SHA-512-256 without a qop, as RFC 2069 */
    if (sha512_256()) {
        ASSERT_TRUE(createAuthHeader("testuser", "secret", "REGISTER", "example.com", "",
                                     "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-512-256",
                                     nullptr, nullptr, nullptr, 1, result));
        EXPECT_EQ(std::string::npos, result.find("cnonce")) << result;
        EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "")) << result;
    }

    /* Still none of another algorithm */
    EXPECT_FALSE(createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "",
                                  "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-384",
                                  nullptr, nullptr, nullptr, 1, result));
    EXPECT_EQ("createAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, "
             "SHA-512-256, SHA-512-256-sess or AKAv1-MD5, not 'SHA-384'", result);
}

TEST(DigestAuth, base64_decode_string) {
    EXPECT_EQ("abc", base64_decode_string("YWJj"));
    EXPECT_EQ("abcde", base64_decode_string("YWJjZGU="));
    EXPECT_EQ("abcd", base64_decode_string("YWJjZA=="));
    /* Zero bytes are decoded, not taken as padding */
    EXPECT_EQ(std::string(3, '\0'), base64_decode_string("AAAA"));
    EXPECT_EQ("", base64_decode_string("YW!j"));
}

TEST(DigestAuth, AKAv1MD5HexKeys) {
    /* 3GPP TS 35.208 test set 1, whose K has 0x0A and 0x5B bytes: the
     * challenge has its RAND and AUTN, the response its RES. */
    std::string result;
    const char* header = "Digest realm=\"r\", nonce=\"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=\", algorithm=AKAv1-MD5";
    ASSERT_TRUE(createAuthHeader("alice", "", "REGISTER", "sip:example.com", "", header,
                                 "0xCDC202D5123E20F62B6D676AC72CB318", "0xB9B9",
                                 "0x465B5CE8B199B49FAA5F0A2EE238A6BC", 1, result))
        << result;
    EXPECT_NE(std::string::npos, result.find(",response=\"1efe54bb65c7771548e279052d82bd09\",")) << result;
    /* Spaces around the nonce's '=' */
    header = "Digest realm=\"r\", nonce = \"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=\", algorithm=AKAv1-MD5";
    ASSERT_TRUE(createAuthHeader("alice", "", "REGISTER", "sip:example.com", "", header,
                                 "0xCDC202D5123E20F62B6D676AC72CB318", "0xB9B9",
                                 "0x465B5CE8B199B49FAA5F0A2EE238A6BC", 1, result))
        << result;
    EXPECT_NE(std::string::npos, result.find(",response=\"1efe54bb65c7771548e279052d82bd09\",")) << result;
}

TEST(DigestAuth, AKAv1MD5AMFOfAUTN) {
    /* 3GPP TS 35.208 test set 1, whose AUTN has an AMF of 0xB9B9: that
     * AMF is the one of the MAC, whatever aka_AMF is. */
    std::string result;
    const char* header = "Digest realm=\"r\", nonce=\"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=\", algorithm=AKAv1-MD5";
    ASSERT_TRUE(createAuthHeader("alice", "", "REGISTER", "sip:example.com", "", header,
                                 "0xCDC202D5123E20F62B6D676AC72CB318", "",
                                 "0x465B5CE8B199B49FAA5F0A2EE238A6BC", 1, result))
        << result;
    EXPECT_NE(std::string::npos, result.find(",response=\"1efe54bb65c7771548e279052d82bd09\",")) << result;
    /* An AMF of 0xB9B8 in AUTN doesn't match its MAC */
    header = "Digest realm=\"r\", nonce=\"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m4Sp/6w1Tfr7M=\", algorithm=AKAv1-MD5";
    EXPECT_FALSE(createAuthHeader("alice", "", "REGISTER", "sip:example.com", "", header,
                                  "0xCDC202D5123E20F62B6D676AC72CB318", "0xB9B8",
                                  "0x465B5CE8B199B49FAA5F0A2EE238A6BC", 1, result));
    EXPECT_NE(std::string::npos, result.find("MAC != expectedMAC")) << result;
}

TEST(DigestAuth, AKAv1MD5Header)
{
    /* Test set 1 again, whole: RES is the password, of 8 bytes (as
     * Python's hashlib computes it) */
    std::string result;
    ASSERT_TRUE(createAuthHeader("alice", "", "REGISTER", "example.com", "",
                                 "Digest realm=\"r\", nonce=\"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=\", "
                                 "algorithm=AKAv1-MD5, opaque=\"o\"",
                                 "0xCDC202D5123E20F62B6D676AC72CB318", "", "0x465B5CE8B199B49FAA5F0A2EE238A6BC", 1,
                                 result))
        << result;
    EXPECT_EQ("Digest username=\"alice\",realm=\"r\",uri=\"sip:example.com\","
              "nonce=\"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=\","
              "response=\"c967d9c99f26c4da203ee73f572b5364\",algorithm=AKAv1-MD5,opaque=\"o\"",
              result);
    /* A nonce too short for a RAND and an AUTN */
    EXPECT_FALSE(createAuthHeader("alice", "", "REGISTER", "example.com", "",
                                  "Digest realm=\"r\", nonce=\"YWJj\", algorithm=AKAv1-MD5", "", "", "", 1, result));
    EXPECT_EQ("createAuthHeaderAKAv1MD5 : Nonce is too short 3 < 32 expected\n", result);
    EXPECT_FALSE(createAuthHeader("alice", "", "REGISTER", "example.com", "",
                                  "Digest realm=\"r\", nonce=\"Y!Jj\", algorithm=AKAv1-MD5", "", "", "", 1, result));
    EXPECT_EQ("createAuthHeaderAKAv1MD5 : Nonce is too short 0 < 32 expected\n", result);
}

TEST(DigestAuth, getAuthParameter) {
    EXPECT_EQ("abc", getAuthParameter("nonce", "Digest nonce=abc"));
    /* Spaces around '=', a quoted value */
    EXPECT_EQ("SHA-256", getAuthParameter("algorithm", "Digest realm=\"r\", algorithm = SHA-256"));
    EXPECT_EQ("a b", getAuthParameter("realm", "Digest realm= \"a b\""));
    /* Not in cnonce, nor in another parameter's quoted value */
    EXPECT_EQ("y", getAuthParameter("nonce", "Digest cnonce=\"x\", nonce=\"y\""));
    EXPECT_EQ("MD5", getAuthParameter("algorithm", "Digest realm=\"a, algorithm=SHA-256\", algorithm=MD5"));
    EXPECT_EQ("good", getAuthParameter("nonce", "Digest realm=\"a\\\", nonce=bad\", nonce=good"));
    EXPECT_EQ("", getAuthParameter("opaque", "Digest realm=\"opaque=x\""));
    /* A quoted value ends at a quote or the end, another at a space, a
     * comma, a quote or a line end */
    EXPECT_EQ("a,b", getAuthParameter("realm", "Digest realm=\"a,b"));
    EXPECT_EQ("", getAuthParameter("realm", "Digest realm=\"\", nonce=n"));
    EXPECT_EQ("", getAuthParameter("realm", "Digest realm="));
    EXPECT_EQ("a\tb", getAuthParameter("nonce", "Digest nonce=a\tb,c"));
    EXPECT_EQ("a", getAuthParameter("nonce", "Digest nonce=a\"b"));
    EXPECT_EQ("a", getAuthParameter("nonce", "Digest nonce=a\r\n"));
    /* The name whole, after a tab too */
    EXPECT_EQ("", getAuthParameter("nonc", "Digest nonce=a"));
    EXPECT_EQ("n", getAuthParameter("NONCE", "Digest\tnonce=n"));
}

TEST(DigestAuth, ValueLimits)
{
    /* The parts of the values that are used, as they were */
    std::string result;
    const std::string opaque(70, 'o');
    ASSERT_TRUE(createAuthHeader("u", "p", "INVITE", "h", "",
                                 "Digest realm=\"r\", nonce=\"n\", opaque=\"" + opaque + "\"", nullptr, nullptr,
                                 nullptr, 1, result));
    EXPECT_NE(std::string::npos, result.find(",opaque=\"" + opaque.substr(0, 63) + "\"")) << result;
    /* The first 15 characters of a qop: auth here, auth-int past them */
    ASSERT_TRUE(createAuthHeader("u", "p", "INVITE", "h", "",
                                 "Digest realm=\"r\", nonce=\"n\", qop=\"token,auth-conf,auth-int\"", nullptr, nullptr,
                                 nullptr, 1, result));
    EXPECT_NE(std::string::npos, result.find(",qop=auth,")) << result;
    ASSERT_TRUE(createAuthHeader("u", "p", "INVITE", "h", "",
                                 "Digest realm=\"r\", nonce=\"n\", qop=\"token-of-twenty-two\"", nullptr, nullptr,
                                 nullptr, 1, result));
    EXPECT_NE(std::string::npos, result.find(",qop=token-of-twenty,")) << result;
    EXPECT_EQ(1, verifyAuthHeader("u", "p", "INVITE", result, "")) << result;
    EXPECT_FALSE(createAuthHeader("u", "p", "INVITE", "h", "",
                                  "Digest realm=\"r\", nonce=\"n\", algorithm=" + std::string(40, 'a'), nullptr,
                                  nullptr, nullptr, 1, result));
    EXPECT_EQ("createAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, "
              "SHA-512-256, SHA-512-256-sess or AKAv1-MD5, not '" +
                  std::string(31, 'a') + "'",
              result);

    /* -auth_uri, of up to 2044 characters after "sip:" */
    char *const saved_auth_uri = auth_uri;
    std::string forced(3000, 'f');
    auth_uri = &forced[0];
    ASSERT_TRUE(createAuthHeader("u", "p", "INVITE", "h", "", "Digest realm=\"r\", nonce=\"n\"", nullptr, nullptr,
                                 nullptr, 1, result));
    EXPECT_NE(std::string::npos, result.find(",uri=\"sip:" + forced.substr(0, 2044) + "\",")) << result;
    EXPECT_EQ(1, verifyAuthHeader("u", "p", "INVITE", result, "")) << result;
    /* verifyauth uses it too, not the uri of the credentials */
    forced[0] = 'g';
    EXPECT_EQ(0, verifyAuthHeader("u", "p", "INVITE", result, "")) << result;
    auth_uri = saved_auth_uri;

    /* verifyauth uses the first 2048 characters of a value */
    const std::string realm(2048, 'r');
    ASSERT_TRUE(createAuthHeader("u", "p", "INVITE", "h", "", "Digest realm=\"" + realm + "\", nonce=\"n\"", nullptr,
                                 nullptr, nullptr, 1, result));
    result.insert(result.find(realm) + realm.size(), "R");
    EXPECT_EQ(1, verifyAuthHeader("u", "p", "INVITE", result, "")) << result;
}

static std::string selectedChallenge(const char* auth)
{
    return std::string(selectAuthChallenge(auth));
}

TEST(DigestAuth, SelectChallenge) {
    EXPECT_EQ("Digest realm=\"b\", nonce=\"2\", algorithm=MD5",
              selectedChallenge("Digest realm=\"a\", nonce=\"1\", algorithm=SHA-384, "
                                "Digest realm=\"b\", nonce=\"2\", algorithm=MD5"));
    EXPECT_EQ("Digest realm=\"a\", nonce=\"1\", qop=\"auth,auth-int\"",
              selectedChallenge("Digest realm=\"a\", nonce=\"1\", qop=\"auth,auth-int\", "
                                "Digest realm=\"b\", nonce=\"2\", algorithm=SHA-256"));
    EXPECT_EQ("Digest realm = \"c\",nonce=\"3\"",
              selectedChallenge("Basic realm=\"x\", Digest realm=\"a, Digest b\", algorithm=AKAv2-MD5, "
                                "Digest realm = \"c\",nonce=\"3\""));
    /* A bare qop list, as some servers send, is not split at auth-int */
    EXPECT_EQ("Digest realm=\"r\", qop=auth,auth-int, nonce=\"n1\", algorithm=MD5",
              selectedChallenge("Digest realm=\"r\", qop=auth,auth-int, nonce=\"n1\", algorithm=MD5"));
    EXPECT_EQ("Digest realm=\"b\", qop=auth, auth-int, nonce=\"2\"",
              selectedChallenge("Digest realm=\"a\", algorithm=SHA-384, "
                                "Digest realm=\"b\", qop=auth, auth-int, nonce=\"2\""));
    /* An algorithm with spaces around its '=' is still read */
    EXPECT_EQ("Digest realm=\"b\", algorithm = MD5",
              selectedChallenge("Digest realm=\"a\", algorithm = SHA-384, "
                                "Digest realm=\"b\", algorithm = MD5"));
    /* Those of RFC 7616 too */
    EXPECT_EQ(sha512_256() ? "Digest realm=\"b\", nonce=\"2\", qop=\"auth\", algorithm=SHA-512-256-sess"
                           : "Digest realm=\"c\", nonce=\"3\", algorithm=MD5",
              selectedChallenge("Digest realm=\"a\", nonce=\"1\", algorithm=SHA-384, "
                                "Digest realm=\"b\", nonce=\"2\", qop=\"auth\", algorithm=SHA-512-256-sess, "
                                "Digest realm=\"c\", nonce=\"3\", algorithm=MD5"));
    EXPECT_EQ("Digest realm=\"a\", qop=\"auth\", algorithm=md5-sess",
              selectedChallenge("Digest realm=\"a\", qop=\"auth\", algorithm=md5-sess, Digest realm=\"b\""));
    /* A -sess one without a qop can't be answered */
    EXPECT_EQ("Digest realm=\"b\", nonce=\"2\", algorithm=MD5",
              selectedChallenge("Digest realm=\"a\", nonce=\"1\", algorithm=MD5-sess, "
                                "Digest realm=\"b\", nonce=\"2\", algorithm=MD5"));
    /* None to answer: all, for the error to name the first */
    EXPECT_EQ("Digest realm=\"a\", algorithm=SHA-384, Digest realm=\"b\", algorithm=AKAv2-MD5",
              selectedChallenge("Digest realm=\"a\", algorithm=SHA-384, Digest realm=\"b\", algorithm=AKAv2-MD5"));
    /* The one kept without the spaces and commas around it, or all of
     * them as they are */
    EXPECT_EQ("Digest realm=\"a\"", selectedChallenge(" \tDigest realm=\"a\" ,\r\n"));
    EXPECT_EQ(" Digest realm=\"a\", algorithm=SHA-384 ", selectedChallenge(" Digest realm=\"a\", algorithm=SHA-384 "));
    EXPECT_EQ("DIGEST realm=\"b\"", selectedChallenge("Digest\trealm=\"a\", algorithm=X, DIGEST realm=\"b\", "));
    EXPECT_EQ("Digest", selectedChallenge("Digest"));
    EXPECT_EQ("", selectedChallenge(""));
}

#endif //GTEST
