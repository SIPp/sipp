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
#include <string>
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

/* AKA */

#define KLEN 16
typedef u_char K[KLEN];
#define RANDLEN 16
typedef u_char RAND[RANDLEN];
#define AUTNLEN 16
typedef u_char AUTN[AUTNLEN];

#define AKLEN 6
typedef u_char AK[AKLEN];
#define AMFLEN 2
typedef u_char AMF[AMFLEN];
#define MACLEN 8
typedef u_char MAC[MACLEN];
#define CKLEN 16
typedef u_char CK[CKLEN];
#define IKLEN 16
typedef u_char IK[IKLEN];
#define SQNLEN 6
typedef u_char SQN[SQNLEN];
#define AUTSLEN 14
typedef char AUTS[AUTSLEN];
#define AUTS64LEN 29
typedef char AUTS64[AUTS64LEN];
#define RESLEN 8
typedef unsigned char RES[RESLEN+1];
#define RESHEXLEN 17
typedef char RESHEX[RESHEXLEN];
#define OPLEN 16
typedef u_char OP[OPLEN];

AMF amfstar="\0";
SQN sqn_he= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* end AKA */


static int createAuthHeaderDigest(
    const EVP_MD* md, bool sess, const char* user, const char* password,
    int password_len, const char* method, const char* uri,
    const char* msgbody, const char* auth, const char* algo,
    unsigned int nonce_count, char* result, size_t result_len);

static int createAuthHeaderAKAv1MD5(
    const char* user, const char* OP, const char* AMF, const char* K,
    const char* method, const char* uri, const char* msgbody,
    const char* auth, const char* algo, unsigned int nonce_count,
    char* result, size_t result_len);

/* This function is from RFC 2617 Section 5 */

static void hashToHex(unsigned char* _b_raw, unsigned char* _h, unsigned short size)
{
    unsigned short i;
    unsigned char j;
    unsigned char *_b = (unsigned char *) _b_raw;

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
    _h[2 * size] = '\0';
}

static char *stristr(const char* s1, const char* s2)
{
    char *cp = (char*) s1;
    char *p1, *p2, *endp;
    char l, r;

    endp = (char*)s1 + (strlen(s1) - strlen(s2)) ;
    while (*cp && (cp <= endp)) {
        p1 = cp;
        p2 = (char*)s2;
        while (*p1 && *p2) {
            l = toupper(*p1);
            r = toupper(*p2);
            if (l != r) {
                break;
            }
            p1++;
            p2++;
        }
        if (*p2 == 0) {
            return cp;
        }
        cp++;
    }
    return 0;
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

static const DigestAlgorithm* digestAlgorithm(const char* algo)
{
    for (const DigestAlgorithm& a : digestAlgorithms) {
        if (!strcasecmp(algo, a.name)) {
            return &a;
        }
    }
    return nullptr;
}

int createAuthHeader(
    const char* user, const char* password, const char* method,
    const char* uri, const char* msgbody, const char* auth,
    const char* aka_OP, const char* aka_AMF, const char* aka_K,
    unsigned int nonce_count, char* result, size_t result_len)
{

    char algo[32] = "MD5";
    char *start;

    if ((start = stristr(auth, "Digest")) == nullptr) {
        snprintf(result, result_len, "createAuthHeader: authentication must be digest");
        return 0;
    }

    if (!method) {
        snprintf(result, result_len, "createAuthHeader: authentication requires a method");
        return 0;
    }

    getAuthParameter("algorithm", auth, algo, sizeof(algo));
    if (algo[0] == '\0') {
        strcpy(algo, "MD5");
    }

    if (strcasecmp(algo, "AKAv1-MD5")==0) {
        if (!aka_K) {
            snprintf(result, result_len, "createAuthHeader: AKAv1-MD5 authentication requires a key");
            return 0;
        }
        return createAuthHeaderAKAv1MD5(
            user, aka_OP, aka_AMF, aka_K, method, uri, msgbody, auth,
            algo, nonce_count, result, result_len);
    } else if (const DigestAlgorithm* a = digestAlgorithm(algo)) {
        if (!a->md()) {
            snprintf(result, result_len, "createAuthHeader: %s is not supported by the SSL library SIPp is built with", a->name);
            return 0;
        }
        return createAuthHeaderDigest(
            a->md(), a->sess, user, password, strlen(password), method,
            uri, msgbody, auth, algo, nonce_count, result, result_len);
    } else {
        snprintf(result, result_len, "createAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256, SHA-512-256-sess or AKAv1-MD5, not '%s'", algo);
        return 0;
    }


}


/* Where the value of parameter name starts in header, or nullptr: the
 * name must begin the header or follow a ',' or a space, outside a
 * quoted string, and have an '=' after it, with spaces around allowed.
 * So "nonce" isn't found in "cnonce", nor in realm="a, nonce=b". */
static const char* findAuthParameter(const char* name, const char* header)
{
    size_t n = strlen(name);
    bool quoted = false;
    const char* p = header;

    while (*p) {
        if (quoted && *p == '\\' && p[1]) {
            p += 2;  // an escaped character
            continue;
        }
        if (*p == '"') {
            quoted = !quoted;
        } else if (!quoted && (p == header || p[-1] == ',' || isspace(p[-1])) &&
                   !strncasecmp(p, name, n)) {
            const char* eq = p + n + strspn(p + n, " \t\r\n");
            if (*eq == '=') {
                return eq + 1 + strspn(eq + 1, " \t\r\n");
            }
        }
        p++;
    }
    return nullptr;
}

int getAuthParameter(const char *name, const char *header, char *result, int len)
{
    const char *start = findAuthParameter(name, header);
    const char *end;

    if (!start) {
        result[0] = '\0';
        return 0;
    }
    if (*start == '"') {
        start++;
        end = start;
        while (*end != '"' && *end) {
            end++;
        }
    } else {
        end = start + strcspn(start, " ,\"\r\n");
    }

    if (end - start >= len) {
        strncpy(result, start, len - 1);
        result[len - 1] = '\0';
    } else {
        strncpy(result, start, end - start);
        result[end - start] = '\0';
    }

    return end - start;
}

/* The challenge after the one at p: past a comma, outside quotes, a
 * token followed by spaces, then by neither '=' nor ',', is the next
 * one's scheme. So the auth-int of a bare qop=auth,auth-int is not. */
static char* nextChallenge(char* p)
{
    bool quoted = false;

    while (*p) {
        if (quoted && *p == '\\' && p[1]) {
            p += 2;  // an escaped character
            continue;
        }
        if (*p == '"') {
            quoted = !quoted;
        } else if (*p == ',' && !quoted) {
            char* start = p + 1 + strspn(p + 1, " \t\r\n");
            char* end = start + strcspn(start, " \t\r\n=,");
            char* after = end + strspn(end, " \t\r\n");
            if (end > start && after > end && *after && *after != '=' &&
                    *after != ',') {
                return start;
            }
        }
        p++;
    }
    return nullptr;
}

/* Keep, of the challenges in auth (headers joined by ", "), the first
 * that createAuthHeader() can answer; all of them if none. */
void selectAuthChallenge(char* auth)
{
    char* start = auth + strspn(auth, " \t");

    while (start) {
        char* next = nextChallenge(start);
        size_t len = next ? next - start : strlen(start);

        if (!strncasecmp(start, "Digest", 6) && isspace(start[6])) {
            std::string challenge(start, len);
            char algo[32], qop[16];
            const DigestAlgorithm* a;

            getAuthParameter("algorithm", challenge.c_str(), algo, sizeof(algo));
            // A -sess one has no cnonce to answer with without a qop
            if (!algo[0] || !strcasecmp(algo, "AKAv1-MD5") ||
                    ((a = digestAlgorithm(algo)) && a->md() &&
                     (!a->sess || getAuthParameter("qop", challenge.c_str(), qop, sizeof(qop))))) {
                while (len && strchr(" \t\r\n,", start[len - 1])) {
                    len--;
                }
                memmove(auth, start, len);
                auth[len] = '\0';
                return;
            }
        }
        start = next;
    }
}

static void digestString(EVP_MD_CTX* mdctx, const char* s)
{
    EVP_DigestUpdate(mdctx, s, strlen(s));
}

/* Ends the hash in mdctx, and writes it in hex: its length, 0 if the
 * SSL library failed it */
static size_t digestFinalHex(EVP_MD_CTX* mdctx, unsigned char* hex)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    if (!EVP_DigestFinal_ex(mdctx, hash, &len)) {
        len = 0;
    }
    hashToHex(hash, hex, len);
    return 2 * len;
}

/* The response, in hex, to a Digest challenge by the hash md, of a
 * -sess algorithm if sess: false, and none, if the SSL library can't
 * compute it (MD5 in FIPS mode) */
static bool createAuthResponse(
    const EVP_MD* md, bool sess, const char* user, const char* password,
    int password_len, const char* method, const char* uri,
    const char* authtype, const char* msgbody, const char* realm,
    const char* nonce, const char* cnonce, const char* nc,
    unsigned char* result)
{
    unsigned char body_hex[HASH_HEX_MAX_SIZE + 1];
    unsigned char ha1_hex[HASH_HEX_MAX_SIZE + 1], ha2_hex[HASH_HEX_MAX_SIZE + 1];
    size_t hex_len;
    char tmp[MAX_HEADER_LEN];
    bool ok = false;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    result[0] = '\0';
    // Load in A1
    if (!mdctx || !EVP_DigestInit_ex(mdctx, md, nullptr)) {
        goto end;
    }
    digestString(mdctx, user);
    digestString(mdctx, ":");
    digestString(mdctx, realm);
    digestString(mdctx, ":");
    EVP_DigestUpdate(mdctx, password, password_len);
    if (!(hex_len = digestFinalHex(mdctx, ha1_hex))) {
        goto end;
    }
    if (sess) {
        if (!EVP_DigestInit_ex(mdctx, md, nullptr)) {
            goto end;
        }
        EVP_DigestUpdate(mdctx, ha1_hex, hex_len);
        digestString(mdctx, ":");
        digestString(mdctx, nonce);
        digestString(mdctx, ":");
        digestString(mdctx, cnonce);
        if (digestFinalHex(mdctx, ha1_hex) != hex_len) {
            goto end;
        }
    }

    if (auth_uri) {
        snprintf(tmp, sizeof(tmp), "sip:%s", auth_uri);
    } else {
        snprintf(tmp, sizeof(tmp), "%s", uri);
    }
    // If using Auth-Int make a hash of the body - which is NULL for REG
    if (stristr(authtype, "auth-int") != nullptr) {
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
    digestString(mdctx, tmp);
    if (stristr(authtype, "auth-int") != nullptr) {
        digestString(mdctx, ":");
        EVP_DigestUpdate(mdctx, body_hex, hex_len);
    }
    if (digestFinalHex(mdctx, ha2_hex) != hex_len ||
            !EVP_DigestInit_ex(mdctx, md, nullptr)) {
        goto end;
    }
    EVP_DigestUpdate(mdctx, ha1_hex, hex_len);
    digestString(mdctx, ":");
    digestString(mdctx, nonce);
    if (cnonce[0] != '\0') {
        digestString(mdctx, ":");
        digestString(mdctx, nc);
        digestString(mdctx, ":");
        digestString(mdctx, cnonce);
        digestString(mdctx, ":");
        digestString(mdctx, authtype);
    }
    digestString(mdctx, ":");
    EVP_DigestUpdate(mdctx, ha2_hex, hex_len);
    ok = digestFinalHex(mdctx, result) == hex_len;
end:
    EVP_MD_CTX_free(mdctx);
    return ok;
}

int createAuthHeaderDigest(
    const EVP_MD* md, bool sess, const char* user, const char* password,
    int password_len, const char* method, const char* uri,
    const char* msgbody, const char* auth, const char* algo,
    unsigned int nonce_count, char* result, size_t result_len)
{

    unsigned char resp_hex[HASH_HEX_MAX_SIZE + 1];
    char realm[MAX_HEADER_LEN],
        sipuri[MAX_HEADER_LEN],
        nonce[MAX_HEADER_LEN],
        authtype[16],
        cnonce[32],
        nc[32],
        opaque[64];
    int has_opaque = 0;
    int written = 0;

    // Extract the Auth Type - If not present, using 'none'
    cnonce[0] = '\0';
    if (getAuthParameter("qop", auth, authtype, sizeof(authtype))) {
        // Sloppy auth type recognition (may be "auth,auth-int")
        if (stristr(authtype, "auth-int")) {
            strncpy(authtype, "auth-int", sizeof(authtype) - 1);
        } else if (stristr(authtype, "auth")) {
            strncpy(authtype, "auth", sizeof(authtype) - 1);
        }
        sprintf(cnonce, "%x", rand());
        sprintf(nc, "%08x", nonce_count);
    }

    if (sess && !cnonce[0]) {
        snprintf(result, result_len, "createAuthHeader: %s needs a qop in the challenge, for a cnonce", algo);
        return 0;
    }

    // Extract the Opaque value - if present
    if (getAuthParameter("opaque", auth, opaque, sizeof(opaque))) {
        has_opaque = 1;
    }

    // Extract the Realm
    if (!getAuthParameter("realm", auth, realm, sizeof(realm))) {
        snprintf(result, result_len, "createAuthHeader: couldn't parse realm in '%s'", auth);
        return 0;
    }

    written += snprintf(
        result + written, result_len - written,
        "Digest username=\"%s\",realm=\"%s\"", user, realm);

    // Construct the URI
    if (auth_uri == nullptr) {
        snprintf(sipuri, sizeof(sipuri), "sip:%s", uri);
    } else {
        snprintf(sipuri, sizeof(sipuri), "sip:%s", auth_uri);
    }

    if (cnonce[0] != '\0') {
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
        written += snprintf(
            result + written, result_len - written,
            ",cnonce=\"%s\",nc=%s,qop=%s", cnonce, nc, authtype);
    }
    written += snprintf(
        result + written, result_len - written, ",uri=\"%s\"", sipuri);

    // Extract the Nonce
    if (!getAuthParameter("nonce", auth, nonce, sizeof(nonce))) {
        snprintf(result, result_len, "createAuthHeader: couldn't parse nonce");
        return 0;
    }

    if (!createAuthResponse(
            md, sess, user, password, password_len, method, sipuri,
            authtype, msgbody, realm, nonce, cnonce, nc, &resp_hex[0])) {
        snprintf(result, result_len, "createAuthHeader: the SSL library failed to compute the %s response", algo);
        return 0;
    }

    written += snprintf(
        result + written, result_len - written,
        ",nonce=\"%s\",response=\"%s\",algorithm=%s", nonce, resp_hex, algo);
    if (has_opaque) {
        written += snprintf(
            result + written, result_len - written, ",opaque=\"%s\"", opaque);
    }

    return written;
}

int verifyAuthHeader(const char *user, const char *password, const char *method, const char *auth, const char *msgbody)
{
    char algo[MAX_HEADER_LEN];
    char realm[MAX_HEADER_LEN];
    char nonce[MAX_HEADER_LEN];
    char cnonce[MAX_HEADER_LEN];
    char authtype[MAX_HEADER_LEN];
    char nc[MAX_HEADER_LEN];
    char uri[MAX_HEADER_LEN];
    char *start;

    if ((start = stristr(auth, "Digest")) == nullptr) {
        WARNING("verifyAuthHeader: authentication must be digest is %s", auth);
        return 0;
    }

    getAuthParameter("algorithm", auth, algo, sizeof(algo));
    if (algo[0] == '\0') {
        strcpy(algo, "MD5");
    }
    const DigestAlgorithm* a = digestAlgorithm(algo);
    if (!a) {
        WARNING("verifyAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256 or SHA-512-256-sess, value is '%s'", algo);
        return 0;
    }
    if (!a->md()) {
        WARNING("verifyAuthHeader: %s is not supported by the SSL library SIPp is built with", a->name);
        return 0;
    }
    unsigned char result[HASH_HEX_MAX_SIZE + 1];
    char response[HASH_HEX_MAX_SIZE + 1];
    getAuthParameter("realm", auth, realm, sizeof(realm));
    getAuthParameter("uri", auth, uri, sizeof(uri));
    getAuthParameter("nonce", auth, nonce, sizeof(nonce));
    getAuthParameter("cnonce", auth, cnonce, sizeof(cnonce));
    getAuthParameter("nc", auth, nc, sizeof(nc));
    getAuthParameter("qop", auth, authtype, sizeof(authtype));
    if (a->sess && !*cnonce) {
        return 0;  // no HA1 without a cnonce
    }
    if (!createAuthResponse(
            a->md(), a->sess, user, password, strlen(password), method,
            uri, authtype, msgbody, realm, nonce, cnonce, nc, result)) {
        WARNING("verifyAuthHeader: the SSL library failed to compute the %s response", algo);
        return 0;
    }
    getAuthParameter("response", auth, response, sizeof(response));
    TRACE_CALLDEBUG("Processing verifyauth command - user %s, password %s, method %s, uri %s, realm %s, nonce %s, result expected %s, response from user %s\n",
            user,
            password,
            method,
            uri,
            realm,
            nonce,
            (char*)result,
            response);
    return *response && !strcmp((char *)result, response);
}

static char* base64_decode_string(const char* buf, unsigned int len, int* newlen)
{
    char* out = (char*)malloc((len * 3 / 4) + 8);
    if (!out) {
        *newlen = 0;
        return nullptr;
    }

    int decoded_len = EVP_DecodeBlock((unsigned char*)out,
                                       (const unsigned char*)buf, len);

    if (decoded_len < 0) {
        free(out);
        *newlen = 0;
        return nullptr;
    }

    // OpenSSL decodes the '=' padding as zero bytes, wolfSSL doesn't
    if (decoded_len == (int)(len / 4 * 3)) {
        if (len > 0 && buf[len - 1] == '=') decoded_len--;
        if (len > 1 && buf[len - 2] == '=') decoded_len--;
    }

    out[decoded_len] = '\0';
    *newlen = decoded_len;
    return out;
}

char hexa[17] = "0123456789abcdef";

/* An AKA key's bytes: those of its text, or those its hex digits after
 * "0x" give, with zeros past their end. */
static void getAKAKey(const char* text, u_char* key, size_t len)
{
    size_t n = 0;

    memset(key, 0, len);
    if (text[0] == '0' && text[1] == 'x') {
        for (text += 2; n < len && isxdigit(*text); n++) {
            int val = get_decimal_from_hex(*text++);
            if (isxdigit(*text)) {
                val = (val << 4) + get_decimal_from_hex(*text++);
            }
            key[n] = val;
        }
    } else {
        memcpy(key, text, strnlen(text, len));
    }
}

static int createAuthHeaderAKAv1MD5(
    const char* user, const char* aka_OP, const char* aka_AMF,
    const char* aka_K, const char* method, const char* uri,
    const char* msgbody, const char* auth, const char* algo,
    unsigned int nonce_count, char* result, size_t result_len)
{

    char tmp[MAX_HEADER_LEN];
    int has_auts = 0;
    int written = 0;
    char *nonce64, *nonce;
    int noncelen;
    AMF amf;
    OP op;
    RAND rnd;
    AUTS auts_bin;
    AUTS64 auts_hex;
    MAC mac, xmac;
    SQN sqn, sqnxoraka, sqn_ms;
    K k;
    RES res;
    CK ck;
    IK ik;
    AK ak;
    int i;

    // Extract the Nonce
    if (!getAuthParameter("nonce", auth, tmp, sizeof(tmp))) {
        snprintf(result, result_len, "createAuthHeaderAKAv1MD5: couldn't parse nonce");
        return 0;
    }

    /* Compute the AKA RES */
    nonce64 = tmp;
    nonce = base64_decode_string(nonce64, strlen(tmp), &noncelen);
    if (noncelen < RANDLEN + AUTNLEN) {
        if (nonce)
            free(nonce);
        snprintf(
            result, result_len,
            "createAuthHeaderAKAv1MD5 : Nonce is too short %d < %d expected\n",
            noncelen, RANDLEN + AUTNLEN);
        return 0;
    }
    memcpy(rnd, nonce, RANDLEN);
    memcpy(sqnxoraka, nonce + RANDLEN, SQNLEN);
    memcpy(mac, nonce + RANDLEN + SQNLEN + AMFLEN, MACLEN);
    /* An omitted aka_OP or aka_AMF is all zeros, not what the buffer
     * held. */
    getAKAKey(aka_K, k, KLEN);
    getAKAKey(aka_AMF, amf, AMFLEN);
    getAKAKey(aka_OP, op, OPLEN);

    /* Compute the AK, response and keys CK IK */
    f2345(k, rnd, res, ck, ik, ak, op);
    res[RESLEN] = '\0';

    /* Compute sqn encoded in AUTN */
    for (i=0; i < SQNLEN; i++)
        sqn[i] = sqnxoraka[i] ^ ak[i];

    /* compute XMAC */
    f1(k, rnd, sqn, amf, xmac, op);
    if (memcmp(mac, xmac, MACLEN) != 0) {
        free(nonce);
        snprintf(
            result, result_len,
            "createAuthHeaderAKAv1MD5 : MAC != expectedMAC -> Server might not know the secret (man-in-the-middle attack?)\n");
        return 0;
    }

    /* Check SQN, compute AUTS if needed and authorization parameter */
    /* the condition below is wrong.
     * Should trigger synchronization when sqn_ms>>3!=sqn_he>>3 for example.
     * Also, we need to store the SQN per user or put it as auth parameter. */
    if (1/*sqn[5] > sqn_he[5]*/) {
        sqn_he[5] = sqn[5];
        has_auts = 0;
        /* RES has to be used as password to compute response */
        written = createAuthHeaderDigest(
            EVP_md5(), false, user, (const char *)res, RESLEN, method, uri,
            msgbody, auth, algo, nonce_count, result, result_len);
        if (written == 0) {
            free(nonce);
            snprintf(
                result, result_len,
                "createAuthHeaderAKAv1MD5 : Unexpected return value from createAuthHeaderDigest\n");
            return 0;
        }
    } else {
        sqn_ms[5] = sqn_he[5] + 1;
        f5star(k, rnd, ak, op);
        for(i=0; i<SQNLEN; i++)
            auts_bin[i]=sqn_ms[i]^ak[i];
        f1star(k, rnd, sqn_ms, amf, (unsigned char * ) (auts_bin+SQNLEN), op);
        has_auts = 1;
        /* When re-synchronisation occurs an empty password has to be used */
        /* to compute MD5 response (Cf. rfc 3310 section 3.2) */
        written = createAuthHeaderDigest(
            EVP_md5(), false, user, "", 0, method, uri, msgbody, auth, algo,
            nonce_count, result, result_len);
        if (written == 0) {
            free(nonce);
            snprintf(
                result, result_len,
                "createAuthHeaderAKAv1MD5 : Unexpected return value from createAuthHeaderDigest\n");
            return 0;
        }
    }
    if (has_auts) {
        /* Format data for output in the SIP message */
        for (i = 0; i < AUTSLEN; i++) {
            auts_hex[2*i] = hexa[(auts_bin[i]&0xF0)>>4];
            auts_hex[2*i+1] = hexa[auts_bin[i]&0x0F];
        }
        auts_hex[AUTS64LEN-1] = 0;

        written += snprintf(
            result + written, result_len - written, ",auts=\"%s\"", auts_hex);
    }
    free(nonce);
    return written;
}


#ifdef GTEST
#include "gtest/gtest.h"

TEST(DigestAuth, nonce) {
    char nonce[40];
    getAuthParameter("nonce", " Authorization: Digest cnonce=\"c7e1249f\",nonce=\"a6ca2bf13de1433183f7c48781bd9304\"", nonce, sizeof(nonce));
    EXPECT_STREQ("a6ca2bf13de1433183f7c48781bd9304", nonce);
    getAuthParameter("nonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\", cnonce=\"c7e1249f\"", nonce, sizeof(nonce));
    EXPECT_STREQ("a6ca2bf13de1433183f7c48781bd9304", nonce);
}

TEST(DigestAuth, cnonce) {
    char cnonce[10];
    getAuthParameter("cnonce", " Authorization: Digest cnonce=\"c7e1249f\",nonce=\"a6ca2bf13de1433183f7c48781bd9304\"", cnonce, sizeof(cnonce));
    EXPECT_STREQ("c7e1249f", cnonce);
    getAuthParameter("cnonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\", cnonce=\"c7e1249f\"", cnonce, sizeof(cnonce));
    EXPECT_STREQ("c7e1249f", cnonce);
}

TEST(DigestAuth, MissingParameter) {
    char cnonce[10];
    getAuthParameter("cnonce", " Authorization: Digest nonce=\"a6ca2bf13de1433183f7c48781bd9304\"", cnonce, sizeof(cnonce));
    EXPECT_EQ('\0', cnonce[0]);
}

TEST(DigestAuth, BasicVerification) {
    char* header = strdup(("Digest \r\n"
                           " realm=\"testrealm@host.com\",\r\n"
                           " nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n,"
                           " opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    char result[255];
    createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "hello world", header, nullptr, nullptr, nullptr, 1, result, 255);
    EXPECT_STREQ("Digest username=\"testuser\",realm=\"testrealm@host.com\",uri=\"sip:sip:example.com\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",response=\"db94e01e92f2b09a52a234eeca8b90f7\",algorithm=MD5,opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"", result);
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
    free(header);
}

TEST(DigestAuth, BasicVerificationSHA256) {
    char* header = strdup(("Digest \r\n"
                           " realm=\"testrealm@host.com\",\r\n"
                           " nonce=\"ZaGxV2WhsCtREI2EsiD1LR0RYd\"\r\n,"
                           " algorithm=SHA-256"));
    char result[255];
    createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "hello world", header, nullptr, nullptr, nullptr, 1, result, 255);
    EXPECT_STREQ("Digest username=\"testuser\",realm=\"testrealm@host.com\",uri=\"sip:sip:example.com\",nonce=\"ZaGxV2WhsCtREI2EsiD1LR0RYd\",response=\"91b58523b983191b52d14455a2599631990110c974ed2e4b4b49bc6053af04ce\",algorithm=SHA-256", result);
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
    free(header);
}

TEST(DigestAuth, MissingResponse) {
    /* Not the response of any password, were none computed */
    const char* header = "Digest username=\"testuser\",realm=\"r\",uri=\"sip:x\",nonce=\"n\",algorithm=MD5";
    EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "REGISTER", header, ""));
    EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "REGISTER",
                                  (std::string(header) + ",response=\"\"").c_str(), ""));
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
    EXPECT_EQ(1, verifyAuthHeader("Mufasa", "Circle of Life", method, auth.c_str(), body)) << auth;
    EXPECT_EQ(0, verifyAuthHeader("Mufasa", "Circle of life", method, auth.c_str(), body)) << auth;

    unsigned char result[HASH_HEX_MAX_SIZE + 1];
    EXPECT_TRUE(createAuthResponse(a->md(), a->sess, "Mufasa", "Circle of Life",
                                   strlen("Circle of Life"), method, uri, qop, body,
                                   "http-auth@example.org",
                                   "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
                                   "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
                                   nc, result));
    EXPECT_STREQ(response, (char*)result) << algo;
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
    char result[1024];
    char* header = strdup(("Digest \r\n"
                           "\trealm=\"testrealm@host.com\",\r\n"
                           "\tqop=\"auth,auth-int\",\r\n"
                           "\tnonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n,"
                           "\topaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
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
                     result,
                     1024);
    EXPECT_EQ(1, !!strstr(result, ",qop=auth-int,")); // no double quotes around qop-value
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
    free(header);
}

TEST(DigestAuth, SessAlgorithms) {
    char result[1024];
    const char* algos[] = {"MD5-sess", "SHA-256-sess", "SHA-512-256", "sha-512-256-SESS"};
    const char* qops[] = {"auth", "auth-int", "auth,auth-int"};

    for (const char* algo : algos) {
        if (!digestAlgorithm(algo)->md()) {
            continue;
        }
        for (const char* qop : qops) {
            std::string challenge = std::string("Digest realm=\"r\", nonce=\"n\", qop=\"") + qop +
                                    "\", algorithm=" + algo;
            ASSERT_LT(0, createAuthHeader("testuser", "secret", "INVITE", "bob@example.com", "v=0\r\n",
                                          challenge.c_str(), nullptr, nullptr, nullptr, 1, result,
                                          sizeof(result))) << result;
            /* The algorithm as the challenge has it */
            EXPECT_NE(nullptr, strstr(result, (std::string(",algorithm=") + algo).c_str())) << result;
            EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "INVITE", result, "v=0\r\n")) << result;
            /* auth-int covers the body */
            EXPECT_EQ(!strcmp(qop, "auth"),
                      verifyAuthHeader("testuser", "secret", "INVITE", result, "v=1\r\n")) << result;
            EXPECT_EQ(0, verifyAuthHeader("testuser", "Secret", "INVITE", result, "v=0\r\n")) << result;
            /* Not the response of the algorithm without -sess */
            std::string other = result;
            size_t at = other.find("-sess");
            if (at == std::string::npos) {
                at = other.find("-SESS");
            }
            if (at != std::string::npos) {
                other.erase(at, 5);
                EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "INVITE", other.c_str(), "v=0\r\n"))
                    << other;
            }
        }
    }

    /* A -sess one has no cnonce without a qop */
    EXPECT_EQ(0, createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "",
                                  "Digest realm=\"r\", nonce=\"n\", algorithm=MD5-sess",
                                  nullptr, nullptr, nullptr, 1, result, sizeof(result)));
    EXPECT_STREQ("createAuthHeader: MD5-sess needs a qop in the challenge, for a cnonce", result);
    unsigned char response[HASH_HEX_MAX_SIZE + 1];
    EXPECT_TRUE(createAuthResponse(EVP_md5(), true, "testuser", "secret", strlen("secret"), "REGISTER",
                                   "sip:x", "", "", "r", "n", "", "", response));
    EXPECT_EQ(0, verifyAuthHeader("testuser", "secret", "REGISTER",
                                  (std::string("Digest username=\"testuser\",realm=\"r\",uri=\"sip:x\",nonce=\"n\","
                                               "response=\"") + (char*)response + "\",algorithm=MD5-sess").c_str(), ""));
    /* SHA-512-256 without a qop, as RFC 2069 */
    if (sha512_256()) {
        ASSERT_LT(0, createAuthHeader("testuser", "secret", "REGISTER", "example.com", "",
                                      "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-512-256",
                                      nullptr, nullptr, nullptr, 1, result, sizeof(result)));
        EXPECT_EQ(nullptr, strstr(result, "cnonce")) << result;
        EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "")) << result;
    }

    /* Still none of another algorithm */
    EXPECT_EQ(0, createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "",
                                  "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-384",
                                  nullptr, nullptr, nullptr, 1, result, sizeof(result)));
    EXPECT_STREQ("createAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, "
                 "SHA-512-256, SHA-512-256-sess or AKAv1-MD5, not 'SHA-384'", result);
}

TEST(DigestAuth, base64_decode_string) {
    int len;
    char* out = base64_decode_string("YWJj", 4, &len);
    ASSERT_NE(nullptr, out);
    EXPECT_EQ(3, len);
    EXPECT_STREQ("abc", out);
    free(out);
    out = base64_decode_string("YWJjZGU=", 8, &len);
    ASSERT_NE(nullptr, out);
    EXPECT_EQ(5, len);
    EXPECT_STREQ("abcde", out);
    free(out);
    out = base64_decode_string("YWJjZA==", 8, &len);
    ASSERT_NE(nullptr, out);
    EXPECT_EQ(4, len);
    EXPECT_STREQ("abcd", out);
    free(out);
    /* Zero bytes are decoded, not taken as padding */
    out = base64_decode_string("AAAA", 4, &len);
    ASSERT_NE(nullptr, out);
    EXPECT_EQ(3, len);
    EXPECT_EQ(0, memcmp("\0\0\0", out, 4));
    free(out);
    EXPECT_EQ(nullptr, base64_decode_string("YW!j", 4, &len));
    EXPECT_EQ(0, len);
}

TEST(DigestAuth, AKAv1MD5HexKeys) {
    /* 3GPP TS 35.208 test set 1, whose K has 0x0A and 0x5B bytes: the
     * challenge has its RAND and AUTN, the response its RES. */
    char result[1024];
    const char* header = "Digest realm=\"r\", nonce=\"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=\", algorithm=AKAv1-MD5";
    ASSERT_NE(0, createAuthHeader("alice", "", "REGISTER", "sip:example.com", "", header,
                                  "0xCDC202D5123E20F62B6D676AC72CB318", "0xB9B9",
                                  "0x465B5CE8B199B49FAA5F0A2EE238A6BC", 1, result, sizeof(result)))
        << result;
    EXPECT_NE(nullptr, strstr(result, ",response=\"1efe54bb65c7771548e279052d82bd09\",")) << result;
    /* Spaces around the nonce's '=' */
    header = "Digest realm=\"r\", nonce = \"I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=\", algorithm=AKAv1-MD5";
    ASSERT_NE(0, createAuthHeader("alice", "", "REGISTER", "sip:example.com", "", header,
                                  "0xCDC202D5123E20F62B6D676AC72CB318", "0xB9B9",
                                  "0x465B5CE8B199B49FAA5F0A2EE238A6BC", 1, result, sizeof(result)))
        << result;
    EXPECT_NE(nullptr, strstr(result, ",response=\"1efe54bb65c7771548e279052d82bd09\",")) << result;
}

TEST(DigestAuth, getAuthParameter) {
    char v[64];
    EXPECT_EQ(3, getAuthParameter("nonce", "Digest nonce=abc", v, sizeof(v)));
    EXPECT_STREQ("abc", v);
    /* Spaces around '=', a quoted value */
    getAuthParameter("algorithm", "Digest realm=\"r\", algorithm = SHA-256", v, sizeof(v));
    EXPECT_STREQ("SHA-256", v);
    getAuthParameter("realm", "Digest realm= \"a b\"", v, sizeof(v));
    EXPECT_STREQ("a b", v);
    /* Not in cnonce, nor in another parameter's quoted value */
    getAuthParameter("nonce", "Digest cnonce=\"x\", nonce=\"y\"", v, sizeof(v));
    EXPECT_STREQ("y", v);
    getAuthParameter("algorithm", "Digest realm=\"a, algorithm=SHA-256\", algorithm=MD5", v, sizeof(v));
    EXPECT_STREQ("MD5", v);
    getAuthParameter("nonce", "Digest realm=\"a\\\", nonce=bad\", nonce=good", v, sizeof(v));
    EXPECT_STREQ("good", v);
    EXPECT_EQ(0, getAuthParameter("opaque", "Digest realm=\"opaque=x\"", v, sizeof(v)));
    EXPECT_STREQ("", v);
}

static std::string selectedChallenge(const char* auth)
{
    char buf[1024];
    strcpy(buf, auth);
    selectAuthChallenge(buf);
    return buf;
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
}

#endif //GTEST
