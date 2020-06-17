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
#include "md5.h"
#include "milenage.h"
#include "screen.hpp"
#include "logger.hpp"
#include "auth.hpp"

#define MAX_HEADER_LEN  2049
#define MD5_HASH_SIZE 16
#define HASH_HEX_SIZE 2*MD5_HASH_SIZE

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


int createAuthHeaderMD5(const char *user,
                        const char *password,
                        int password_len,
                        const char *method,
                        const char *uri,
                        const char *msgbody,
                        const char *auth,
                        const char *algo,
                        unsigned int nonce_count,
                        char *result);
int createAuthHeaderAKAv1MD5(const char *user,
                             const char *OP,
                             const char *AMF,
                             const char *K,
                             const char *method,
                             const char *uri,
                             const char *msgbody,
                             const char *auth,
                             const char *algo,
                             unsigned int nonce_count,
                             char * result);


/* This function is from RFC 2617 Section 5 */

static void hashToHex(md5_byte_t* _b_raw, unsigned char* _h)
{
    unsigned short i;
    unsigned char j;
    unsigned char *_b = (unsigned char *) _b_raw;

    for (i = 0; i < MD5_HASH_SIZE; i++) {
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
    _h[HASH_HEX_SIZE] = '\0';
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

int createAuthHeader(const char *user, const char *password, const char *method,
                     const char *uri, const char *msgbody, const char *auth,
                     const char *aka_OP,
                     const char *aka_AMF,
                     const char *aka_K,
                     unsigned int nonce_count,
                     char *result)
{

    char algo[32]="MD5";
    char *start, *end;

    if ((start = stristr(auth, "Digest")) == NULL) {
        sprintf(result, "createAuthHeader: authentication must be digest");
        return 0;
    }

    if ((start = stristr(auth, "algorithm=")) != NULL) {
        start = start + strlen("algorithm=");
        if (*start == '"') {
            start++;
        }
        end = start + strcspn(start, " ,\"\r\n");
        strncpy(algo, start, end - start);
        algo[end - start] ='\0';

    }

    if (strncasecmp(algo, "MD5", 3)==0) {
        return createAuthHeaderMD5(user, password, strlen(password), method,
                                   uri, msgbody, auth, algo, nonce_count, result);
    } else if (strncasecmp(algo, "AKAv1-MD5", 9)==0) {
        if (!aka_K) {
            sprintf(result, "createAuthHeader: AKAv1-MD5 authentication requires a key");
            return 0;
        }
        return createAuthHeaderAKAv1MD5(user, aka_OP, aka_AMF, aka_K, method,
                                        uri, msgbody, auth, algo, nonce_count, result);
    } else {
        sprintf(result, "createAuthHeader: authentication must use MD5 or AKAv1-MD5");
        return 0;
    }


}


int getAuthParameter(const char *name, const char *header, char *result, int len)
{
    char *start, *end;

    start = stristr(header, name);
    while (start) {
        // Ensure that the preceding character is "," or whitespace - this
        // stops us finding "cnonce" when we search for "nonce".
        char preceding_char = start[-1];
        if ((preceding_char == ',')
            || isspace(preceding_char)) {
            break;
        }
        start = stristr(start+1, name);
    }

    if (!start) {
        result[0] = '\0';
        return 0;
    }
    start += strlen(name);
    if (*start++ != '=') {
        return getAuthParameter(name, start, result, len);
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

static int createAuthResponseMD5(const char* user,
                                 const char* password,
                                 int password_len,
                                 const char* method,
                                 const char* uri,
                                 const char* authtype,
                                 const char* msgbody,
                                 const char* realm,
                                 const char* nonce,
                                 const char* cnonce,
                                 const char* nc,
                                 unsigned char* result)
{
    md5_byte_t ha1[MD5_HASH_SIZE], ha2[MD5_HASH_SIZE];
    md5_byte_t resp[MD5_HASH_SIZE], body[MD5_HASH_SIZE];
    unsigned char body_hex[HASH_HEX_SIZE+1];
    unsigned char ha1_hex[HASH_HEX_SIZE+1], ha2_hex[HASH_HEX_SIZE+1];
    char tmp[MAX_HEADER_LEN];
    md5_state_t Md5Ctx;

    // Load in A1
    md5_init(&Md5Ctx);
    md5_append(&Md5Ctx, (md5_byte_t *) user, strlen(user));
    md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
    md5_append(&Md5Ctx, (md5_byte_t *) realm, strlen(realm));
    md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
    md5_append(&Md5Ctx, (md5_byte_t *) password, password_len);
    md5_finish(&Md5Ctx, ha1);
    hashToHex(&ha1[0], &ha1_hex[0]);

    if (auth_uri) {
        sprintf(tmp, "sip:%s", auth_uri);
    } else {
        strncpy(tmp, uri, sizeof(tmp) - 1);
    }
    // If using Auth-Int make a hash of the body - which is NULL for REG
    if (stristr(authtype, "auth-int") != NULL) {
        md5_init(&Md5Ctx);
        md5_append(&Md5Ctx, (md5_byte_t *) msgbody, strlen(msgbody));
        md5_finish(&Md5Ctx, body);
        hashToHex(&body[0], &body_hex[0]);
    }

    // Load in A2
    md5_init(&Md5Ctx);
    md5_append(&Md5Ctx, (md5_byte_t *) method, strlen(method));
    md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
    md5_append(&Md5Ctx, (md5_byte_t *) tmp, strlen(tmp));
    if (stristr(authtype, "auth-int") != NULL) {
        md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
        md5_append(&Md5Ctx, (md5_byte_t *) &body_hex, HASH_HEX_SIZE);
    }
    md5_finish(&Md5Ctx, ha2);
    hashToHex(&ha2[0], &ha2_hex[0]);

    md5_init(&Md5Ctx);
    md5_append(&Md5Ctx, (md5_byte_t *) &ha1_hex, HASH_HEX_SIZE);
    md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
    md5_append(&Md5Ctx, (md5_byte_t *) nonce, strlen(nonce));
    if (cnonce[0] != '\0') {
        md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
        md5_append(&Md5Ctx, (md5_byte_t *) nc, strlen(nc));
        md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
        md5_append(&Md5Ctx, (md5_byte_t *) cnonce, strlen(cnonce));
        md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
        md5_append(&Md5Ctx, (md5_byte_t *) authtype, strlen(authtype));
    }
    md5_append(&Md5Ctx, (md5_byte_t *) ":", 1);
    md5_append(&Md5Ctx, (md5_byte_t *) &ha2_hex, HASH_HEX_SIZE);
    md5_finish(&Md5Ctx, resp);
    hashToHex(&resp[0], result);

    return 1;
}

int createAuthHeaderMD5(const char *user,
                        const char *password,
                        int password_len,
                        const char *method,
                        const char *uri,
                        const char *msgbody,
                        const char *auth,
                        const char *algo,
                        unsigned int nonce_count,
                        char *result)
{

    unsigned char resp_hex[HASH_HEX_SIZE+1];
    char tmp[MAX_HEADER_LEN],
        tmp2[MAX_HEADER_LEN],
        realm[MAX_HEADER_LEN],
        sipuri[MAX_HEADER_LEN],
        nonce[MAX_HEADER_LEN],
        authtype[16],
        cnonce[32],
        nc[32],
        opaque[64];
    int has_opaque = 0;

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

    // Extract the Opaque value - if present
    if (getAuthParameter("opaque", auth, opaque, sizeof(opaque))) {
        has_opaque = 1;
    }

    // Extract the Realm
    if (!getAuthParameter("realm", auth, realm, sizeof(realm))) {
        sprintf(result, "createAuthHeaderMD5: couldn't parse realm in '%s'", auth);
        return 0;
    }

    sprintf(result, "Digest username=\"%s\",realm=\"%s\"", user, realm);

    // Construct the URI
    if (auth_uri == NULL) {
        sprintf(sipuri, "sip:%s", uri);
    } else {
        sprintf(sipuri, "sip:%s", auth_uri);
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
        snprintf(tmp, sizeof(tmp), ",cnonce=\"%s\",nc=%s,qop=%s", cnonce, nc, authtype);
        strcat(result, tmp);
    }
    snprintf(tmp, sizeof(tmp), ",uri=\"%s\"", sipuri);
    strcat(result, tmp);

    // Extract the Nonce
    if (!getAuthParameter("nonce", auth, nonce, sizeof(nonce))) {
        sprintf(result, "createAuthHeader: couldn't parse nonce");
        return 0;
    }

    createAuthResponseMD5(user,
                          password,
                          strlen(password),
                          method,
                          sipuri,
                          authtype,
                          msgbody,
                          realm,
                          nonce,
                          cnonce,
                          nc,
                          &resp_hex[0]);

    snprintf(tmp2, sizeof(tmp2), ",nonce=\"%s\",response=\"%s\",algorithm=%s", nonce, resp_hex, algo);
    strcat(result, tmp2);

    if (has_opaque) {
        snprintf(tmp2, sizeof(tmp2), ",opaque=\"%s\"", opaque);
        strcat(result, tmp2);
    }

    return 1;
}

int verifyAuthHeader(const char *user, const char *password, const char *method, const char *auth, const char *msgbody)
{
    char algo[MAX_HEADER_LEN];
    unsigned char result[HASH_HEX_SIZE + 1];
    char response[HASH_HEX_SIZE + 1];
    char realm[MAX_HEADER_LEN];
    char nonce[MAX_HEADER_LEN];
    char cnonce[MAX_HEADER_LEN];
    char authtype[MAX_HEADER_LEN];
    char nc[MAX_HEADER_LEN];
    char uri[MAX_HEADER_LEN];
    char *start;

    if ((start = stristr(auth, "Digest")) == NULL) {
        WARNING("verifyAuthHeader: authentication must be digest is %s", auth);
        return 0;
    }

    getAuthParameter("algorithm", auth, algo, sizeof(algo));
    if (algo[0] == '\0') {
        strcpy(algo, "MD5");
    }
    if (strncasecmp(algo, "MD5", 3)==0) {
        getAuthParameter("realm", auth, realm, sizeof(realm));
        getAuthParameter("uri", auth, uri, sizeof(uri));
        getAuthParameter("nonce", auth, nonce, sizeof(nonce));
        getAuthParameter("cnonce", auth, cnonce, sizeof(cnonce));
        getAuthParameter("nc", auth, nc, sizeof(nc));
        getAuthParameter("qop", auth, authtype, sizeof(authtype));
        createAuthResponseMD5(user,
                              password,
                              strlen(password),
                              method,
                              uri,
                              authtype,
                              msgbody,
                              realm,
                              nonce,
                              cnonce,
                              nc,
                              result);
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
        return !strcmp((char *)result, response);
    } else {
        WARNING("createAuthHeader: authentication must use MD5 or AKAv1-MD5, value is '%s'", algo);
        return 0;
    }
}



/*"
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";*/
static int base64_val(char x) {
    switch(x) {
    case '=':
        return -1;
    case 'A':
        return 0;
    case 'B':
        return 1;
    case 'C':
        return 2;
    case 'D':
        return 3;
    case 'E':
        return 4;
    case 'F':
        return 5;
    case 'G':
        return 6;
    case 'H':
        return 7;
    case 'I':
        return 8;
    case 'J':
        return 9;
    case 'K':
        return 10;
    case 'L':
        return 11;
    case 'M':
        return 12;
    case 'N':
        return 13;
    case 'O':
        return 14;
    case 'P':
        return 15;
    case 'Q':
        return 16;
    case 'R':
        return 17;
    case 'S':
        return 18;
    case 'T':
        return 19;
    case 'U':
        return 20;
    case 'V':
        return 21;
    case 'W':
        return 22;
    case 'X':
        return 23;
    case 'Y':
        return 24;
    case 'Z':
        return 25;
    case 'a':
        return 26;
    case 'b':
        return 27;
    case 'c':
        return 28;
    case 'd':
        return 29;
    case 'e':
        return 30;
    case 'f':
        return 31;
    case 'g':
        return 32;
    case 'h':
        return 33;
    case 'i':
        return 34;
    case 'j':
        return 35;
    case 'k':
        return 36;
    case 'l':
        return 37;
    case 'm':
        return 38;
    case 'n':
        return 39;
    case 'o':
        return 40;
    case 'p':
        return 41;
    case 'q':
        return 42;
    case 'r':
        return 43;
    case 's':
        return 44;
    case 't':
        return 45;
    case 'u':
        return 46;
    case 'v':
        return 47;
    case 'w':
        return 48;
    case 'x':
        return 49;
    case 'y':
        return 50;
    case 'z':
        return 51;
    case '0':
        return 52;
    case '1':
        return 53;
    case '2':
        return 54;
    case '3':
        return 55;
    case '4':
        return 56;
    case '5':
        return 57;
    case '6':
        return 58;
    case '7':
        return 59;
    case '8':
        return 60;
    case '9':
        return 61;
    case '+':
        return 62;
    case '/':
        return 63;
    }
    return 0;
}

static char* base64_decode_string(const char* buf, unsigned int len, int* newlen)
{
    unsigned long i;
    int j, x1, x2, x3, x4;
    char *out;
    out = (char *)malloc( ( len * 3/4 ) + 8 );
    for(i=0, j=0; i + 3 < len; i += 4) {
        x1=base64_val(buf[i]);
        x2=base64_val(buf[i+1]);
        x3=base64_val(buf[i+2]);
        x4=base64_val(buf[i+3]);
        out[j++]=(x1<<2) | ((x2 & 0x30)>>4);
        out[j++]=((x2 & 0x0F)<<4) | ((x3 & 0x3C)>>2);
        out[j++]=((x3 & 0x03)<<6) | (x4 & 0x3F);
    }
    if (i<len) {
        x1 = base64_val(buf[i]);
        if (i+1<len)
            x2=base64_val(buf[i+1]);
        else
            x2=-1;
        if (i+2<len)
            x3=base64_val(buf[i+2]);
        else
            x3=-1;
        if(i+3<len)
            x4=base64_val(buf[i+3]);
        else x4=-1;
        if (x2!=-1) {
            out[j++]=(x1<<2) | ((x2 & 0x30)>>4);
            if (x3==-1) {
                out[j++]=((x2 & 0x0F)<<4) | ((x3 & 0x3C)>>2);
                if (x4==-1) {
                    out[j++]=((x3 & 0x03)<<6) | (x4 & 0x3F);
                }
            }
        }

    }

    out[j++] = 0;
    *newlen=j;
    return out;
}

char base64[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char hexa[17]="0123456789abcdef";
int createAuthHeaderAKAv1MD5(const char *user, const char *aka_OP,
                             const char *aka_AMF, const char *aka_K,
                             const char *method, const char *uri,
                             const char *msgbody, const char *auth,
                             const char *algo, unsigned int nonce_count,
                             char *result)
{

    char tmp[MAX_HEADER_LEN];
    char *start, *end;
    int has_auts = 0, resuf = 1;
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
    if ((start = stristr(auth, "nonce=")) == NULL) {
        sprintf(result, "createAuthHeaderAKAv1MD5: couldn't parse nonce");
        return 0;
    }
    start = start + strlen("nonce=");
    if (*start == '"') {
        start++;
    }
    end = start + strcspn(start, " ,\"\r\n");
    strncpy(tmp, start, end - start);
    tmp[end - start] ='\0';

    /* Compute the AKA RES */
    nonce64 = tmp;
    nonce = base64_decode_string(nonce64, end-start, &noncelen);
    if (noncelen < RANDLEN + AUTNLEN) {
        sprintf(result, "createAuthHeaderAKAv1MD5 : Nonce is too short %d < %d expected \n",
                noncelen, RANDLEN + AUTNLEN);
        if (nonce)
            free(nonce);
        return 0;
    }
    memcpy(rnd, nonce, RANDLEN);
    memcpy(sqnxoraka, nonce + RANDLEN, SQNLEN);
    memcpy(mac, nonce + RANDLEN + SQNLEN + AMFLEN, MACLEN);
    memcpy(k, aka_K, KLEN);
    memcpy(amf, aka_AMF, AMFLEN);
    memcpy(op, aka_OP, OPLEN);

    /* Compute the AK, response and keys CK IK */
    f2345(k, rnd, res, ck, ik, ak, op);
    res[RESLEN] = '\0';

    /* Compute sqn encoded in AUTN */
    for (i=0; i < SQNLEN; i++)
        sqn[i] = sqnxoraka[i] ^ ak[i];

    /* compute XMAC */
    f1(k, rnd, sqn, (unsigned char *) aka_AMF, xmac, op);
    if (memcmp(mac, xmac, MACLEN) != 0) {
        free(nonce);
        sprintf(result, "createAuthHeaderAKAv1MD5 : MAC != eXpectedMAC -> Server might not know the secret (man-in-the-middle attack?) \n");
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
        resuf = createAuthHeaderMD5(user, (char *) res, RESLEN, method, uri, msgbody, auth, algo, nonce_count, result);
        if (resuf == 0) {
            sprintf(result, "createAuthHeaderAKAv1MD5 : Unexpected return value from createAuthHeaderMD5\n");
            free(nonce);
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
        resuf = createAuthHeaderMD5(user, "", 0, method, uri, msgbody, auth, algo, nonce_count, result);
        if (resuf == 0) {
            sprintf(result, "createAuthHeaderAKAv1MD5 : Unexpected return value from createAuthHeaderMD5\n");
            free(nonce);
            return 0;
        }
    }
    if (has_auts) {
        /* Format data for output in the SIP message */
        for(i=0; i<AUTSLEN; i++) {
            auts_hex[2*i]=hexa[(auts_bin[i]&0xF0)>>4];
            auts_hex[2*i+1]=hexa[auts_bin[i]&0x0F];
        }
        auts_hex[AUTS64LEN-1]=0;

        sprintf(tmp, "%s,auts=\"%s\"", result, auts_hex);
        strcat(result, tmp);
    }
    free(nonce);
    return 1;
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
    createAuthHeader("testuser", "secret", "REGISTER", "sip:example.com", "hello world", header, NULL, NULL, NULL, 1, result);
    EXPECT_STREQ("Digest username=\"testuser\",realm=\"testrealm@host.com\",uri=\"sip:sip:example.com\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",response=\"db94e01e92f2b09a52a234eeca8b90f7\",algorithm=MD5,opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"", result);
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
    free(header);
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
                     NULL,
                     NULL,
                     NULL,
                     1,
                     result);
    EXPECT_EQ(1, !!strstr(result, ",qop=auth-int,")); // no double quotes around qop-value
    EXPECT_EQ(1, verifyAuthHeader("testuser", "secret", "REGISTER", result, "hello world"));
    free(header);
}

#endif //GTEST
