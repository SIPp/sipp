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
 *  Authors: F. Tarek Rogers - 01 Sept 2004
 *           Russell Roy
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>

#define MAX_HEADER_LEN  2049
#define MD5_HASH_SIZE 16
#define HASH_HEX_SIZE 2*MD5_HASH_SIZE

extern char               *auth_uri;


/* This function is from RFC 2617 Section 5 */

void hashToHex (unsigned char *_b, unsigned char *_h)
{
    unsigned short i;
    unsigned char j;

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

char *stristr (const char *s1, const char *s2) {
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

int createAuthHeader(char * user, char * password, char * method,
                     char * uri, char * msgbody, char * auth, char * result) {

    unsigned char ha1[MD5_HASH_SIZE], ha2[MD5_HASH_SIZE];
    unsigned char resp[MD5_HASH_SIZE], body[MD5_HASH_SIZE]; 
    unsigned char ha1_hex[HASH_HEX_SIZE+1], ha2_hex[HASH_HEX_SIZE+1];
    unsigned char resp_hex[HASH_HEX_SIZE+1], body_hex[HASH_HEX_SIZE+1];
    char tmp[MAX_HEADER_LEN], authtype[16], cnonce[32], nc[32], algo[32]="MD5", opaque[64];
    char *start, *end;
    static unsigned int mync = 1;
    int has_opaque = 0;
    MD5_CTX Md5Ctx;

    if ((start = stristr(auth, "Digest")) == NULL) {
        sprintf(result, "createAuthHeader: authentication must be digest");
        return 0;
    }
    // extract the algo. If it is not "MD5", exit with an error
    if ((start = stristr(auth, "algorithm=")) != NULL) {
        start = start + strlen("algorithm=");
        if (*start == '"') { start++; }
        end = start + strcspn(start, " ,\"\r\n");
        strncpy(algo, start, end - start);
        algo[end - start] ='\0';

        if (strncasecmp(algo, "MD5", 3)) {
            sprintf(result, "createAuthHeader: authentication must use MD5");
            return 0;
        }
    }

    // Extract the Auth Type - If not present, using 'none' 
    cnonce[0] = '\0';
    if ((start = stristr(auth, "qop=")) != NULL) {
        start = start + strlen("qop=");
        if (*start == '"') { start++; }
        end = start + strcspn(start, " ,\"\r\n");
        strncpy(authtype, start, end - start);
        authtype[end - start] ='\0';
        sprintf(cnonce, "%x", rand());
        sprintf(nc, "%08x", mync++);
    }

    // Extract the Opaque value - if present
    opaque[0] = '\0';
    if ((start = stristr(auth, "opaque=")) != NULL) {
        start = start + strlen("opaque=");
        if (*start == '"') { start++; }
        end = start + strcspn(start, " ,\"\r\n");
        strncpy(opaque, start, end - start);
        opaque[end - start] ='\0';
        has_opaque = 1;
    }

    // Extract the Realm 
    if ((start = stristr(auth, "realm=")) == NULL) {
        sprintf(result, "createAuthHeader: couldn't parse realm");
        return 0;
    }
    start = start + strlen("realm=");
    if (*start == '"') { start++; }       
    end = start + strcspn(start, ",\"\r\n");
    strncpy(tmp, start, end - start);
    tmp[end - start] ='\0';

    // Load in A1 
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, user, strlen(user));
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, tmp, strlen(tmp));
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, password, strlen(password));
    MD5_Final(ha1, &Md5Ctx);
    hashToHex(&ha1[0], &ha1_hex[0]);

    sprintf(result, "Digest username=\"%s\",realm=\"%s\"",user,tmp);
    if (cnonce[0] != '\0') {
        sprintf(result, "%s,cnonce=\"%s\",nc=%s,qop=%s",result,cnonce,nc,authtype);
    }

    // Construct the URI 
    if (auth_uri == NULL) {
      sprintf(tmp, "sip:%s", uri);
    } else {
      sprintf(tmp, "sip:%s", auth_uri);
    }

    // If using Auth-Int make a hash of the body - which is NULL for REG 
    if (stristr(authtype, "auth-int") != NULL) {
        MD5_Init(&Md5Ctx);
        MD5_Update(&Md5Ctx, msgbody, strlen(msgbody));
        MD5_Final(body, &Md5Ctx);
        hashToHex(&body[0], &body_hex[0]);
    }

    // Load in A2 
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, method, strlen(method));
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, tmp, strlen(tmp));
    if (stristr(authtype, "auth-int") != NULL) {
        MD5_Update(&Md5Ctx, ":", 1);
        MD5_Update(&Md5Ctx, &body_hex, HASH_HEX_SIZE);
    }
    MD5_Final(ha2, &Md5Ctx);
    hashToHex(&ha2[0], &ha2_hex[0]);

    sprintf(result, "%s,uri=\"%s\"",result,tmp);

    // Extract the Nonce 
    if ((start = stristr(auth, "nonce=")) == NULL) {
        sprintf(result, "createAuthHeader: couldn't parse nonce");
        return 0;
    }
    start = start + strlen("nonce=");
    if (*start == '"') { start++; }
    end = start + strcspn(start, " ,\"\r\n");
    strncpy(tmp, start, end - start);
    tmp[end - start] ='\0';

    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, &ha1_hex, HASH_HEX_SIZE);
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, tmp, strlen(tmp));
    if (cnonce[0] != '\0') {
        MD5_Update(&Md5Ctx, ":", 1);
        MD5_Update(&Md5Ctx, nc, strlen(nc));
        MD5_Update(&Md5Ctx, ":", 1);
        MD5_Update(&Md5Ctx, cnonce, strlen(cnonce));
        MD5_Update(&Md5Ctx, ":", 1);
        MD5_Update(&Md5Ctx, authtype, strlen(authtype));
    }
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, &ha2_hex, HASH_HEX_SIZE);
    MD5_Final(resp, &Md5Ctx);
    hashToHex(&resp[0], &resp_hex[0]);

    sprintf(result, "%s,nonce=\"%s\",response=\"%s\",algorithm=%s",result,tmp,resp_hex,algo);

    if (has_opaque) {
        sprintf(result, "%s,opaque=\"%s\"",result,opaque);
    }

    return 1;
}


