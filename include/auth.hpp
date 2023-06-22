/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
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

#pragma once

#define CKLEN 16
typedef u_char CK[CKLEN];
#define IKLEN 16
typedef u_char IK[IKLEN];

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
#define SQNLEN 6
typedef u_char SQN[SQNLEN];
#define AUTSLEN 14
typedef char AUTS[AUTSLEN];
#define AUTS64LEN 29
typedef char AUTS64[AUTS64LEN];
#define RESLEN 8
typedef unsigned char RES[RESLEN + 1];
#define RESHEXLEN 17
typedef char RESHEX[RESHEXLEN];
#define OPLEN 16
typedef u_char OP[OPLEN];

//AMF amfstar="\0";

/* end AKA */

int createAuthHeader(const char *user, const char *password, const char *method, const char *uri, const char *msgbody,
                     const char *auth, const char *aka_OP, const char *aka_AMF, const char *aka_K,
                     unsigned int nonce_count, char *result, size_t result_len, CK ck, IK ik);

int verifyAuthHeader(const char *user, const char *password,
                     const char *method, const char *auth,
                     const char *msgbody);

int getAuthParameter(const char *name, const char *header, char *result,
                     int len);

static char base64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

static char *base64_decode_string(const char *buf, unsigned int len, int *newlen) {
	unsigned long i;
	int j, x1, x2, x3, x4;
	char *out;
	out = (char *) malloc((len * 3 / 4) + 8);
	for (i = 0, j = 0; i + 3 < len; i += 4) {
		x1 = base64_val(buf[i]);
		x2 = base64_val(buf[i + 1]);
		x3 = base64_val(buf[i + 2]);
		x4 = base64_val(buf[i + 3]);
		out[j++] = (x1 << 2) | ((x2 & 0x30) >> 4);
		out[j++] = ((x2 & 0x0F) << 4) | ((x3 & 0x3C) >> 2);
		out[j++] = ((x3 & 0x03) << 6) | (x4 & 0x3F);
	}
	if (i < len) {
		x1 = base64_val(buf[i]);
		if (i + 1 < len)
			x2 = base64_val(buf[i + 1]);
		else
			x2 = -1;
		if (i + 2 < len)
			x3 = base64_val(buf[i + 2]);
		else
			x3 = -1;
		if (i + 3 < len)
			x4 = base64_val(buf[i + 3]);
		else x4 = -1;
		if (x2 != -1) {
			out[j++] = (x1 << 2) | ((x2 & 0x30) >> 4);
			if (x3 == -1) {
				out[j++] = ((x2 & 0x0F) << 4) | ((x3 & 0x3C) >> 2);
				if (x4 == -1) {
					out[j++] = ((x3 & 0x03) << 6) | (x4 & 0x3F);
				}
			}
		}

	}

	out[j++] = 0;
	*newlen = j;
	return out;
}
