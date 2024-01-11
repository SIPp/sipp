//
// Created by dbori on 18.06.2023.
//

#include <cstdlib>
#include <cstring>
#include <iostream>
#include "auth.hpp"
#include "milenage.h"
#include "strings.hpp"

#define STR_K_LEN (CKLEN * 2 + 2 + 1)
typedef char STR_KEY[STR_K_LEN];

char digit_to_hex(const char c) {
	if (c > 15 || c < 0)
		return 0;
	if (c > 9)
		return 'a' + c - 10;
	return '0' + c;
}

void key_to_hex(const CK key, STR_KEY res) {
	bzero(res, STR_K_LEN);
	int i = 2;
	res[0] = '0';
	res[1] = 'x';
	while (i < STR_K_LEN - 1) {
		res[i] = digit_to_hex(key[(i - 2) / 2] >> 4);
		res[i + 1] = digit_to_hex(key[(i - 2) / 2] & 0x0f);
		i += 2;
	}
	res[STR_K_LEN - 1] = '\0';
}

void parse_key_str(const char *key_str, K key, size_t key_len) {
	size_t pos;
	bzero(key, key_len);
	size_t len = strlen(key_str);
	if (key_str[0] == '0' && key_str[1] == 'x') {
		pos = 2;
		while (pos < strlen(key_str)) {
			if (key_str[pos] == '\0')
				break;
			if (!(pos % 2))
				key[pos / 2 - 1] += get_decimal_from_hex(key_str[pos]) << 4;
			else
				key[pos / 2 - 1] += get_decimal_from_hex(key_str[pos]);
			pos++;
		}
		return;
	} else if (len && key_str[0] == '"' && key_str[len - 1] == '"') {
		int pos_s = 1, pos_k = 0;
		while (pos_s < len - 1 && pos_k < key_len) {
			if (key_str[pos_s] != '\\')
				key[pos_k] = key_str[pos_s];
			else
				++pos_s;
			++pos_s;
			++pos_k;
		}
		return;
	} else {
		int pos_s = 0, pos_k = 0;
		while (pos_s < len && pos_k < key_len) {
			if (key_str[pos_s] != '\\')
				key[pos_k] = key_str[pos_s];
			else
				++pos_s;
			++pos_s;
			++pos_k;
		}
	}
}

int main(int argc, char *argv[]) {
	OP op;
	RAND rnd;
	K k;
	RES res;
	AK ak;
	CK ck;
	IK ik;


	if (argc != 5)
		exit(-1);
	if (!strcmp(argv[3], "null")) {
		std::cout << "''";
		exit(0);
	}
	int nonce_len;
	auto nonce = base64_decode_string(argv[2], strlen(argv[2]), &nonce_len);

	if (nonce_len < RANDLEN + AUTNLEN) {
		if (nonce)
			free(nonce);
		std::cerr << "Incorrect length of nonce, expected " << RANDLEN + AUTNLEN << std::endl;
		exit(-1);
	}

	memcpy(rnd, nonce, RANDLEN);
	parse_key_str(argv[1], k, sizeof k);
	parse_key_str(argv[4], op, sizeof op);

	bzero(op, sizeof op);
	bzero(ak, sizeof ak);

	f2345(k, rnd, res, ck, ik, ak, op);
	if (strstr(argv[0], "calc_ck")) {
		STR_KEY s_ck;
		key_to_hex(ck, s_ck);
		std::cout << s_ck;
	} else if (strstr(argv[0], "calc_ik")) {
		STR_KEY s_ik;
		key_to_hex(ik, s_ik);
		std::cout << s_ik;
	} else {
		std::cout << "Program should be called as 'calc_ck' or 'calc_ik' but called as " << argv[0] << std::endl;
		exit(-1);
	}
}