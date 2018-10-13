/* Copyright 2017 comword
*
* This file is a part of libmobileqq
*
*/
#include "Tea.h"
#include <vector>

const uint32_t DELTA = 0x9E3779B9;
const int fillnor = 0xF8;

void Tea::NewCipher(uint32_t *key, std::vector<char> value)
{
	TeaCipher cipher;
	cipher.keys = key;
	cipher.ibuf = value;
	tc = cipher;
}

inline void Tea::Push_bigendian(uint32_t *t, char *s)
{
	t[0] = *(s + 3) & 0x000000ff;
	t[0] |= (*(s + 2) << 8) & 0x0000ff00;
	t[0] |= (*(s + 1) << 16) & 0x00ff0000;
	t[0] |= (*(s) << 24) & 0xff000000;
	t[1] = *(s + 7) & 0x000000ff;
	t[1] |= (*(s + 6) << 8) & 0x0000ff00;
	t[1] |= (*(s + 5) << 16) & 0x00ff0000;
	t[1] |= (*(s + 4) << 24) & 0xff000000;
}

inline void Tea::Push_vec(std::vector<char> &t, uint32_t *s)
{
	t.push_back((s[0] >> 24) & 0xff);
	t.push_back((s[0] >> 16) & 0xff);
	t.push_back((s[0] >> 8) & 0xff);
	t.push_back(s[0] & 0xff);
	t.push_back((s[1] >> 24) & 0xff);
	t.push_back((s[1] >> 16) & 0xff);
	t.push_back((s[1] >> 8) & 0xff);
	t.push_back(s[1] & 0xff);
}

void Tea::Encipher()
{
	char n = 16;
	uint32_t y = tc.ibyte32[0], z = tc.ibyte32[1], sum = DELTA;
	uint32_t a = tc.keys[0], b = tc.keys[1], c = tc.keys[2], d = tc.keys[3];
	while (n-- > 0) {
		y += (((z << 4) & 0xFFFFFFF0) + a) ^ (z + sum) ^ (((z >> 5) & 0x07ffffff) + b);
		z += (((y << 4) & 0xFFFFFFF0) + c) ^ (y + sum) ^ (((y >> 5) & 0x07ffffff) + d);
		sum += DELTA;
	}
	tc.obyte32[0] = y;
	tc.obyte32[1] = z;
}

void Tea::Decipher()
{
	char n = 16;
	uint32_t y = tc.ibyte32[0], z = tc.ibyte32[1], sum = DELTA << 4 & 0xffffffff;
	uint32_t a = tc.keys[0], b = tc.keys[1], c = tc.keys[2], d = tc.keys[3];
	while (n-- > 0) {
		z -= (((y << 4 & 0xFFFFFFF0) + c) ^ (y + sum) ^ ((y >> 5 & 0x07ffffff) + d));
		z &= 0xffffffff;
		y -= (((z << 4 & 0xFFFFFFF0) + a) ^ (z + sum) ^ ((z >> 5 & 0x07ffffff) + b));
		y &= 0xffffffff;
		sum -= DELTA;
	}
	tc.obyte32[0] = y;
	tc.obyte32[1] = z;
}

inline void Tea::M_xor(uint32_t *o, uint32_t *a, uint32_t *b)
{
	o[0] = a[0] ^ b[0];
	o[1] = a[1] ^ b[1];
}

void Tea::Encrypt()
{
	int vl = tc.ibuf.size();
	char filln = (8 - (vl + 2)) % 8;
	if (filln < 0) {
		filln += 2 + 8;
	}
	else {
		filln += 2;
	}
	char fills[9] = { 0 };
	for (int i = 0; i < filln; i++) {
		fills[i] = std::rand() % 256;
		//      fills[i] = 0;
	}
	std::vector<char> filled_buf;
	filled_buf.resize(8 + filln + vl);
	char *p = &filled_buf.front();
	p[0] = (filln - 2) | fillnor;
	memcpy(p + 1, fills, filln);
	memcpy(p + 1 + filln, &tc.ibuf.front(), vl);
	memset(p + 1 + filln + vl, 0, 7);
	std::vector<char> res;
	uint32_t tr[2] = { 0 };
	uint32_t to[2] = { 0 };
	uint32_t o[2] = { 0 };
	for (size_t i = 0; i < filled_buf.size(); i += 8) {
		Push_bigendian(tc.ibyte32, p + i);
		M_xor(o, tc.ibyte32, tr);
		memcpy(tc.ibyte32, o, 2 * sizeof(uint32_t));
		Encipher();
		M_xor(tr, tc.obyte32, to);
		memcpy(to, o, 2 * sizeof(uint32_t));
		Push_vec(res, tr);
	}
	tc.obuf = res;
}

int Tea::Decrypt()
{
	int vl = tc.ibuf.size();
	std::vector<char> res;
	tc.obuf = res;
	if (vl <= 0 || (vl % 8) != 0) {
		return -1;
	}
	char *p = &tc.ibuf.front();
	Push_bigendian(tc.ibyte32, p);
	Decipher();
	int pos = ((tc.obyte32[0] >> 24) & 0x7) + 2;
	Push_vec(res, tc.obyte32);
	uint32_t x[2] = { 0 };
	for (int i = 8; i < vl; i += 8) {
		Push_bigendian(tc.ibyte32, p + i);
		M_xor(x, tc.ibyte32, tc.obyte32);
		tc.ibyte32[0] = x[0];
		tc.ibyte32[1] = x[1];
		Decipher();
		Push_bigendian(tc.ibyte32, p + i - 8);
		M_xor(x, tc.obyte32, tc.ibyte32);
		M_xor(tc.obyte32, x, tc.ibyte32);
		Push_bigendian(tc.ibyte32, p + i);
		Push_vec(res, x);
	}
	for (size_t i = res.size() - 1; i >= res.size() - 7; i--) {
		if (res[i] != 0) {
			return -2;
		}
	}
	for (int i = 0; i <= pos; i++) {
		res.erase(res.begin());
	}
	tc.obuf = res;
	return 0;
}
