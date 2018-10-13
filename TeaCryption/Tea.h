/* Copyright 2017 comword
*
* This file is a part of libmobileqq
*
*/
#include <vector>
#include <stdint.h>

class Tea
{
public:
	struct TeaCipher {
		uint32_t *keys;
		std::vector<char> ibuf;
		std::vector<char> obuf;
		uint32_t ibyte32[2] = { 0 };
		uint32_t obyte32[2] = { 0 };
	};
public:
	Tea() {}
	Tea(TeaCipher &tc) : tc(tc) {}
	virtual ~Tea() {}
	struct TeaCipher tc;
public:
	void NewCipher(uint32_t *key, std::vector<char> value);
	void Encrypt();
	int Decrypt();
private:
	inline void Push_bigendian(uint32_t *t, char *s);
	inline void Push_vec(std::vector<char> &t, uint32_t *s);
	void Encipher();
	void Decipher();
	inline void M_xor(uint32_t *o, uint32_t *a, uint32_t *b);
};
