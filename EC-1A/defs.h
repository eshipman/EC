#ifndef DEFS_H
#define DEFS_H

#include <stddef.h>
#include <stdint.h>

const int endian_checker = 1;

#define SWAP(type, a, b) {  \
    type tmp = a;           \
    a = b;                  \
    b = tmp;                \
}

#define little_endian() (*((char*) &endian_checker))


/* EC-1 is a 128-bit block cipher */
#define BLOCKSIZE 16

/* LCG constants taken from cc65 */
#define A 16843009
#define C 826366247
#define M 4294967296

#define SUCCESS  0
#define FAIL     1

uint32_t
char_to_uint32(const uint8_t chars[4]);

uint64_t
char_to_uint64(const uint8_t chars[8]);

uint8_t*
uint64_to_char(uint8_t *out, const uint64_t num);

uint32_t
lcg(uint32_t seed);

uint64_t
xorshift64(const uint64_t seed);

uint8_t*
xorshift_bytes(uint8_t *output, uint8_t seed[8], int o_len);

uint8_t*
to_permutation(uint8_t *output, uint8_t *input, int length);

uint8_t
substitute(uint8_t S[BLOCKSIZE][BLOCKSIZE], uint8_t input);

uint8_t
desubstitute(uint8_t S[BLOCKSIZE][BLOCKSIZE], uint8_t input);

uint8_t*
permute(uint8_t output[BLOCKSIZE], uint8_t data[BLOCKSIZE],
        uint8_t P[BLOCKSIZE]);

uint8_t*
depermute(uint8_t output[BLOCKSIZE], uint8_t data[BLOCKSIZE],
        uint8_t P[BLOCKSIZE]);

uint8_t*
round_key(uint8_t *output, const uint8_t *key, const uint32_t length);

uint8_t*
cipher(uint8_t output[BLOCKSIZE], uint8_t *key, int keylen,
        uint8_t input[BLOCKSIZE]);

#endif
