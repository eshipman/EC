/*
 * TITLE : EC-1A Reference Implementation
 * AUTHOR: Evan Shipman
 * DATE  : 2019-11-02
 * DESCR.: This is the reference implementation for EC-1A
 *
 * Copyright 2019 Evan Shipman
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#ifndef MAIN_C
#define MAIN_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"

/*
 * FUNCTION: char_to_uint32
 * --------------------
 * Converts a char[4] to an unsigned int. Always use little-endian order
 *
 * INPUT:
 *  chars: The char array to convert
 *
 * RETURN: The 32-bit representation in little-endian order
 */
uint32_t
char_to_uint32(const uint8_t chars[4])
{
    uint32_t out;

    if (little_endian()) {
        memcpy(&out, chars, 4);
    } else {
        out = (((uint32_t) chars[4]) << 24) | (((uint32_t) chars[5]) << 16) |
              (((uint32_t) chars[6]) << 8)  | chars[7];
    }

    return out;
}

/*
 * FUNCTION: char_to_uint64
 * ----------------------
 * Converts a char[8] to an unsigned long. Always use little-endian order
 *
 * INPUT:
 *  chars: The char array to convert
 *
 * RETURN: The 64-bit integer representation in little-endian order
 */
uint64_t
char_to_uint64(const uint8_t chars[8])
{
    uint64_t out;

    if (little_endian()) {
        memcpy(&out, chars, 8);
    } else {
        out = (((uint64_t) chars[0]) << 56) | (((uint64_t) chars[1]) << 48) |
              (((uint64_t) chars[2]) << 40) | (((uint64_t) chars[3]) << 32) |
              (((uint64_t) chars[4]) << 24) | (((uint64_t) chars[5]) << 16) |
              (((uint64_t) chars[6]) << 8)  | chars[7];
    }

    return out;
}

/*
 * FUNCTION: uint64_to_char
 * ------------------------
 * Converts a uint64_t to a char array. Always use little endian order
 *
 * INPUT:
 *  out: The destination to store the result
 *  num: The uint64_t to convert to chars
 *
 * RETURN: A pointer to the char[8] representation in little endian order
 */
uint8_t*
uint64_to_char(uint8_t* out, const uint64_t num)
{

    if (little_endian()) {
        memcpy(out, &num, 8);
    } else {
        out[7] = num & 0xFF;
        out[6] = (num >> 8) & 0xFF;
        out[5] = (num >> 16) & 0xFF;
        out[4] = (num >> 24) & 0xFF;
        out[3] = (num >> 32) & 0xFF;
        out[2] = (num >> 40) & 0xFF;
        out[1] = (num >> 48) & 0xFF;
        out[0] = (num >> 56) & 0xFF;
    }

    return out;
}

/*
 * Function: lcg
 * -------------
 * Applies a raw LCG to a seed value
 *
 * INPUT:
 *  seed: A 32-bit starting seed
 *
 * RETURN: A 32-bit pseudorandom value
 */
uint32_t
lcg(uint32_t seed)
{
    return (uint32_t) ((A * seed + C) % M);
}

/*
 * FUNCTION: xorshift64
 * --------------------
 * Applies a raw xorshift to a seed value
 *
 * INPUT:
 *  seed:  A 64-bit starting seed
 *
 * RETURN: a 64-bit pseudorandom value
 */
uint64_t
xorshift64(const uint64_t seed)
{
    uint64_t x;
    x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

/*
 * FUNCTION: xorshift_bytes
 * ------------------------
 * Generates pseudorandom bytes using xorshift.
 *
 * INPUT:
 *  output: Where to store the bytes. MUST BE ALLOCATED BEFORE CALLING
 *  seed  : The seed value to start from. MUST BE 64-BITS
 *  o_len : The number of random bytes to generate.
 *
 * RETURN: uint8_t[o_len] filled with pseudorandom bytes
 */
uint8_t*
xorshift_bytes(uint8_t *output, uint8_t seed[8], int o_len)
{
    uint64_t x;
    int i;
    uint8_t tmp[8];

    if (output == NULL || seed == NULL)
        return NULL;

    x = char_to_uint64(seed);
    
    /* Fill with random bytes, generate the next number every 8 bytes */
    for (i = 0; i < o_len; i++) {
        if (i % 8 == 0) {
            /* Generate the next number and convert to char array */
            x = xorshift64(x);
            uint64_to_char(tmp, x);
        }
        output[i] = tmp[i % 8];
    }

    return output;
}

/*
 * FUNCTION: to_permutation
 * ------------------------
 * Naively convert an input to a permutation.
 *
 * INPUT:
 *  output: Where to store the permutation. MUST BE ALLOCATED BEFORE CALLING
 *  input : The input stream to convert
 *  length: The length of the stream
 *
 * RETURN: A pointer to the permutation
 */
uint8_t*
to_permutation(uint8_t *output, uint8_t *input, int length)
{

    int *tmp,
        i, j, k,
        pos;
    uint8_t *out;

    tmp = (int*) malloc(length * sizeof(int));
    out = (uint8_t*) malloc(length);

    memset(tmp, 0, length * sizeof(int));

    for (i = 0, j = length; i < length && j > 0; i++, j--) {
        pos = input[i] % j;
        for (k = 0; k < length && pos >= 0; k++)
            if (!tmp[k])
                pos--;
        out[k - 1] = i;
        tmp[k - 1] = 1;
    }

    memcpy(output, out, length);

    free(tmp);
    free(out);

    return output;
}

/*
 * FUNCTION: substitute
 * --------------------
 * Apply the S-Box to the input value
 *
 * INPUT:
 *  S    : The S-Box to use
 *  input: The 8-bit integer to lookup
 * 
 * RETURN: The substituted value
 */
uint8_t
substitute(uint8_t S[BLOCKSIZE][BLOCKSIZE], uint8_t input)
{
    return S[input >> 4][input & 0x0F];
}

/*
 * FUNCTION: desubstitute
 * ----------------------
 * Reverse the S-Box substitution
 *
 * INPUT:
 *  S    : The S-Box to use
 *  input: The value to be reversed
 *
 * RETURN: The reversed value
 */
uint8_t
desubstitute(uint8_t S[BLOCKSIZE][BLOCKSIZE], uint8_t input)
{
    int i, j;
    for (i = 0; i < BLOCKSIZE; i++)
        for (j = 0; j < BLOCKSIZE; j++)
            if (S[i][j] == input)
                return (i << 4) | j;
    return 0;
}

/*
 * FUNCTION: permute
 * -----------------
 * Permute the data according to the P-Box
 *
 * INPUT:
 *  output: Where to store the permuted data. MUST BE ALLOCATED BEFORE CALLING
 *  data  : The data to be permuted
 *  P     : The P-Box to do the permuting
 *
 * RETURN: A pointer to the permuted data
 */
uint8_t*
permute(uint8_t output[BLOCKSIZE], uint8_t data[BLOCKSIZE], uint8_t P[BLOCKSIZE])
{
    int i;
    uint8_t tmp[BLOCKSIZE];

    if (output == NULL || data == NULL || P == NULL)
        return NULL;

    for (i = 0; i < BLOCKSIZE; i++)
        tmp[i] = data[P[i]];

    memcpy(output, tmp, BLOCKSIZE);

    return output;
}

/*
 * FUNCTION: depermute
 * -------------------
 * Reverses a permutation by a P-Box
 *
 * INPUT:
 *  output: Where to store the reversed data. MUST BE ALLOCATED BEFORE CALLING
 *  data  : The data to be depermuted
 *  P     : The P-box that originally permuted the data
 *
 * RETURN: A pointer to the depermuted data
 */
uint8_t*
depermute(uint8_t output[BLOCKSIZE], uint8_t data[BLOCKSIZE], uint8_t P[BLOCKSIZE])
{
    int i;
    uint8_t tmp[BLOCKSIZE];

    if (output == NULL || data == NULL || P == NULL)
        return NULL;

    for (i = 0; i < BLOCKSIZE; i++)
        tmp[P[i]] = data[i];

    memcpy(output, tmp, BLOCKSIZE);

    return output;
}

/* 
 * +---------------------------------+
 * | TODO: ONLY HANDLES 128-BIT KEYS |
 * +---------------------------------+
 *
 * FUNCTION: round_key
 * -------------------
 * Generates the next round key from the previous. Does not allocate any memory
 * for the output.
 *
 * INPUT:
 *  output: The array to write the output to. MUST BE ALLOCATED BEFORE CALLING
 *  key:    The previous round key as an array of bytes
 *  length: The length in bytes of the key
 *
 * RETURN: A pointer to the next round key in the sequence
 */
uint8_t*
round_key(uint8_t *output, const uint8_t *key, const uint32_t length)
{
    uint64_t r,
             l;
    uint32_t l0,
             l1;

    if (output == NULL)
        return NULL;
    else if (length % 16 != 0 || length == 0)
        return NULL;

    if (length == 16) {
        /* Split the key into the three pieces */
        l0 = char_to_uint32(key);
        l1 = char_to_uint32(key + 4);
        r = char_to_uint64(key + 8);

        /* Apply the initial PRNG functions to each piece */
        l0 = lcg(l0);
        l1 = lcg(l1);
        r = xorshift64(r);
        
        /* Apply the first xor & swap */
        l0 ^= l1;
        SWAP(uint32_t, l0, l1)

        /* Apply the second xor & swap */
        l = (((uint64_t) l0) << 8) | l1;
        l ^= r;
        SWAP(uint64_t, l, r)

        /* Copy to the output */
        memcpy(output, &r, 8);
        memcpy(output + 8, &l, 8);
    } else {
        return round_key(output, key, 16);
    }

    return output;
}

/*
 * FUNCTION: cipher
 * ----------------
 * Encrypts or decrypts an input with EC-1. A negative keylen switches to
 *  decryption mode.
 *
 * INPUT:
 *  output: Where to store the result. MUST BE ALLOCATED BEFORE CALLING
 *  key   : The key to perform encryption/decryption with
 *  keylen: The length of the key in bytes. If negative, decrypt
 *  input : The input data
 *
 * RETURN: A pointer to the ciphertext/plaintext
 */
uint8_t*
cipher(uint8_t output[BLOCKSIZE], uint8_t *key, int keylen,
        uint8_t input[BLOCKSIZE])
{
    int i, j,
        rounds,
        decrypt,
        key_index;
    uint8_t **keys,
            P[BLOCKSIZE],
            S[BLOCKSIZE][BLOCKSIZE];

    /* Setting keylen to negative invokes decryption */
    if (keylen < 0) {
        keylen *= -1;
        decrypt = 1;
    } else {
        decrypt = 0;
    }

    if (output == NULL || key == NULL || input == NULL)
        return NULL;
    else if ((keylen > 0 && keylen % 16 != 0) || keylen <= 0)
        return NULL;

    memcpy(output, input, BLOCKSIZE);

    rounds = 6 + 6 * keylen / 8;

    /* Pre-compute the round keys */
    keys = (uint8_t**) malloc(rounds * sizeof(uint8_t*));
    for (i = 0; i < rounds; i++) {
        keys[i] = (uint8_t*) malloc(BLOCKSIZE);
        if (i == 0)
            round_key(keys[i], key, BLOCKSIZE);
        else
            round_key(keys[i], keys[i - 1], BLOCKSIZE);
    }

    for (i = 0; i < rounds; i++) {
        /* If decrypting, work backwards through the keys */
        if (decrypt)
            key_index = rounds - 1 - i;
        else
            key_index = i;

        /* Generate the P-Box from the key */
        xorshift_bytes(P, keys[key_index], BLOCKSIZE);
        to_permutation(P, P, BLOCKSIZE);

        /* Revision: Generate the S-Box from the P-Box */
        xorshift_bytes((uint8_t*) S, P, BLOCKSIZE * BLOCKSIZE);
        to_permutation((uint8_t*) S, (uint8_t*) S, BLOCKSIZE * BLOCKSIZE);

        if (decrypt) {
            /* Xor with the key, then desubstitute and de-permute */
            for (j = 0; j < BLOCKSIZE; j++)
                output[j] = desubstitute(S, output[j] ^ keys[key_index][j]);
            depermute(output, output, P);
        } else {
            /* Run the block through P and S, then xor with K */
            permute(output, output, P);
            for (j = 0; j < BLOCKSIZE; j++)
                output[j] = substitute(S, output[j]) ^ keys[key_index][j];
        }
    }

    /* Cleanup */
    for (i = 0; i < rounds; i++)
        free(keys[i]);
    free(keys);

    return output;
}

int
main(int argc, char **argv)
{
    uint8_t input[BLOCKSIZE],
            key[BLOCKSIZE],
            output[BLOCKSIZE],
            dec[BLOCKSIZE];
    int i;

    printf("KEY  : ");
    for (i = 0; i < BLOCKSIZE; i++)
        printf("%02x ", (key[i] = 32 + i));
    printf("\n");

    printf("INPUT: ");
    for (i = 0; i < BLOCKSIZE; i++)
        printf("%02x ", (input[i] = 65 + i));
    printf("\n");

     cipher(output, key, BLOCKSIZE, input);

    printf("CTEXT: ");
    for (i = 0; i < BLOCKSIZE; i++)
        printf("%02x ", output[i]);
    printf("\n");

    cipher(dec, key, BLOCKSIZE * -1, output);

    printf("PTEXT: ");
    for (i = 0; i < BLOCKSIZE; i++)
        printf("%02x ", dec[i]);
    printf("\n");

    return 0;
}

#endif
