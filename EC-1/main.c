#ifndef MAIN_C
#define MAIN_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"

/*
 * FUNCTION: char_to_32
 * --------------------
 * Converts a char[4] to an unsigned int. Always use little-endian order
 *
 * INPUT:
 *  chars: The char array to convert
 *
 * RETURN: The 32-bit representation in little-endian order
 */
uint32_t
char_to_32(const uint8_t chars[4])
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
 * FUNCTION: char_to_64
 * ----------------------
 * Converts a char[8] to an unsigned long. Always use little-endian order
 *
 * INPUT:
 *  chars: The char array to convert
 *
 * RETURN: The 64-bit integer representation in little-endian order
 */
uint64_t
char_to_64(const uint8_t chars[8])
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
    int out_size;

    if (output == NULL || seed == NULL)
        return NULL;

    x = char_to_64(seed);
    out_size = 0;

    /* Fill the output with random bytes in 64-bit chunks but don't overflow */
    while (out_size < o_len) {
        x = xorshift64(x);
        for (i = 0; i < o_len - out_size && i < 8; i++)
            output[out_size + i] = x >> (8 * i);
        out_size += i + 1;
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

    tmp = (int*) malloc(length);

    memset(tmp, -1, length);

    /* Convert the input stream into a permutation naively */
    for (i = 0, j = length; i < length && j > 0; i++, j--) {
        pos = input[i] % j;
        for (k = 0; k < length && pos >= 0; k++)
            if (tmp[k] == -1)
                pos--;
        output[k - 1] = i;
        tmp[k - 1] = i;
    }

    free(tmp);

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
        l0 = char_to_32(key);
        l1 = char_to_32(key + 4);
        r = char_to_64(key + 8);

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
        decrypt;
    uint8_t **keys,
            P[BLOCKSIZE],
            S[BLOCKSIZE][BLOCKSIZE];


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

    keys = (uint8_t**) malloc(rounds);
    for (i = 0; i < rounds; i++) {
        keys[i] = (uint8_t*) malloc(keylen);
        if (i == 0)
            round_key(keys[i], key, keylen);
        else
            round_key(keys[i], keys[i - 1], keylen);
    }

    rounds = 6 + 6 * keylen / 8;

    for (i = 0; i < rounds; i++) {
        /* Generate the P-Box from the key */
        if (decrypt) {
            xorshift_bytes(P, keys[rounds - 1], BLOCKSIZE);
            to_permutation(P, P, BLOCKSIZE);
        } else {
            xorshift_bytes(P, keys[i], BLOCKSIZE);
            to_permutation(P, P, BLOCKSIZE);
        }

        /* Revision: Generate the S-Box from the P-Box */
        xorshift_bytes((uint8_t*) S, P, BLOCKSIZE * BLOCKSIZE);
        to_permutation((uint8_t*) S, (uint8_t*) S, BLOCKSIZE * BLOCKSIZE);

        if (decrypt) {
            /* Xor with the key, then desubstitute and de-permute */
            for (j = 0; j < BLOCKSIZE; j++)
                output[j] = desubstitute(S, output[j] ^ keys[rounds - 1][j]);
            depermute(output, output, P);
        } else {
            /* Run the block through P and S, then xor with K */
            permute(output, output, P);

            /*
             *  TODO: Somehow the code is Segfaulting in this loop
             */
            for (j = 0; j < BLOCKSIZE; j++)
                output[j] = substitute(S, output[j] ^ keys[i][j]);



        }
    }
    
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
            output[BLOCKSIZE];
    int i;

    printf("KEY  :");
    for (i = 0; i < BLOCKSIZE; i++)
        printf("%02x", (key[i] = 32 + i));
    printf("\n");

    printf("PTEXT:");
    for (i = 0; i < BLOCKSIZE; i++)
        printf("%02x", (input[i] = 65 + i));
    printf("\n");

    cipher(output, key, BLOCKSIZE, input);

    printf("CTEXT:");
    for (i = 0; i < BLOCKSIZE; i++)
        printf("%02x", output[i]);
    printf("\n");

    /*
    uint8_t key[16];
    int i;

    for (i = 0; i < 16; i++)
        printf("%02x", (key[i] = 65 + i));
    printf("\n");

    round_key(key, 16, key);
    */

    return 0;
}

#endif
