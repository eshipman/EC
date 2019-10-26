#ifndef TEST_C
#define TEST_C

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "defs.h"

#define SWAP(type, a, b) {  \
    type tmp = a;           \
    a = b;                  \
    b = tmp;                \
}

uint32_t char_to_int(uint8_t*);
uint64_t char_to_long(uint8_t*);
void long_to_char(uint64_t, uint8_t*);



/*
 * Apply a Lagged Fibonacci Generator to a 10-byte seed, using j = 7 and k = 10
 * A length of 0 returns the seed
 */
uint8_t* lfg(uint8_t *seed, uint32_t length, uint32_t J, uint32_t K)
{
    if (length < 1)
        return seed;
    
    uint8_t *output = (uint8_t*) malloc(length * sizeof(char));
    uint8_t left, right;

    /* Apply the LFG to the seed */
    right = seed[K - 1];
    for (int i = 0; i < length; i++) {
        /* 
         * Define the left register to be the last four chars, then use the
         * output stream. After the output is calculated, adjust the right
         * register.
         */
        left = (i <= (K - J)) ? seed[J - 1 + i] : output[i - (K - J) - 1];
        output[i] = (left + right) % 256;
        right = output[i];
    }

    return output;
}

/*
 * Permutate the data according to the P-Box, returning a pointer to the
 * permutated version of the data.
 */
uint8_t* permutate(uint8_t *data, uint8_t *p)
{
    if (p == NULL || data == NULL)
        return NULL;
    
    uint8_t *output = (uint8_t*) malloc(BLOCKSIZE * sizeof(char));
    for (int i = 0; i < BLOCKSIZE; i++)
        output[i] = data[p[i]];
    return output;
}

/*
 * Apply a raw LCG to a seed value
 */
uint32_t lcg(uint32_t seed)
{
    return (uint32_t) ((A * seed + C) % M);
}

/*
 * Generate a variable number of bytes using an LCG.
 */
uint8_t* lcg_bytes(uint8_t seed[sizeof(uint32_t)], uint32_t length)
{
    /* Define the value for each generation and the output value */
    uint32_t x = *(uint32_t*) seed;
    uint8_t *output = (uint8_t*) malloc(length);
    memset(output, 0, length);

    /* Apply the LCG, extract the upper 16 bits each time */
    for (int i = 0; i < length; i += 2) {
        x = lcg(x);
        uint8_t *tmp = (uint8_t*) &x;
        output[i] = tmp[3];
        output[i + 1] = tmp[2];
    }
    return output;
}

/*
 * Apply a raw xorshift to a seed value
 */
uint64_t xorshift(uint64_t seed)
{
    uint64_t x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

/*
 * Generate a variable number of bytes using xorshift
 */
uint8_t* xorshift_bytes(uint8_t seed[sizeof(uint64_t)], uint32_t length)
{
    /*
     * Define the value for each generation and the output value. Allocate the
     * output buffer to be a multiple of 8 bytes. After it's filled, reallocate
     * the buffer to be the correct size.
     */
    //uint64_t x = *(uint64_t*) seed,
    uint64_t x = char_to_long(seed),
             output_len = length + (
                 (length % sizeof(uint64_t) != 0) ?
                    sizeof(uint64_t) - (length % sizeof(uint64_t)) :
                    0);
    uint8_t *output = (uint8_t*) malloc(output_len);
    memset(output, 0, output_len);

    /* Apply the xorshift, converting to a char array */
    for (int i = 0; i < length; i += 8) {
        x = xorshift(x);
        long_to_char(x, output + i);
    }

    /* Resize to the requested size */
    output = realloc(output, length);

    return output;
}

/*
 * Compute a roundkey from the previous one. Handles 16 byte keys
 */
uint8_t* roundkey(uint8_t* key, uint32_t length)
{
    uint8_t *output = (uint8_t*) malloc(length);
    if (length == 16) {
        uint32_t l0 = char_to_int(key),
                 l1 = char_to_int(key + 4);
        uint64_t r = char_to_long(key + 8),
                 l = 0;
        l = ((uint64_t) lcg(l1) << 32) + (lcg(l1) ^ lcg(l0));
        r = xorshift(r);
        SWAP(uint64_t, l, r)
        r = r ^ l;
        long_to_char(l, output);
        long_to_char(r, output + sizeof(uint64_t));
    } else if (length == 192) {
        memcpy(output, key, length);
    } else if (length == 256) {
        memcpy(output, key, length);
    }
    return output;
}

/*
 * Get the X and Y coordinates for the S-Box, pack them into an uint32_t
 */
uint32_t get_xy(uint8_t data)
{
    uint16_t x = (data >> 1) & 0x3,
             y = ((data & 0x8) >> 2) | (data & 0x1);
    return (x << sizeof(uint16_t)) | y;
}

/*
 * Apply the S-Box to the data in-place.
 */
int sub(uint8_t **data, uint8_t *s)
{
    if (S == NULL)
        return FAIL;
    
    /* Substitute the data in-place */
    for (int i = 0; i < BLOCKSIZE; i++) {
        /* Get the coordinates for the S-Box */
        uint32_t l = get_xy((*data)[i] >> 4),
                     r = get_xy((*data)[i] & 0xF);
        /* Get the substituted value and place it back into data */
        uint8_t l_subbed = s[(l >> sizeof(uint16_t)) * S_WIDTH + (l & 0xF)],
                      r_subbed = s[(r >> sizeof(uint16_t)) * S_WIDTH + (r & 0xF)];
        (*data)[i] = (l_subbed << 4) | (r_subbed & 0xF);
    }
}

/*
 * Generate the P-Boxes, S-Boxes, and round keys
 */
uint8_t setup(uint8_t *key, uint32_t keylen)
{
    uint8_t rounds;

    /* Make sure the keylength is valid */
    if (keylen % 64)
        rounds = 0;
    else
        rounds = 6 + 6 * keylen / 64;
    
    /* Make sure the P-Box hasn't been allocated */
    if (P != NULL)
        return 0;
    else if (K != NULL)
        return 0;
    else if (S != NULL)
        return 0;
    
    /* Allocate the P-Boxes, S-Boxes, and round keys */
    P = (uint8_t**) malloc(rounds * sizeof(uint8_t*));
    S = (uint8_t**) malloc(rounds * sizeof(uint8_t*));
    K = (uint8_t**) malloc(rounds * sizeof(uint8_t*));

    /* Compute the round keys, P-Box, and S-Boxes */
    for (int i = 0; i < rounds; i++) {
        K[i] = roundkey((i > 0) ? K[i - 1] : key, keylen);
        P[i] = to_permutation(xorshift_bytes(K[i], BLOCKSIZE), keylen);
        S[i] = (uint8_t*) malloc(BLOCKSIZE);
        S[i] = memcpy(S[i], P[i], BLOCKSIZE);
    }
    
    return rounds;
}

/*
 * Convert a char array to a uint32_t
 */
uint32_t char_to_int(uint8_t *input)
{
    uint32_t output = 0;
    for (int i = 0; i < sizeof(uint32_t); i++)
        output ^= input[sizeof(uint32_t) - 1 - i] << (i * 8);
    return output;
}

/*
 * Convert a char array to a uint64_t
 */
uint64_t char_to_long(uint8_t *input)
{
    uint64_t output = 0;
    for (int i = 0; i < sizeof(uint64_t); i++)
        output ^= ((uint64_t) input[sizeof(uint64_t) - 1 - i]) << (i * 8);
    return output;
    //return ((uint64_t) char_to_int(input) << 32) | char_to_int(input + 4);
}

/*
 * Convert a uint64_t to a char array
 */
void long_to_char(uint64_t input, uint8_t *output)
{
    for (int i = 0; i < sizeof(uint64_t); i++)
        output[sizeof(uint64_t) - 1 - i] = (uint8_t) (input >> (i * 8));
        //output[i] = (uint8_t) (input >> ((sizeof(uint64_t) - i - 1) * 8));
}

/*
 * Encrypt the plaintext with the given key.
 */
uint8_t* encrypt(uint8_t *ptext, uint8_t *key)
{
    /* Setup the parameters, define the rounds, and allocate the output */
    uint8_t rounds = setup(key, 128);
    uint8_t *output = (uint8_t*) malloc(BLOCKSIZE);

    /* Copy the plaintext to start with */
    memcpy(output, ptext, BLOCKSIZE);

    for (int i = 0; i < rounds; i++) {
        /* Run the text through the P-Box */
        uint8_t *permed = permutate(output, P[i]);

        /* XOR the text with the round key */
        for (int j = 0; j < BLOCKSIZE; j++)
            permed[i] ^= K[i][j];
        
        /* Copy the output to the output variable and free it */
        memcpy(output, permed, BLOCKSIZE);
        free(permed);
    }
    return output;
}


/* BEGIN TESTING HELPER FUNCTIONS */

// Generate the nth fibonacci number
long fib(long n) {
    if (n == 0 || n == 1) return 1;
    else return fib(n - 1) + fib(n - 2);
}

/*
 * Fail the ith test
 */
void fail(uint32_t *mask, uint32_t i) {
    *mask = *mask & (0xFFFFFFFF ^ (0x1 << i));
}

/*
 * Get the result of the ith unit test
 */
void get_result(uint32_t mask, uint32_t i) {
    if (!(mask & (0x1 << i)))
        printf("  FAIL: ");
    else
        printf("  SUCCESS: ");
}

/* END TESTING HELPER FUNCTIONS */

int main(int argc, char **argv)
{
    uint32_t TEST_RESULT = 0xFFFFFFFF;

    /* BEGIN TESTS */


    printf("\n");
    printf("Running unit tests ...\n");


    /*
     * Function: to_permutation()
     * Input: Fibonacci Sequence (increasing modulo)
     * Output: Permutation computed by hand
     */
    uint8_t p_correct[BLOCKSIZE] = {14, 0, 1, 12, 2, 8, 3, 6, 7, 4, 13, 15, 11, 5, 10, 9};
    uint8_t *p_fib = (uint8_t*) malloc(BLOCKSIZE);
    for (int i = 0; i < BLOCKSIZE; i++)
        p_fib[i] = (uint8_t) fib(i) % (BLOCKSIZE - i);

    uint8_t *p_test = to_permutation(p_fib, BLOCKSIZE);
    for (int i = 0; i < BLOCKSIZE; i++)
        if (p_test[i] != p_correct[i])
            fail(&TEST_RESULT, 1);


    /* Report on the unit test */
    get_result(TEST_RESULT, 1);
    printf("to_permutation()\n");


    free(p_fib);
    free(p_test);


    /*
     * Function: lfg()
     * Input: Fibonacci Sequence, j = 7, k = 10
     * Output: Pseudorandom sequence computed by hand
     */
    uint8_t s_correct[10] = {68, 89, 123, 178, 246, 79, 202, 124, 114, 193};
    uint8_t *s_seed = (uint8_t*) malloc(sizeof(uint8_t*) * 10);
    for (int i = 0; i < 10; i++)
        s_seed[i] = (uint8_t) fib(i);

    uint8_t *s_test = lfg(s_seed, 10, 7, 10);
    for (int i = 0; i < 10; i++)
        if (s_test[i] != s_correct[i])
            fail(&TEST_RESULT, 2);


    /* Report on the unit test */
    get_result(TEST_RESULT, 2);
    printf("lfg()\n");
    

    free(s_test);
    free(s_seed);

    // permutate()
    /*
     * Function: permutate()
     * Input: A P-Box as the sequence {0 .. 15}
     * Output: The sequence permutated according to the P-Box
     */
    uint8_t perm_correct[BLOCKSIZE] = {14, 0, 1, 12, 2, 8, 3, 6, 7, 4, 15, 13, 11, 5, 10, 9};
    uint8_t ordered[BLOCKSIZE];
    uint8_t *perm;
    for (int i = 0; i < BLOCKSIZE; i++)
        ordered[i] = i;
    perm = permutate(ordered, perm_correct);
    if (perm == NULL)
        fail(&TEST_RESULT, 3);
    else
        for (int i = 0; i < BLOCKSIZE; i++)
            if (perm[i] != perm_correct[i])
                fail(&TEST_RESULT, 3);
    

    /* Report on the unit test */
    get_result(TEST_RESULT, 3);
    printf("permutate()\n");


    free(perm);


    /*
     * Function: lcg()
     * Input: 123456789
     * Output: The next two numbers in the sequence, verified by hand
     */
    uint32_t input = 0x75BCD15,
                 output1 = lcg(input),
                 output2 = lcg(output1);
    if (output1 != 0x767F3B3C || output2 != 0x9E37D063)
        fail(&TEST_RESULT, 4);


    /* Report on the unit test */
    get_result(TEST_RESULT, 4);
    printf("lcg()\n");


    /*
     * Function: lcg_bytes()
     * Input: A 32-bit seed, 0x46D63871
     * Output: A byte array produced by the seed, verified by hand
     */
    uint8_t lcg_seed[4] = {70, 214, 56, 113};
    uint8_t lcg_correct[8] = {0xF7, 0x96, 0xA1, 0xBA, 0x5C, 0xCB, 0x3C, 0xF0};
    uint8_t *lcg_test = lcg_bytes(lcg_seed, 8);
    for (int i = 0; i < 8; i++)
        if (lcg_test[i] != lcg_correct[i])
            fail(&TEST_RESULT, 5);


    /* Report on the unit test */
    get_result(TEST_RESULT, 5);
    printf("lcg_bytes()\n");


    /*
     * Function: xorshift()
     * Input: 1234567890123456789
     * Output: The next number in the sequence, verified by hand
     */
    uint64_t xorshift_seed = 0x112210F47DE98115;
    uint64_t xorshift_correct = 0x9F7558D6B1FEB757;
    uint64_t xorshift_output = xorshift(xorshift_seed);
    if (xorshift_output != xorshift_correct)
        fail(&TEST_RESULT, 6);


    get_result(TEST_RESULT, 6);
    printf("xorshift()\n");
    


    /*
     * Function: xorshift_bytes()
     * Input:
     * Output:
     */
    uint8_t xorshift_bytes_seed[sizeof(uint64_t)],
            *xorshift_bytes_output;
    long_to_char(xorshift_seed, xorshift_bytes_seed);
    xorshift_bytes_output = xorshift_bytes(xorshift_bytes_seed, sizeof(uint64_t));
    if (char_to_long(xorshift_bytes_output) != xorshift_output)
        fail(&TEST_RESULT, 7);

    get_result(TEST_RESULT, 7);
    printf("xorshift_bytes()\n");

    free(xorshift_bytes_output);
    

    /*
     * Function: roundkey()
     * Input: A test key
     * Output: A 128-bit round key computed by hand
     */
    uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x56, 0x78, 0x12, 0x34, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t key_correct[16] = {0x3F, 0x28, 0x00, 0xD6, 0x56, 0x9e, 0x01, 0xB4, 0x7A, 0xD7, 0x9F, 0x8D, 0x55, 0x25, 0xB9, 0x70};
    uint8_t *rkey = roundkey(key, 16);
    for (int i = 0; i < 16; i++)
        if (rkey[i] != key_correct[i])
            fail(&TEST_RESULT, 8);


    get_result(TEST_RESULT, 8);
    printf("roundkey()\n");


    free(rkey);
    

    /*
     * Function: get_xy()
     * Input:
     * Output:
     */


    fail(&TEST_RESULT, 9);

    get_result(TEST_RESULT, 9);
    printf("get_xy()\n");


    /*
     * Function: sub()
     * Input:
     * Output:
     */


    fail(&TEST_RESULT, 10);

    /* Report on the unit test */
    get_result(TEST_RESULT, 10);
    printf("sub()\n");


    /*
     * Function: setup()
     * Input:
     * Output:
     */


    fail(&TEST_RESULT, 11);

    /* Report on the unit test */
    get_result(TEST_RESULT, 11);
    printf("setup()\n");


    /*
     * Function: encrypt()
     * Input:
     * Output:
     */
    uint8_t *ptext = "12345678";
    uint8_t *enc_key = "87654321";
    uint8_t *ctext = encrypt(ptext, enc_key);
    printf("ctext = ");
    for (int i = 0; i < 8; i++)
        printf("%x:", ctext[i]);
    printf("\n");
    fail(&TEST_RESULT, 12);


    get_result(TEST_RESULT, 12);
    printf("encrypt()\n");


    printf("... done\n");

    /* END TESTS */

    
    return 0;
}

#endif