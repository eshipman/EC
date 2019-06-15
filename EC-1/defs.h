#ifndef DEFS_H
#define DEFS_H

#include <stddef.h>
#include <stdint.h>

#define SUCCESS 0
#define FAIL 1

#define BLOCKSIZE 128 / 8
#define ROUNDS 21

/* LCG constants taken from cc65 */
#define A 16843009
#define C 826366247
#define M 4294967296

unsigned char **P = NULL;
unsigned char **S = NULL;

#define S_WIDTH 4
#define S_HEIGHT 4

/*
// Static P-Box - old design
unsigned char P[21][BLOCKSIZE] = {
    {14, 0, 1, 12, 2, 8, 3, 6, 7, 4, 15, 13, 11, 5, 10, 9},
    {9, 4, 6, 5, 7, 14, 2, 0, 11, 10, 13, 12, 15, 3, 1, 8},
    {14, 6, 5, 11, 7, 13, 9, 3, 12, 2, 10, 4, 0, 1, 8, 15},
    {10, 14, 3, 5, 11, 7, 13, 4, 9, 6, 12, 0, 8, 2, 15, 1},
    {14, 4, 6, 0, 11, 2, 10, 7, 5, 1, 13, 12, 8, 15, 9, 3},
    {14, 9, 11, 1, 13, 8, 7, 4, 12, 10, 2, 0, 15, 6, 3, 5},
    {6, 0, 10, 14, 11, 3, 2, 1, 4, 9, 13, 8, 7, 12, 5, 15},
    {8, 4, 2, 14, 9, 11, 10, 13, 12, 7, 6, 0, 5, 1, 15, 3},
    {1, 0, 2, 5, 6, 9, 10, 8, 14, 13, 4, 11, 7, 3, 12, 15},
    {14, 1, 13, 5, 2, 6, 10, 0, 4, 3, 11, 9, 12, 15, 7, 8},
    {6, 14, 8, 2, 13, 11, 7, 5, 3, 12, 10, 4, 15, 0, 1, 9},
    {3, 10, 9, 0, 5, 4, 8, 7, 14, 13, 1, 11, 12, 15, 6, 2},
    {2, 6, 9, 14, 3, 0, 13, 5, 10, 8, 11, 12, 7, 15, 1, 4},
    {6, 14, 13, 11, 9, 0, 3, 7, 12, 2, 5, 10, 1, 8, 4, 15},
    {3, 7, 10, 4, 14, 0, 13, 11, 8, 12, 5, 2, 15, 1, 6, 9},
    {14, 7, 2, 6, 13, 3, 1, 5, 9, 0, 10, 8, 4, 11, 12, 15},
    {7, 0, 2, 6, 3, 14, 5, 1, 13, 11, 12, 8, 10, 4, 9, 15},
    {0, 5, 10, 1, 2, 3, 9, 14, 8, 13, 11, 12, 7, 15, 4, 6},
    {8, 14, 2, 9, 13, 6, 0, 1, 3, 5, 7, 10, 11, 4, 12, 15},
    {7, 3, 14, 13, 6, 0, 9, 1, 11, 8, 5, 2, 4, 12, 10, 15},
    {10, 0, 2, 6, 1, 14, 13, 11, 8, 7, 4, 5, 12, 15, 3, 9}
};
*/

#endif