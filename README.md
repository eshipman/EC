# Evan's Cipher (EC)

DISCLAIMER
==========
I make absolutely no claims that any of the ciphers described in this repository are secure or safe.
I do not recommend using them under any circumstances unless they have been thoroughly studied.

## Overview

EC is a family of block ciphers, intended as a learning exercise. An important thing to note is that by starting this project, I'm breaking two very important rules in the field of cryptography:
 1. Don't roll your own crypto
 2. Don't implement your own crypto

I understand and accept the consequences of breaking these rules because these ciphers should never be used in any real-world system (see above disclaimer).

Each of the algorithms in the EC family meet a minimum of these two requirements:
 - Block size of 128 bits
 - Keysizes of 128, 192, 256, 384, or 512 bits


Below is an overview of each cipher, however within each cipher's subdirectory will be additional information

## EC-1
### Overview
EC-1 is designed as a Substitution-Permutation Network (SPN), similar in structure to Rijndael/AES. Beyond the above requirements, it supports keysizes of any multiple of 64 bits above 128 (e.g: 320, 448, 576, etc.). Additionally, the number of rounds ```r``` is dependent on the keysize (```r = 6 + keylen/64 * 6``` bits).

A diagram of the cipher's structure and the P-Box and S-Box construction, ```Cipher_P_S.png```, can be found in EC-1's subdirectory.

### P-Boxes and S-Boxes
EC-1 uses key-dependent P-Boxes and S-Boxes, making analysis more difficult and attacks harder to generalize. Currently, the P-Boxes are filled by "permutating" an xorshift of each roundkey. By "permutating" I mean that:
```
output[input[i] % keylen] = i
```
Of course, this requires removing the filled elements from the list of elements that are counted in the output array. It feels like a difficult idea to convey in a small english paragraph and I believe the code does a much better job.

The S-Boxes are 'filled' from the P-Boxes by simply copying every 2 bytes as 1 row in the S-Box.

### Key Schedule
The key schedules were originally an LCG or Xorshift applied to the key iteratively, however this design was deemed too simple. The current design for the key schedule is a series of LCGs and Xorshifts applied to different pieces of the key in a hierarchical Feistel-like structure, as shown in the diagram ```Key_Schedule.png``` under EC-1's subdirectory.

### Weaknesses
As I was implementing EC-1, I noticed several weaknesses. I continued to implement it despite this fact, so that I would have a reference to start from.
The list of weaknesses that I know about is as follows:
 - Changing 1 byte of the plaintext affects only 1 byte of the ciphertext. This is because of the small size of EC-1's S-Boxes and poor diffusion between channels of data.

## Future
In the future (assuming I still maintain this repository), I will hopefully perform security analysis on the ciphers. In light of any attacks on the ciphers, I will attempt to redesign them to resist the attacks. Each new cipher will be given a new number (e.g: EC-1, EC-2, EC-3, etc.). However, if a design change does not really constitute a new cipher, it will be given an additional letter (e.g: EC-1A, EC-1B, EC-1C, etc.).


## What you can do
Though I may know more about cryptography than the average person or programmer, I am by no means an expert on cryptography. I'm merely very interested in it. If you discover any vulnerabilities or attacks on any of the ciphers that I haven't already described, please let me know. It's entirely possible that I've overlooked a lot of serious problems. To quote cryptographer Bruce Schneier:
> Anyone, from the most clueless amateur to the best cryptographer, can create an algorithm that he himself can't break.
