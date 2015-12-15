//
//					Filename: sha3.c
//                  Implementation of the SHA-3 algorithm and its SHAKE variants. At the heart of it, its the KECCAK algorithm.
//					Author: Jason Mitchell
//
//					This is derived from the official, "compact and readable" version from the developers with modifications made to ensure
//                  readability and friendliness to compilers, great and small 
//
//					Because the original source code is Open Source / Creative Commons, it follows from a legal standpoint that this code is also
//                  similarly Open Source software
//
//										To the extent possible under law, the implementer has waived all copyright
//												and related or neighboring rights to the source code in this file.
//                                                     http://creativecommons.org/publicdomain/zero/1.0/
//
//					Because the SHAKE algorithm is so closely related to Keccak, the functions are included here.
//                  Reference Source: https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/CompactFIPS202/Keccak-readable-and-compact.c
//
//
//------------------------------------------------------------------------------------------------------------------------------------------------------------

#include "common.h"
#include "sha3.h"
#include <string.h>
#include <stdio.h>
#include "debug.h"

#define BIG_ENDIAN

//--------------------------------------------------------------------------------------------------------------------------
// Hash functions
//--------------------------------------------------------------------------------------------------------------------------

//  Function to compute SHAKE128 on the input message with any output length.
//------------------------------------------------------------------------------
void FIPS202_SHAKE128(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen)
{
    Keccak(1344, 256, input, inputByteLen, 0x1F, output, outputByteLen);
}


//  Function to compute SHAKE256 on the input message with any output length.
//-------------------------------------------------------------------------------
void FIPS202_SHAKE256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen)
{
    Keccak(1088, 512, input, inputByteLen, 0x1F, output, outputByteLen);
}


//  Function to compute SHA3-224 on the input message. The output length is fixed to 28 bytes.
//-----------------------------------------------------------------------------------------------
void FIPS202_SHA3_224(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
{
    Keccak(1152, 448, input, inputByteLen, 0x06, output, 28);
}


// Function to compute SHA3-256 on the input message. The output length is fixed to 32 bytes.
//-----------------------------------------------------------------------------------------------
void FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
{
    Keccak(1088, 512, input, inputByteLen, 0x06, output, 32);
}

//  Function to compute SHA3-384 on the input message. The output length is fixed to 48 bytes.
//
void FIPS202_SHA3_384(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
{
    Keccak(832, 768, input, inputByteLen, 0x06, output, 48);
}

//  Function to compute SHA3-512 on the input message. The output length is fixed to 64 bytes.
//
void FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output)
{
    Keccak(576, 1024, input, inputByteLen, 0x06, output, 64);
}

//---------------------------------------------------------------------
// Assistant functions
//---------------------------------------------------------------------
#ifndef LITTLE_ENDIAN

	// load64: load 64-bit value using LE convention
	// This is a cast-less operation to make the code more portable IMHO
	static UINT64 load64(const UINT8 *x){
    	int i;
    	UINT64 u=0;

    	for(i = 7; i >= 0; --i){
        	u <<= 8;
        	u |= x[i];
    	}
    	return u;
	}

	// store64: store 64-bit value using LE convention
	// This is a cast-less operation to make the code more portable IMHO
	static void store64(UINT8 *x, UINT64 u){
    	unsigned int i;

    	for(i = 0; i < 8; ++i){
        	x[i] = u;
        	u >>= 8;
    	}
	}

	// xor64: xor into 64-bit value using LE convention
	// Again, a cast-less operation to make sure it does exactly what it is supposed to
	static void xor64(UINT8 *x, UINT64 u){
    	unsigned int i;

    	for(i = 0; i < 8; ++i){
        	x[i] ^= u;
        	u >>= 8;
    	}
	}
#endif


//-------------------------------------------------------------------------------------------------------
// Macros to implement ROTATELEFT64, readLane, writeLane, XORLane
// This does NOT assume such an instruction exists on the CPU, which is a flaw of other implementations
//-------------------------------------------------------------------------------------------------------

#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))

#ifdef LITTLE_ENDIAN
    #define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
    #define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
    #define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)
#else
    #define readLane(x, y)          load64((UINT8*)state+sizeof(tKeccakLane)*i(x, y))
    #define writeLane(x, y, lane)   store64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
    #define XORLane(x, y, lane)     xor64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
#endif

//-------------------------------------------------------------------------------------------------------
// Specialized functions
//-------------------------------------------------------------------------------------------------------

// Name: LFSR86540
// Function: Implements the linear feedback shift register that is used to generate Keccak round constants
//-------------------------------------------------------------------------------------------------------
int LFSR86540(UINT8 *LFSR){
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        // Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

// Name: KeccakF1600_StatePermute
// Function: Perform a state permutation of the Keccak algorithm
//------------------------------------------------------------------------------------------------------------
void KeccakF1600_StatePermute(void *state){
    unsigned int round, x, y, j, t;
    UINT8 LFSRstate = 0x01;

    for(round = 0; round < 24; round++){
        {   
        	// === θ step (see [Keccak Reference, Section 2.3.2]) ===
            tKeccakLane C[5], D;

            // Compute the parity of the columns
            for(x = 0; x < 5; x++)
            		C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
            				for(x = 0; x < 5; x++){
                					// Compute the θ effect for a given column
                					D = C[(x + 4) % 5] ^ ROL64(C[(x + 1) %5], 1);
                					// Add the θ effect to the whole column
                			for (y = 0; y < 5; y++)
                    				XORLane(x, y, D);
            				}
        }

        {   // === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) ===
            tKeccakLane current, temp;
            // Start at coordinates (1 0)
            x = 1; y = 0;
            current = readLane(x, y);
            // Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23
            for(t = 0; t < 24; t++) {
                // Compute the rotation constant r = (t+1)(t+2)/2
                unsigned int r = ((t + 1) * (t + 2) / 2) %64;
                // Compute ((0 1)(2 3)) * (x y)
                unsigned int Y = (2 * x + 3 * y) % 5; x = y; y = Y;
                // Swap current and state(x,y), and rotate
                temp = readLane(x, y);
                writeLane(x, y, ROL64(current, r));
                current = temp;
            }
        }

        {   // === χ step (see [Keccak Reference, Section 2.3.1]) ===
            tKeccakLane temp[5];
            for(y = 0; y < 5; y++) {
                // Take a copy of the plane
                for(x = 0; x < 5; x++)
                    temp[x] = readLane(x, y);
                // Compute χ on the plane
                for(x = 0; x < 5; x++)
                    writeLane(x, y, temp[x] ^((~temp[(x + 1) %5]) & temp[(x + 2)%5]));
            }
        }

        {   // === ι step (see [Keccak Reference, Section 2.3.5]) ===
            for(j = 0; j < 7; j++) {
                unsigned int bitPosition = (1 << j) - 1; //2^j-1
                if (LFSR86540(&LFSRstate))
                    XORLane(0, 0, (tKeccakLane)1 << bitPosition);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Name: Keccak
// Function: Core Keccak routine
//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen)
{
    UINT8 state[200];
    unsigned int rateInBytes = rate/8;
    unsigned int blockSize = 0;
    unsigned int i;

    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
        return;

    // === Initialize the state ===
    memset(state, 0, sizeof(state));

    // === Absorb all the input blocks ===
    while(inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for(i=0; i<blockSize; i++)
            state[i] ^= input[i];
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            KeccakF1600_StatePermute(state);
            blockSize = 0;
        }
    }

    // === Do the padding and switch to the squeezing phase ===
    // Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix)
    state[blockSize] ^= delimitedSuffix;
    // If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding
    if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes-1)))
        KeccakF1600_StatePermute(state);
    // Add the second bit of padding
    state[rateInBytes-1] ^= 0x80;
    // Switch to the squeezing phase
    KeccakF1600_StatePermute(state);

    // === Squeeze out all the output blocks ===
    while(outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            KeccakF1600_StatePermute(state);
    }
}






//-----------------------------------------------------------------------------------------------------------------------------------------------------
// Unit Tests
//-----------------------------------------------------------------------------------------------------------------------------------------------------

void SHA3UT(void){
		BYTE output[64];
		BYTE input[16];
		BYTE dispinfo[64];

		memset(dispinfo, 0, 64);
		memset(input, 0, 16);

		strcpy(input, "abc");			// FIPS standard input test vector

		Debug("Entering SHA3 Unit Test...", TRUE);
		FIPS202_SHA3_256(input, 3, output);
		Debug("SHA3 Digest computed!", TRUE);
		DebugHex(output, 32, TRUE);

}
