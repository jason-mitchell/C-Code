//
//							Filename: sha3.h
//							Function: Header file for sha3.c Keccak routines
//
//
//
//
//
//
//-------------------------------------------------------------------------------------------------------------------------------------------------

#ifndef SHA3_H_
#define SHA3_H_


// Definitions
//-------------
typedef unsigned char UINT8;
typedef unsigned long long int UINT64;
typedef UINT64 tKeccakLane;

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Macros
//---------------------------------------------------------------



// Function Prototypes
//---------------------
void FIPS202_SHAKE128(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen);
void FIPS202_SHAKE256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output, int outputByteLen);
void FIPS202_SHA3_224(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
void FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
void FIPS202_SHA3_384(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
void FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

// Unit test Prototypes
//----------------------
void SHA3UT(void);



 



#endif

